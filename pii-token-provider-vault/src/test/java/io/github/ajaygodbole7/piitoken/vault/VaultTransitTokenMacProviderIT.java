package io.github.ajaygodbole7.piitoken.vault;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.ajaygodbole7.piitoken.provider.ProviderFailureReason;
import io.github.ajaygodbole7.piitoken.provider.TokenMacException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@Testcontainers
class VaultTransitTokenMacProviderIT {

    // Bootstrap twin: VaultTransitTestFixture in pii-token-test. Keep the
    // pinned hashicorp/vault:2.0.3 image, HMAC key flags, runtime policy, and
    // request framing aligned. Sharing it here would create a Maven reactor
    // cycle because pii-token-test depends on this provider module.
    private static final String ROOT_TOKEN = "test-only-root-token";
    private static final String KEY_NAME = "pii-token";
    private static final String RUNTIME_POLICY = "pii-token-runtime";
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final HttpClient HTTP = HttpClient.newHttpClient();
    private static final byte[] DIGEST = fixedDigest();

    @Container
    private static final GenericContainer<?> VAULT =
            new GenericContainer<>(DockerImageName.parse("hashicorp/vault:2.0.3"))
                    .withExposedPorts(8200)
                    .withEnv("VAULT_DEV_ROOT_TOKEN_ID", ROOT_TOKEN)
                    .withEnv("VAULT_DEV_LISTEN_ADDRESS", "0.0.0.0:8200")
                    .waitingFor(Wait.forHttp("/v1/sys/health").forStatusCode(200));

    private static String runtimeToken;
    private static String revokedToken;
    private static byte[] versionOneBeforeRotation;

    @BeforeAll
    static void configureVault() {
        request(
                "POST",
                "/v1/sys/mounts/transit",
                ROOT_TOKEN,
                object("type", "transit"),
                204);

        ObjectNode keyRequest = JSON.createObjectNode();
        keyRequest.put("type", "hmac");
        keyRequest.put("key_size", 32);
        keyRequest.put("exportable", false);
        keyRequest.put("allow_plaintext_backup", false);
        request(
                "POST",
                "/v1/transit/keys/" + KEY_NAME,
                ROOT_TOKEN,
                keyRequest,
                200);

        JsonNode key = request(
                "GET",
                "/v1/transit/keys/" + KEY_NAME,
                ROOT_TOKEN,
                null,
                200).path("data");
        assertThat(key.path("exportable").booleanValue()).isFalse();
        assertThat(key.path("allow_plaintext_backup").booleanValue()).isFalse();

        ObjectNode policy = JSON.createObjectNode();
        policy.put(
                "policy",
                "path \"transit/hmac/" + KEY_NAME + "/sha2-256\" {\n"
                        + "  capabilities = [\"update\"]\n"
                        + "}");
        request(
                "PUT",
                "/v1/sys/policies/acl/" + RUNTIME_POLICY,
                ROOT_TOKEN,
                policy,
                204);

        runtimeToken = createRuntimeToken();
        revokedToken = createRuntimeToken();

        try (var versionOne = provider(
                Map.of("k1", 1),
                "k1",
                () -> runtimeToken)) {
            versionOneBeforeRotation = versionOne.macDigest("k1", DIGEST);
        }

        request(
                "POST",
                "/v1/transit/keys/" + KEY_NAME + "/rotate",
                ROOT_TOKEN,
                JSON.createObjectNode(),
                200);
        request(
                "POST",
                "/v1/auth/token/revoke",
                ROOT_TOKEN,
                object("token", revokedToken),
                204);
    }

    @Test
    void pinsVersionsAcrossInPlaceRotation() {
        try (var provider = provider(
                Map.of("k1", 1, "k2", 2),
                "k2",
                () -> runtimeToken)) {
            byte[] versionOneAfterRotation = provider.macDigest("k1", DIGEST);
            byte[] versionTwoFirst = provider.macDigest("k2", DIGEST);
            byte[] versionTwoSecond = provider.macDigest("k2", DIGEST);

            assertThat(versionOneAfterRotation)
                    .containsExactly(versionOneBeforeRotation);
            assertThat(versionTwoFirst)
                    .hasSize(32)
                    .isNotEqualTo(versionOneBeforeRotation);
            assertThat(versionTwoSecond).containsExactly(versionTwoFirst);
        }
    }

    @Test
    void parsesThePinnedVaultVersionAndFullSha256Mac() {
        ObjectNode hmacRequest = JSON.createObjectNode();
        hmacRequest.put("input", Base64.getEncoder().encodeToString(DIGEST));
        hmacRequest.put("key_version", 2);
        String versionedHmac = request(
                "POST",
                "/v1/transit/hmac/" + KEY_NAME + "/sha2-256",
                runtimeToken,
                hmacRequest,
                200)
                .path("data")
                .path("hmac")
                .textValue();

        assertThat(versionedHmac).startsWith("vault:v2:");
        byte[] rawMac = Base64.getDecoder().decode(
                versionedHmac.substring("vault:v2:".length()));
        assertThat(rawMac).hasSize(32);

        try (var provider = provider(
                Map.of("k2", 2),
                "k2",
                () -> runtimeToken)) {
            assertThat(provider.macDigest("k2", DIGEST))
                    .containsExactly(rawMac);
        }
    }

    @Test
    void rejectsUnknownVersionsAndMalformedInputBeforeCredentialsOrTransport() {
        var tokenCalls = new AtomicInteger();
        try (var provider = provider(
                Map.of("k1", 1),
                "k1",
                () -> {
                    tokenCalls.incrementAndGet();
                    return runtimeToken;
                })) {
            assertReason(
                    ProviderFailureReason.UNKNOWN_VERSION,
                    () -> provider.macDigest("k2", DIGEST));
            assertReason(
                    ProviderFailureReason.INVALID_INPUT,
                    () -> provider.macDigest("k1", new byte[31]));
            assertReason(
                    ProviderFailureReason.INVALID_INPUT,
                    () -> provider.macDigest(null, DIGEST));
        }
        assertThat(tokenCalls).hasValue(0);
    }

    @Test
    void runtimeTokenCanOnlyHmacTheConfiguredKey() {
        try (var provider = provider(
                Map.of("k1", 1),
                "k1",
                () -> runtimeToken)) {
            assertThat(provider.macDigest("k1", DIGEST)).hasSize(32);
        }

        request(
                "GET",
                "/v1/transit/keys/" + KEY_NAME,
                runtimeToken,
                null,
                403);
        request(
                "POST",
                "/v1/transit/keys/" + KEY_NAME + "/rotate",
                runtimeToken,
                JSON.createObjectNode(),
                403);
    }

    @Test
    void mapsRealInvalidAndRevokedTokensToOneContentFreeAuthFailure() {
        assertRealAuthFailure("invalid-token");
        assertRealAuthFailure(revokedToken);
    }

    private static void assertRealAuthFailure(String token) {
        try (var provider = provider(
                Map.of("k1", 1),
                "k1",
                () -> token)) {
            assertThatThrownBy(() -> provider.macDigest("k1", DIGEST))
                    .isInstanceOfSatisfying(
                            TokenMacException.class,
                            failure -> assertThat(failure.reason())
                                    .isEqualTo(ProviderFailureReason.AUTH_FAILED))
                    .hasMessage("AUTH_FAILED")
                    .hasNoCause();
        }
    }

    private static VaultTransitTokenMacProvider provider(
            Map<String, Integer> versions,
            String currentVersion,
            VaultTokenSupplier tokenSupplier) {
        VaultTransitProperties properties = new VaultTransitProperties();
        properties.setAddress(address());
        properties.setAllowInsecureHttp(true);
        properties.setKeyName(KEY_NAME);
        properties.setKeySetId("vault-integration-test-key-set");
        properties.setCurrentVersion(currentVersion);
        properties.setVersions(versions);
        properties.setTotalDeadline(Duration.ofSeconds(5));
        properties.setMaxAttempts(1);
        return new VaultTransitTokenMacProvider(properties, tokenSupplier);
    }

    private static String createRuntimeToken() {
        ObjectNode tokenRequest = JSON.createObjectNode();
        tokenRequest.putArray("policies").add(RUNTIME_POLICY);
        tokenRequest.put("no_default_policy", true);
        tokenRequest.put("renewable", false);
        tokenRequest.put("ttl", "1h");
        String token = request(
                "POST",
                "/v1/auth/token/create",
                ROOT_TOKEN,
                tokenRequest,
                200)
                .path("auth")
                .path("client_token")
                .textValue();
        assertThat(token).isNotBlank();
        return token;
    }

    private static JsonNode request(
            String method,
            String path,
            String token,
            JsonNode body,
            int expectedStatus) {
        HttpRequest.BodyPublisher publisher = body == null
                ? HttpRequest.BodyPublishers.noBody()
                : HttpRequest.BodyPublishers.ofString(body.toString());
        HttpRequest request = HttpRequest.newBuilder(address().resolve(path))
                .timeout(Duration.ofSeconds(5))
                .header("X-Vault-Token", token)
                .header("Content-Type", "application/json")
                .method(method, publisher)
                .build();
        try {
            HttpResponse<String> response =
                    HTTP.send(request, HttpResponse.BodyHandlers.ofString());
            assertThat(response.statusCode()).isEqualTo(expectedStatus);
            return expectedStatus < 200
                    || expectedStatus >= 300
                    || response.body().isBlank()
                    ? JSON.createObjectNode()
                    : JSON.readTree(response.body());
        }
        catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new AssertionError("Vault integration test interrupted");
        }
        catch (IOException exception) {
            throw new AssertionError("Vault integration test request failed");
        }
    }

    private static URI address() {
        return URI.create("http://" + VAULT.getHost() + ":"
                + VAULT.getMappedPort(8200));
    }

    private static ObjectNode object(String name, String value) {
        ObjectNode node = JSON.createObjectNode();
        node.put(name, value);
        return node;
    }

    private static byte[] fixedDigest() {
        byte[] digest = new byte[32];
        for (int index = 0; index < digest.length; index++) {
            digest[index] = (byte) (index + 1);
        }
        return digest;
    }

    private static void assertReason(
            ProviderFailureReason reason,
            Runnable operation) {
        assertThatThrownBy(operation::run)
                .isInstanceOfSatisfying(
                        TokenMacException.class,
                        failure -> assertThat(failure.reason()).isEqualTo(reason))
                .hasMessage(reason.name())
                .hasNoCause();
    }
}
