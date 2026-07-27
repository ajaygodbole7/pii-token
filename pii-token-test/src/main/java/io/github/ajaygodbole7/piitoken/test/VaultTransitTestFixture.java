package io.github.ajaygodbole7.piitoken.test;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.ajaygodbole7.piitoken.vault.VaultTransitProperties;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Pattern;

/**
 * Test-only HashiCorp Vault Transit fixture.
 *
 * <p>The fixture starts a pinned Vault dev-mode container. Dev mode uses a root
 * token, has no TLS, and stores all data in memory. It must never be used as a
 * production dependency or deployment configuration.</p>
 */
public final class VaultTransitTestFixture implements AutoCloseable {

    // Bootstrap twin: VaultTransitTokenMacProviderIT. Keep the pinned
    // hashicorp/vault:2.0.3 image, HMAC key flags, runtime policy, and request
    // framing aligned. The provider module cannot depend on this test-support
    // module without creating a Maven reactor cycle.
    private static final String VAULT_IMAGE = "hashicorp/vault:2.0.3";
    private static final String ROOT_TOKEN = "pii-test-only-root-token";
    private static final String MOUNT = "transit";
    private static final String POLICY_NAME = "pii-token-test-runtime";
    private static final Pattern KEY_NAME =
            Pattern.compile("[A-Za-z0-9_-]{1,64}");
    private static final Pattern KEY_SET_ID =
            Pattern.compile("[a-z0-9][a-z0-9_-]{0,127}");
    private static final Pattern LOGICAL_VERSION =
            Pattern.compile("[a-z0-9][a-z0-9_-]{0,31}");
    private static final ObjectMapper JSON = new ObjectMapper();

    private final GenericContainer<?> container;
    private final HttpClient httpClient;
    private final String keyName;
    private final String keySetId;
    private final LinkedHashMap<String, Integer> logicalVersions =
            new LinkedHashMap<>();
    private final AtomicBoolean closed = new AtomicBoolean();
    private String currentLogicalVersion;
    private String runtimeToken;
    private int latestProviderVersion;

    private VaultTransitTestFixture(
            String keyName,
            String keySetId,
            String initialLogicalVersion) {
        this.keyName = requireMatch(keyName, KEY_NAME, "INVALID_VAULT_KEY_NAME");
        this.keySetId = requireMatch(
                keySetId,
                KEY_SET_ID,
                "INVALID_VAULT_KEY_SET_ID");
        this.currentLogicalVersion = requireMatch(
                initialLogicalVersion,
                LOGICAL_VERSION,
                "INVALID_LOGICAL_VERSION");
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .build();
        this.container = new GenericContainer<>(
                DockerImageName.parse(VAULT_IMAGE))
                .withExposedPorts(8200)
                .withEnv("VAULT_DEV_ROOT_TOKEN_ID", ROOT_TOKEN)
                .withEnv("VAULT_DEV_LISTEN_ADDRESS", "0.0.0.0:8200")
                .waitingFor(Wait.forHttp("/v1/sys/health").forStatusCode(200));
        try {
            container.start();
            provision();
        }
        catch (RuntimeException exception) {
            close();
            throw new IllegalStateException(
                    "VAULT_TEST_FIXTURE_BOOTSTRAP_FAILED",
                    exception);
        }
    }

    /**
     * Starts a fixture using the default key, key-set, and {@code k1} logical
     * version.
     *
     * @return a started fixture
     */
    public static VaultTransitTestFixture start() {
        return start("pii-token", "pii-test-key-set", "k1");
    }

    /**
     * Starts a fixture with consumer-specific token-domain identifiers.
     *
     * @param keyName Vault Transit HMAC key name
     * @param keySetId registry key-set identifier
     * @param initialLogicalVersion logical name mapped to Vault key version 1
     * @return a started fixture
     */
    public static VaultTransitTestFixture start(
            String keyName,
            String keySetId,
            String initialLogicalVersion) {
        return new VaultTransitTestFixture(
                keyName,
                keySetId,
                initialLogicalVersion);
    }

    /**
     * Returns the mapped HTTP endpoint of the dev-mode Vault container.
     *
     * @return Vault base URI
     */
    public URI address() {
        requireOpen();
        return URI.create("http://" + container.getHost() + ":"
                + container.getMappedPort(8200));
    }

    /**
     * Returns the least-privilege token authorized only for Transit HMAC.
     *
     * @return runtime token for a test {@code VaultTokenSupplier}
     */
    public String runtimeToken() {
        requireOpen();
        return runtimeToken;
    }

    /**
     * Returns the configured Transit key name.
     *
     * @return Transit key name
     */
    public String keyName() {
        return keyName;
    }

    /**
     * Returns the configured registry key-set identifier.
     *
     * @return key-set identifier
     */
    public String keySetId() {
        return keySetId;
    }

    /**
     * Returns the logical version currently selected for new writes.
     *
     * @return current logical version
     */
    public synchronized String currentLogicalVersion() {
        requireOpen();
        return currentLogicalVersion;
    }

    /**
     * Returns an immutable logical-version to Vault-version mapping.
     *
     * @return pinned version mapping
     */
    public synchronized Map<String, Integer> logicalVersions() {
        requireOpen();
        return Map.copyOf(logicalVersions);
    }

    /**
     * Returns the immutable registry reference for a logical version.
     *
     * @param logicalVersion configured logical version
     * @return Vault Transit opaque reference
     */
    public synchronized String opaqueReference(String logicalVersion) {
        requireOpen();
        Integer providerVersion = logicalVersions.get(logicalVersion);
        if (providerVersion == null) {
            throw new IllegalArgumentException("UNKNOWN_LOGICAL_VERSION");
        }
        return "vault-transit:" + MOUNT + ":" + keyName + ":v"
                + providerVersion;
    }

    /**
     * Rotates the Transit key in place and pins a new logical version to the
     * resulting provider version.
     *
     * @param nextLogicalVersion new logical version for writes
     * @return the pinned Vault key version
     */
    public synchronized int rotate(String nextLogicalVersion) {
        requireOpen();
        String logicalVersion = requireMatch(
                nextLogicalVersion,
                LOGICAL_VERSION,
                "INVALID_LOGICAL_VERSION");
        if (logicalVersions.containsKey(logicalVersion)) {
            throw new IllegalArgumentException("DUPLICATE_LOGICAL_VERSION");
        }
        JsonNode response = request(
                "POST",
                "/v1/" + MOUNT + "/keys/" + keyName + "/rotate",
                ROOT_TOKEN,
                JSON.createObjectNode(),
                200);
        int providerVersion = response.path("data")
                .path("latest_version")
                .asInt(-1);
        if (providerVersion != latestProviderVersion + 1) {
            throw new IllegalStateException("VAULT_KEY_VERSION_MISMATCH");
        }
        latestProviderVersion = providerVersion;
        logicalVersions.put(logicalVersion, providerVersion);
        currentLogicalVersion = logicalVersion;
        return providerVersion;
    }

    /**
     * Builds provider properties matching the fixture's current pinned
     * versions.
     *
     * @return independent mutable properties object for a test provider
     */
    public synchronized VaultTransitProperties providerProperties() {
        requireOpen();
        VaultTransitProperties properties = new VaultTransitProperties();
        properties.setAddress(address());
        properties.setAllowInsecureHttp(true);
        properties.setMount(MOUNT);
        properties.setKeyName(keyName);
        properties.setKeySetId(keySetId);
        properties.setCurrentVersion(currentLogicalVersion);
        properties.setVersions(new LinkedHashMap<>(logicalVersions));
        properties.setTotalDeadline(Duration.ofSeconds(5));
        properties.setMaxAttempts(1);
        return properties;
    }

    /**
     * Returns Spring property values ready for a test application context.
     *
     * @return immutable {@code pii.vault.*} property map
     */
    public synchronized Map<String, Object> springProperties() {
        requireOpen();
        VaultTransitProperties source = providerProperties();
        LinkedHashMap<String, Object> properties = new LinkedHashMap<>();
        properties.put("pii.vault.address", source.getAddress().toString());
        properties.put(
                "pii.vault.allow-insecure-http",
                source.isAllowInsecureHttp());
        properties.put("pii.vault.mount", source.getMount());
        properties.put("pii.vault.key-name", source.getKeyName());
        properties.put("pii.vault.key-set-id", source.getKeySetId());
        properties.put(
                "pii.vault.current-version",
                source.getCurrentVersion());
        properties.put(
                "pii.vault.total-deadline",
                source.getTotalDeadline());
        properties.put(
                "pii.vault.max-attempts",
                source.getMaxAttempts());
        source.getVersions().forEach((logicalVersion, providerVersion) ->
                properties.put(
                        "pii.vault.versions." + logicalVersion,
                        providerVersion));
        return Map.copyOf(properties);
    }

    /**
     * Stops the dev-mode Vault container and releases the fixture HTTP client.
     */
    @Override
    public void close() {
        if (!closed.compareAndSet(false, true)) {
            return;
        }
        try {
            httpClient.close();
        }
        finally {
            container.stop();
        }
    }

    private void provision() {
        request(
                "POST",
                "/v1/sys/mounts/" + MOUNT,
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
                "/v1/" + MOUNT + "/keys/" + keyName,
                ROOT_TOKEN,
                keyRequest,
                200);
        assertKeyConfiguration();

        ObjectNode policy = JSON.createObjectNode();
        policy.put(
                "policy",
                "path \"" + MOUNT + "/hmac/" + keyName
                        + "/sha2-256\" {\n"
                        + "  capabilities = [\"update\"]\n"
                        + "}");
        request(
                "PUT",
                "/v1/sys/policies/acl/" + POLICY_NAME,
                ROOT_TOKEN,
                policy,
                204);

        ObjectNode tokenRequest = JSON.createObjectNode();
        tokenRequest.putArray("policies").add(POLICY_NAME);
        tokenRequest.put("no_default_policy", true);
        tokenRequest.put("renewable", false);
        tokenRequest.put("ttl", "1h");
        JsonNode tokenResponse = request(
                "POST",
                "/v1/auth/token/create",
                ROOT_TOKEN,
                tokenRequest,
                200);
        runtimeToken = tokenResponse.path("auth")
                .path("client_token")
                .textValue();
        if (runtimeToken == null || runtimeToken.isBlank()) {
            throw new IllegalStateException("VAULT_RUNTIME_TOKEN_MISSING");
        }

        latestProviderVersion = 1;
        logicalVersions.put(currentLogicalVersion, latestProviderVersion);
    }

    private void assertKeyConfiguration() {
        JsonNode data = request(
                "GET",
                "/v1/" + MOUNT + "/keys/" + keyName,
                ROOT_TOKEN,
                null,
                200).path("data");
        if (!"hmac".equals(data.path("type").textValue())
                || data.path("exportable").asBoolean(true)
                || data.path("allow_plaintext_backup").asBoolean(true)
                || data.path("latest_version").asInt(-1) != 1) {
            throw new IllegalStateException(
                    "VAULT_TEST_KEY_CONFIGURATION_INVALID");
        }
    }

    private JsonNode request(
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
                    httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != expectedStatus) {
                throw new IllegalStateException(
                        "VAULT_TEST_FIXTURE_UNEXPECTED_STATUS");
            }
            if (expectedStatus < 200
                    || expectedStatus >= 300
                    || response.body().isBlank()) {
                return JSON.createObjectNode();
            }
            return JSON.readTree(response.body());
        }
        catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(
                    "VAULT_TEST_FIXTURE_INTERRUPTED",
                    exception);
        }
        catch (IOException exception) {
            throw new IllegalStateException(
                    "VAULT_TEST_FIXTURE_REQUEST_FAILED",
                    exception);
        }
    }

    private void requireOpen() {
        if (closed.get()) {
            throw new IllegalStateException("VAULT_TEST_FIXTURE_CLOSED");
        }
    }

    private static ObjectNode object(String name, String value) {
        ObjectNode node = JSON.createObjectNode();
        node.put(name, value);
        return node;
    }

    private static String requireMatch(
            String value,
            Pattern pattern,
            String reason) {
        Objects.requireNonNull(value, reason);
        if (!pattern.matcher(value).matches()) {
            throw new IllegalArgumentException(reason);
        }
        return value;
    }
}
