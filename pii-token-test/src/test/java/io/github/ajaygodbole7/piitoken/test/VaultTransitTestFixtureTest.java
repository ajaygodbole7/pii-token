package io.github.ajaygodbole7.piitoken.test;

import io.github.ajaygodbole7.piitoken.vault.VaultTransitTokenMacProvider;
import org.junit.jupiter.api.Test;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class VaultTransitTestFixtureTest {

    @Test
    void springPropertiesMirrorEveryExplicitProviderProperty() {
        try (var fixture = VaultTransitTestFixture.start()) {
            var provider = fixture.providerProperties();
            Map<String, Object> expected = new LinkedHashMap<>();
            expected.put(
                    "pii.vault.address",
                    provider.getAddress().toString());
            expected.put(
                    "pii.vault.allow-insecure-http",
                    provider.isAllowInsecureHttp());
            expected.put("pii.vault.mount", provider.getMount());
            expected.put("pii.vault.key-name", provider.getKeyName());
            expected.put("pii.vault.key-set-id", provider.getKeySetId());
            expected.put(
                    "pii.vault.current-version",
                    provider.getCurrentVersion());
            expected.put(
                    "pii.vault.total-deadline",
                    provider.getTotalDeadline());
            expected.put(
                    "pii.vault.max-attempts",
                    provider.getMaxAttempts());
            provider.getVersions().forEach((logicalVersion, providerVersion) ->
                    expected.put(
                            "pii.vault.versions." + logicalVersion,
                            providerVersion));

            assertThat(fixture.springProperties()).containsExactlyInAnyOrderEntriesOf(
                    expected);
        }
    }

    @Test
    void pinsRotationAndProvisionsLeastPrivilegeRuntimeToken() throws Exception {
        byte[] digest = new byte[32];
        for (int index = 0; index < digest.length; index++) {
            digest[index] = (byte) (index + 1);
        }

        try (var fixture = VaultTransitTestFixture.start()) {
            byte[] versionOne;
            try (var provider = new VaultTransitTokenMacProvider(
                    fixture.providerProperties(),
                    fixture::runtimeToken)) {
                versionOne = provider.macDigest("k1", digest);
            }

            assertThat(fixture.rotate("k2")).isEqualTo(2);
            assertThat(fixture.currentLogicalVersion()).isEqualTo("k2");
            assertThat(fixture.logicalVersions())
                    .containsEntry("k1", 1)
                    .containsEntry("k2", 2);
            assertThat(fixture.opaqueReference("k1"))
                    .isEqualTo("vault-transit:transit:pii-token:v1");
            assertThat(fixture.opaqueReference("k2"))
                    .isEqualTo("vault-transit:transit:pii-token:v2");

            try (var provider = new VaultTransitTokenMacProvider(
                    fixture.providerProperties(),
                    fixture::runtimeToken)) {
                assertThat(provider.macDigest("k1", digest))
                        .containsExactly(versionOne);
                assertThat(provider.macDigest("k2", digest))
                        .isNotEqualTo(versionOne);
            }

            try (HttpClient client = HttpClient.newHttpClient()) {
                assertThat(status(
                        client,
                        fixture,
                        "GET",
                        "/v1/transit/keys/" + fixture.keyName()))
                        .isEqualTo(403);
                assertThat(status(
                        client,
                        fixture,
                        "POST",
                        "/v1/transit/keys/" + fixture.keyName() + "/rotate"))
                        .isEqualTo(403);
            }
        }
    }

    private static int status(
            HttpClient client,
            VaultTransitTestFixture fixture,
            String method,
            String path) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(
                        fixture.address().resolve(path))
                .header("X-Vault-Token", fixture.runtimeToken())
                .method(method, HttpRequest.BodyPublishers.noBody())
                .build();
        return client.send(
                request,
                HttpResponse.BodyHandlers.discarding()).statusCode();
    }
}
