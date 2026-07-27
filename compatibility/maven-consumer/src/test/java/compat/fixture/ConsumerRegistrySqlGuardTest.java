package compat.fixture;

import io.github.ajaygodbole7.piitoken.descriptor.DescriptorManifestCodec;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ConsumerRegistrySqlGuardTest {

    private static final String REGISTRY_SQL = "/consumer-registry.sql";
    private static final Pattern POLICY_APPROVAL = Pattern.compile(
            "(?s)INSERT\\s+INTO\\s+pii_security\\.pii_policy_registry"
                    + ".*?VALUES\\s*\\(.*?E'((?:\\\\.|[^'])*)'"
                    + "\\s*,\\s*'([0-9a-f]{64})'\\s*\\);");

    @Test
    void quickstartRegistryApprovalMatchesGeneratedDescriptorArtifact() {
        assertRegistryMatches(
                resource(REGISTRY_SQL),
                generatedManifest());
    }

    @Test
    void staleQuickstartFingerprintProducesAnActionableFailure() {
        String manifest = generatedManifest();
        String fingerprint = DescriptorManifestCodec.fingerprint(manifest);
        char changedFirstCharacter =
                fingerprint.charAt(0) == '0' ? '1' : '0';
        String staleFingerprint =
                changedFirstCharacter + fingerprint.substring(1);
        String staleSql = resource(REGISTRY_SQL).replace(
                fingerprint,
                staleFingerprint);

        assertThat(staleSql).isNotEqualTo(resource(REGISTRY_SQL));
        assertThatThrownBy(() -> assertRegistryMatches(staleSql, manifest))
                .isInstanceOf(AssertionError.class)
                .hasMessageContaining("consumer-registry.sql")
                .hasMessageContaining("generated descriptor fingerprint");
    }

    private static void assertRegistryMatches(
            String registrySql,
            String generatedManifest) {
        Matcher approval = POLICY_APPROVAL.matcher(registrySql);
        assertThat(approval.find())
                .as("consumer-registry.sql must contain one parseable policy approval")
                .isTrue();
        String approvedManifest = approval.group(1);
        String approvedFingerprint = approval.group(2);
        assertThat(approval.find())
                .as("consumer-registry.sql must contain only one policy approval")
                .isFalse();

        assertThat(decodeSqlLiteral(approvedManifest))
                .as("consumer-registry.sql descriptor manifest")
                .isEqualTo(generatedManifest);
        assertThat(approvedFingerprint)
                .as("consumer-registry.sql generated descriptor fingerprint")
                .isEqualTo(
                        DescriptorManifestCodec.fingerprint(
                                generatedManifest));
    }

    private static String decodeSqlLiteral(String encoded) {
        StringBuilder decoded = new StringBuilder(encoded.length());
        for (int index = 0; index < encoded.length(); index++) {
            char current = encoded.charAt(index);
            if (current != '\\') {
                decoded.append(current);
                continue;
            }
            if (++index == encoded.length()) {
                throw new AssertionError(
                        "consumer-registry.sql has an incomplete escape");
            }
            char escaped = encoded.charAt(index);
            switch (escaped) {
                case 'n' -> decoded.append('\n');
                case 'r' -> decoded.append('\r');
                case 't' -> decoded.append('\t');
                case '\\' -> decoded.append('\\');
                case '\'' -> decoded.append('\'');
                default -> throw new AssertionError(
                        "consumer-registry.sql has an unsupported escape");
            }
        }
        return decoded.toString();
    }

    private static String resource(String name) {
        try (InputStream input =
                     ConsumerRegistrySqlGuardTest.class.getResourceAsStream(
                             name)) {
            if (input == null) {
                throw new AssertionError(name + " is missing");
            }
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }
        catch (IOException exception) {
            throw new AssertionError(name + " cannot be read");
        }
    }

    private static String generatedManifest() {
        try {
            Path classes = Path.of(Customer.class
                    .getProtectionDomain()
                    .getCodeSource()
                    .getLocation()
                    .toURI());
            return Files.readString(
                    classes.resolve(
                            "META-INF/pii/descriptor-manifest.txt"),
                    StandardCharsets.UTF_8);
        }
        catch (Exception exception) {
            throw new AssertionError(
                    "generated descriptor manifest cannot be read");
        }
    }
}
