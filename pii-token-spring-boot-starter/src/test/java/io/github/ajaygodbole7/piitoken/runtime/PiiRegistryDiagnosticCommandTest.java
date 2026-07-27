package io.github.ajaygodbole7.piitoken.runtime;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

class PiiRegistryDiagnosticCommandTest {

    @TempDir
    Path temporary;

    @Test
    void rejectsInvalidCompiledArtifactBeforeOpeningTheRegistry() throws Exception {
        Path resources = temporary.resolve("META-INF/pii");
        Files.createDirectories(resources);
        Files.writeString(
                resources.resolve("descriptor-manifest.txt"),
                "customer.ssn|SSN|true|NONE|bank.Customer|ssn");
        Files.writeString(
                resources.resolve("descriptor-fingerprint.txt"),
                "0".repeat(64));
        var bytes = new ByteArrayOutputStream();

        int exitCode;
        try (var output = new PrintStream(bytes, true, StandardCharsets.UTF_8)) {
            exitCode = PiiRegistryDiagnosticCommand.run(
                    temporary,
                    () -> {
                        throw new AssertionError(
                                "invalid artifact must be rejected before registry access");
                    },
                    output);
        }

        assertThat(exitCode).isEqualTo(PiiRegistryDiagnosticCommand.EXIT_INVALID);
        assertThat(bytes.toString(StandardCharsets.UTF_8))
                .isEqualTo("GENERATED_OUTPUT_INVALID\n")
                .doesNotContain("UPDATE", "descriptor_manifest", "customer.ssn");
    }

    @Test
    void usageFailureIsContentFreeAndNonzero() {
        var bytes = new ByteArrayOutputStream();

        int exitCode;
        try (var output = new PrintStream(bytes, true, StandardCharsets.UTF_8)) {
            exitCode = PiiRegistryDiagnosticCommand.run(new String[0], output);
        }

        assertThat(exitCode).isEqualTo(PiiRegistryDiagnosticCommand.EXIT_USAGE);
        assertThat(bytes.toString(StandardCharsets.UTF_8))
                .contains(
                        "CONFIGURATION_INVALID",
                        "PII_REGISTRY_PASSWORD")
                .doesNotContain("jdbc:", "password=");
    }
}
