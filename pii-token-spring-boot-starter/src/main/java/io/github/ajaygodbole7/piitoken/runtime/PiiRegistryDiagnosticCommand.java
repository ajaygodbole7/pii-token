package io.github.ajaygodbole7.piitoken.runtime;

import io.github.ajaygodbole7.piitoken.descriptor.DescriptorDriftReport;
import io.github.ajaygodbole7.piitoken.descriptor.DescriptorManifestCodec;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import java.util.Objects;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/**
 * Offline, read-only descriptor registry diagnostic.
 *
 * <p>This command does not create a Spring application context and never writes
 * the registry. The password is read from {@code PII_REGISTRY_PASSWORD}.</p>
 */
public final class PiiRegistryDiagnosticCommand {

    static final int EXIT_MATCH = 0;
    static final int EXIT_DRIFT = 2;
    static final int EXIT_INVALID = 3;
    static final int EXIT_USAGE = 64;

    private static final int MAX_MANIFEST_BYTES = 1_048_576;
    private static final List<String> RESOURCE_ROOTS = List.of(
            "META-INF/pii/",
            "BOOT-INF/classes/META-INF/pii/");

    private PiiRegistryDiagnosticCommand() {
    }

    public static void main(String[] args) {
        int exitCode = run(args, System.out);
        if (exitCode != EXIT_MATCH) {
            System.exit(exitCode);
        }
    }

    /**
     * Runs the command without starting the application.
     *
     * @param args artifact path, JDBC URL, and SELECT-only registry username
     * @param output destination for content-safe diagnostics
     * @return zero only when the compiled and approved manifests match
     */
    public static int run(String[] args, PrintStream output) {
        Objects.requireNonNull(args, "args");
        Objects.requireNonNull(output, "output");
        if (args.length != 3 || System.getenv("PII_REGISTRY_PASSWORD") == null) {
            output.println("CONFIGURATION_INVALID");
            output.println("usage=PiiRegistryDiagnosticCommand "
                    + "<compiled-artifact> <jdbc-url> <select-only-username>");
            output.println("credential=PII_REGISTRY_PASSWORD");
            return EXIT_USAGE;
        }
        Path artifact;
        try {
            artifact = Path.of(args[0]);
        }
        catch (IllegalArgumentException exception) {
            output.println("CONFIGURATION_INVALID");
            return EXIT_USAGE;
        }
        return run(
                artifact,
                () -> DriverManager.getConnection(
                        args[1],
                        args[2],
                        System.getenv("PII_REGISTRY_PASSWORD")),
                output);
    }

    static int run(
            Path artifact,
            ConnectionSupplier connections,
            PrintStream output) {
        Objects.requireNonNull(artifact, "artifact");
        Objects.requireNonNull(connections, "connections");
        Objects.requireNonNull(output, "output");
        try {
            CompiledArtifact compiled = readCompiledArtifact(artifact);
            ApprovedManifest approved = readApprovedManifest(connections);
            String approvedComputed =
                    DescriptorManifestCodec.fingerprint(approved.manifest());
            if (!approvedComputed.equals(approved.fingerprint())) {
                output.println(StartupReason.MANIFEST_INTEGRITY.name());
                return EXIT_INVALID;
            }
            try {
                DescriptorManifestCodec.decode(approved.manifest());
            }
            catch (IllegalArgumentException exception) {
                output.println(StartupReason.MANIFEST_INVALID.name());
                return EXIT_INVALID;
            }
            if (compiled.fingerprint().equals(approved.fingerprint())) {
                output.println("DESCRIPTOR_MATCH");
                output.println("fingerprint=" + compiled.fingerprint());
                return EXIT_MATCH;
            }

            DescriptorDriftReport report = DescriptorDriftReport.compare(
                    approved.manifest(),
                    compiled.manifest());
            output.println(StartupReason.DESCRIPTOR_DRIFT.name());
            output.print(report.render(approved.fingerprint()));
            return EXIT_DRIFT;
        }
        catch (DiagnosticFailure exception) {
            output.println(exception.reason().name());
            return EXIT_INVALID;
        }
        catch (RuntimeException exception) {
            output.println(StartupReason.POLICY_INVALID.name());
            return EXIT_INVALID;
        }
    }

    private static CompiledArtifact readCompiledArtifact(Path artifact)
            throws DiagnosticFailure {
        try {
            byte[] manifestBytes = readResource(
                    artifact,
                    "descriptor-manifest.txt",
                    MAX_MANIFEST_BYTES);
            byte[] fingerprintBytes = readResource(
                    artifact,
                    "descriptor-fingerprint.txt",
                    64);
            String manifest = strictUtf8(manifestBytes);
            String fingerprint = strictUtf8(fingerprintBytes);
            DescriptorManifestCodec.decode(manifest);
            if (!DescriptorManifestCodec.fingerprint(manifest).equals(fingerprint)) {
                throw new DiagnosticFailure(StartupReason.GENERATED_OUTPUT_INVALID);
            }
            return new CompiledArtifact(manifest, fingerprint);
        }
        catch (IOException | IllegalArgumentException exception) {
            throw new DiagnosticFailure(StartupReason.GENERATED_OUTPUT_INVALID);
        }
    }

    private static byte[] readResource(
            Path artifact,
            String resourceName,
            int maximumBytes) throws IOException, DiagnosticFailure {
        if (Files.isDirectory(artifact)) {
            for (String root : RESOURCE_ROOTS) {
                Path candidate = artifact.resolve(root).resolve(resourceName);
                if (Files.isRegularFile(candidate)) {
                    if (Files.size(candidate) > maximumBytes) {
                        throw new DiagnosticFailure(StartupReason.GENERATED_OUTPUT_INVALID);
                    }
                    return Files.readAllBytes(candidate);
                }
            }
        }
        else if (Files.isRegularFile(artifact)) {
            try (JarFile jar = new JarFile(artifact.toFile())) {
                for (String root : RESOURCE_ROOTS) {
                    JarEntry entry = jar.getJarEntry(root + resourceName);
                    if (entry != null) {
                        try (InputStream input = jar.getInputStream(entry)) {
                            byte[] bytes = input.readNBytes(maximumBytes + 1);
                            if (bytes.length > maximumBytes) {
                                throw new DiagnosticFailure(
                                        StartupReason.GENERATED_OUTPUT_INVALID);
                            }
                            return bytes;
                        }
                    }
                }
            }
        }
        throw new DiagnosticFailure(StartupReason.GENERATED_OUTPUT_MISSING);
    }

    private static ApprovedManifest readApprovedManifest(
            ConnectionSupplier connections) throws DiagnosticFailure {
        try (Connection connection = connections.get()) {
            connection.setReadOnly(true);
            connection.setTransactionIsolation(Connection.TRANSACTION_REPEATABLE_READ);
            connection.setAutoCommit(false);
            try {
                try (Statement statement = connection.createStatement()) {
                    statement.execute("SET TRANSACTION READ ONLY");
                }
                ApprovedManifest approved;
                try (Statement statement = connection.createStatement();
                     ResultSet result = statement.executeQuery("""
                             SELECT descriptor_manifest, descriptor_fingerprint
                               FROM pii_security.pii_policy_registry
                              WHERE id = 1
                             """)) {
                    if (!result.next()) {
                        throw new DiagnosticFailure(StartupReason.POLICY_ROW_MISSING);
                    }
                    approved = new ApprovedManifest(
                            result.getString("descriptor_manifest"),
                            result.getString("descriptor_fingerprint"));
                    if (result.next()) {
                        throw new DiagnosticFailure(StartupReason.POLICY_IDENTITY_DRIFT);
                    }
                }
                connection.rollback();
                return approved;
            }
            catch (DiagnosticFailure exception) {
                rollback(connection);
                throw exception;
            }
            catch (SQLException exception) {
                rollback(connection);
                throw new DiagnosticFailure(StartupReason.REGISTRY_IO);
            }
        }
        catch (SQLException exception) {
            throw new DiagnosticFailure(StartupReason.REGISTRY_IO);
        }
    }

    private static void rollback(Connection connection) {
        try {
            connection.rollback();
        }
        catch (SQLException ignored) {
            // The diagnostic remains content-free and exits nonzero.
        }
    }

    private static String strictUtf8(byte[] bytes) throws CharacterCodingException {
        return StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes))
                .toString();
    }

    @FunctionalInterface
    interface ConnectionSupplier {
        Connection get() throws SQLException;
    }

    private record CompiledArtifact(String manifest, String fingerprint) {
    }

    private record ApprovedManifest(String manifest, String fingerprint) {
    }

    private static final class DiagnosticFailure extends Exception {

        private final StartupReason reason;

        private DiagnosticFailure(StartupReason reason) {
            super(Objects.requireNonNull(reason, "reason").name());
            this.reason = reason;
        }

        private StartupReason reason() {
            return reason;
        }
    }
}
