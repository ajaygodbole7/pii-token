package io.github.ajaygodbole7.piitoken.runtime;

import io.github.ajaygodbole7.piitoken.annotation.Kind;
import io.github.ajaygodbole7.piitoken.annotation.Mask;
import io.github.ajaygodbole7.piitoken.descriptor.DescriptorManifestCodec;
import io.github.ajaygodbole7.piitoken.descriptor.PiiFieldDescriptor;
import io.github.ajaygodbole7.piitoken.provider.TokenMacProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.postgresql.ds.PGSimpleDataSource;
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

import javax.sql.DataSource;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.Statement;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ApprovedRegistryLoaderTest {

    private static final String APP_ROLE = "pii_p3_runtime";
    private static final String APP_PASSWORD = "pii_p3_runtime_test_password";

    private static PostgreSQLContainer postgres;
    private static DataSource adminDataSource;
    private static DataSource runtimeDataSource;

    @TempDir
    Path temporary;

    @BeforeAll
    static void startPostgres() throws Exception {
        postgres = new PostgreSQLContainer(DockerImageName.parse("postgres:18.4"));
        postgres.start();
        var configured = new PGSimpleDataSource();
        configured.setURL(postgres.getJdbcUrl());
        configured.setUser(postgres.getUsername());
        configured.setPassword(postgres.getPassword());
        adminDataSource = configured;

        try (Connection connection = adminDataSource.getConnection();
             Statement statement = connection.createStatement()) {
            statement.execute("CREATE ROLE " + APP_ROLE + " LOGIN PASSWORD '" + APP_PASSWORD + "'");
        }
        var runtime = new PGSimpleDataSource();
        runtime.setURL(postgres.getJdbcUrl());
        runtime.setUser(APP_ROLE);
        runtime.setPassword(APP_PASSWORD);
        runtimeDataSource = runtime;
    }

    @AfterAll
    static void stopPostgres() {
        if (postgres != null) {
            postgres.stop();
        }
    }

    @BeforeEach
    void resetRegistry() throws Exception {
        try (Connection connection = adminDataSource.getConnection();
             Statement statement = connection.createStatement()) {
            statement.execute("DROP SCHEMA IF EXISTS pii_security CASCADE");
            String schema = Files.readString(Path.of("..", "docs", "registry-schema.sql"));
            for (String ddl : schema.split(";")) {
                if (!ddl.isBlank()) {
                    statement.execute(ddl);
                }
            }
            statement.execute("GRANT USAGE ON SCHEMA pii_security TO " + APP_ROLE);
            statement.execute(
                    "GRANT SELECT ON pii_security.pii_policy_registry TO " + APP_ROLE);
            statement.execute(
                    "GRANT SELECT ON pii_security.pii_key_version_registry TO " + APP_ROLE);
        }
        insertApprovedPolicy(descriptors());
        insertKey("k1", "opaque/k1", "CURRENT");
    }

    @Test
    void loadsOneApprovedRepeatableReadSnapshot() {
        ApprovedRuntimePolicy policy = load(
                descriptors(),
                Map.of("k1", "opaque/k1"),
                new StubProvider("fixture-provider", "fixture-key-set", "k1", Set.of("k1")));

        assertThat(policy.applicationNamespace()).isEqualTo("bank.cards");
        assertThat(policy.currentWriteVersion()).isEqualTo("k1");
        assertThat(policy.liveKeyVersions()).containsExactly("k1");
        assertThat(policy.descriptors()).containsExactlyElementsOf(descriptors());
    }

    @Test
    void rejectsStoredManifestFingerprintTampering() throws Exception {
        execute("UPDATE pii_security.pii_policy_registry "
                + "SET descriptor_fingerprint = '" + "0".repeat(64) + "'");

        assertThatThrownBy(() -> load(
                descriptors(),
                Map.of("k1", "opaque/k1"),
                provider()))
                .isInstanceOf(StartupValidationException.class)
                .hasMessage(StartupReason.MANIFEST_INTEGRITY.name())
                .hasMessageNotContaining("UPDATE pii_security")
                .hasMessageNotContaining("proposed_policy_update")
                .hasMessageNotContaining("descriptor_manifest");
    }

    @Test
    void rejectsInvalidStoredManifestWithoutRepairSql() throws Exception {
        updateApprovedManifest("not-a-canonical-manifest");

        assertThatThrownBy(() -> load(
                descriptors(),
                Map.of("k1", "opaque/k1"),
                provider()))
                .isInstanceOf(StartupValidationException.class)
                .hasMessage(StartupReason.MANIFEST_INVALID.name())
                .hasMessageNotContaining("UPDATE pii_security")
                .hasMessageNotContaining("proposed_policy_update")
                .hasMessageNotContaining("descriptor_manifest");
    }

    @Test
    void descriptorDriftNamesAttributeChangesBlocksAndGuardedApproval() {
        var drifted = List.of(
                new PiiFieldDescriptor(
                        "customer.pan",
                        Kind.PAN,
                        false,
                        Mask.NONE,
                        "bank.Customer",
                        "pan"),
                new PiiFieldDescriptor(
                        "customer.ssn",
                        Kind.SSN,
                        false,
                        Mask.NONE,
                        "bank.OtherCustomer",
                        "ssn"));

        assertThatThrownBy(() -> load(
                drifted,
                Map.of("k1", "opaque/k1"),
                provider()))
                .isInstanceOf(StartupValidationException.class)
                .satisfies(throwable -> assertThat(
                        ((StartupValidationException) throwable).reason())
                        .isEqualTo(StartupReason.DESCRIPTOR_DRIFT))
                .hasMessageContainingAll(
                        "DESCRIPTOR_DRIFT",
                        "- ADDED customer.pan",
                        "classifications=NEW_FIELD_SCHEMA_APPROVAL",
                        "- ALTERED customer.ssn",
                        "searchable: true -> false",
                        "mask: LAST4 -> NONE",
                        "entity: bank.Customer -> bank.OtherCustomer",
                        "TOKEN_DOMAIN_CHANGE",
                        "COORDINATED_MAPPING_MIGRATION",
                        "FORWARD_ONLY_MASK_CHANGE",
                        "META-INF/pii/migrations/fields/customer.pan.sql",
                        "UPDATE pii_security.pii_policy_registry",
                        "AND descriptor_fingerprint = '"
                                + DescriptorManifestCodec.fingerprint(
                                        DescriptorManifestCodec.encode(descriptors()))
                                + "'");
    }

    @Test
    void offlineDiagnosticExitsNonzeroWithTheSameReadOnlyDriftReport() throws Exception {
        var compiled = List.of(
                descriptors().getFirst(),
                new PiiFieldDescriptor(
                        "customer.pan",
                        Kind.PAN,
                        false,
                        Mask.NONE,
                        "bank.Customer",
                        "pan"));
        Path artifact = writeCompiledArtifact(compiled);
        var bytes = new ByteArrayOutputStream();

        int exitCode;
        try (var output = new PrintStream(bytes, true, StandardCharsets.UTF_8)) {
            exitCode = PiiRegistryDiagnosticCommand.run(
                    artifact,
                    runtimeDataSource::getConnection,
                    output);
        }

        assertThat(exitCode).isEqualTo(PiiRegistryDiagnosticCommand.EXIT_DRIFT);
        assertThat(bytes.toString(StandardCharsets.UTF_8))
                .contains(
                        "DESCRIPTOR_DRIFT",
                        "- ADDED customer.pan",
                        "META-INF/pii/migrations/fields/customer.pan.sql",
                        "UPDATE pii_security.pii_policy_registry")
                .doesNotContain("pii_p3_runtime_test_password");
        assertThat(load(
                descriptors(),
                Map.of("k1", "opaque/k1"),
                provider()).descriptors())
                .containsExactlyElementsOf(descriptors());
    }

    @Test
    void offlineDiagnosticReturnsZeroOnlyForAnApprovedArtifact() throws Exception {
        Path artifact = writeCompiledArtifactJar(descriptors());
        var bytes = new ByteArrayOutputStream();

        int exitCode;
        try (var output = new PrintStream(bytes, true, StandardCharsets.UTF_8)) {
            exitCode = PiiRegistryDiagnosticCommand.run(
                    artifact,
                    runtimeDataSource::getConnection,
                    output);
        }

        assertThat(exitCode).isEqualTo(PiiRegistryDiagnosticCommand.EXIT_MATCH);
        assertThat(bytes.toString(StandardCharsets.UTF_8))
                .startsWith("DESCRIPTOR_MATCH\n")
                .doesNotContain("UPDATE pii_security");
    }

    @Test
    void offlineDiagnosticNeverEmitsRepairSqlForRegistryIntegrityFailures()
            throws Exception {
        Path artifact = writeCompiledArtifact(List.of(
                descriptors().getFirst(),
                new PiiFieldDescriptor(
                        "customer.pan",
                        Kind.PAN,
                        false,
                        Mask.NONE,
                        "bank.Customer",
                        "pan")));
        execute("UPDATE pii_security.pii_policy_registry "
                + "SET descriptor_fingerprint = '" + "0".repeat(64) + "'");
        var bytes = new ByteArrayOutputStream();

        int integrityExit;
        try (var output = new PrintStream(bytes, true, StandardCharsets.UTF_8)) {
            integrityExit = PiiRegistryDiagnosticCommand.run(
                    artifact,
                    runtimeDataSource::getConnection,
                    output);
        }

        assertThat(integrityExit).isEqualTo(PiiRegistryDiagnosticCommand.EXIT_INVALID);
        assertThat(bytes.toString(StandardCharsets.UTF_8))
                .isEqualTo("MANIFEST_INTEGRITY\n")
                .doesNotContain("UPDATE", "descriptor_manifest");

        resetRegistry();
        updateApprovedManifest("not-a-canonical-manifest");
        bytes.reset();
        int invalidExit;
        try (var output = new PrintStream(bytes, true, StandardCharsets.UTF_8)) {
            invalidExit = PiiRegistryDiagnosticCommand.run(
                    artifact,
                    runtimeDataSource::getConnection,
                    output);
        }

        assertThat(invalidExit).isEqualTo(PiiRegistryDiagnosticCommand.EXIT_INVALID);
        assertThat(bytes.toString(StandardCharsets.UTF_8))
                .isEqualTo("MANIFEST_INVALID\n")
                .doesNotContain("UPDATE", "descriptor_manifest");
    }

    @Test
    void rejectsOpaqueMappingDrift() {
        assertReason(StartupReason.KEY_MAPPING_DRIFT,
                () -> load(descriptors(), Map.of("k1", "different/ref"), provider()));
    }

    @Test
    void rejectsProviderIdentityAndLiveSetDrift() {
        assertReason(StartupReason.PROVIDER_IDENTITY_DRIFT,
                () -> load(descriptors(), Map.of("k1", "opaque/k1"),
                        new StubProvider("other", "fixture-key-set", "k1", Set.of("k1"))));
        assertReason(StartupReason.PROVIDER_KEY_STATE_DRIFT,
                () -> load(descriptors(), Map.of("k1", "opaque/k1"),
                        new StubProvider("fixture-provider", "fixture-key-set", "k2", Set.of("k1", "k2"))));
    }

    @Test
    void rejectsMissingOrExcessCurrentAndMoreThanThreeReadOnly() throws Exception {
        execute("UPDATE pii_security.pii_key_version_registry SET state = 'READ_ONLY'");
        assertReason(StartupReason.KEY_STATE_INVALID,
                () -> load(descriptors(), Map.of("k1", "opaque/k1"), provider()));

        resetRegistry();
        execute("UPDATE pii_security.pii_key_version_registry SET state = 'READ_ONLY'");
        insertKey("k2", "opaque/k2", "CURRENT");
        insertKey("k3", "opaque/k3", "READ_ONLY");
        insertKey("k4", "opaque/k4", "READ_ONLY");
        insertKey("k5", "opaque/k5", "READ_ONLY");
        var mappings = new LinkedHashMap<String, String>();
        mappings.put("k1", "opaque/k1");
        mappings.put("k2", "opaque/k2");
        mappings.put("k3", "opaque/k3");
        mappings.put("k4", "opaque/k4");
        mappings.put("k5", "opaque/k5");

        assertReason(StartupReason.KEY_STATE_INVALID,
                () -> load(descriptors(), mappings,
                        new StubProvider(
                                "fixture-provider",
                                "fixture-key-set",
                                "k2",
                                Set.copyOf(mappings.keySet()))));
    }

    @Test
    void rejectsDuplicateCurrentKeyVersionRows() throws Exception {
        execute("DROP INDEX pii_security.pii_key_version_one_current");
        insertKey("k2", "opaque/k2", "CURRENT");

        assertReason(
                StartupReason.KEY_STATE_INVALID,
                () -> load(
                        descriptors(),
                        Map.of("k1", "opaque/k1", "k2", "opaque/k2"),
                        new StubProvider(
                                "fixture-provider",
                                "fixture-key-set",
                                "k1",
                                Set.of("k1", "k2"))));
    }

    @Test
    void shippedSchemaIsByteIdenticalToFrozenSchema() throws Exception {
        String frozen = Files.readString(Path.of("..", "docs", "registry-schema.sql"));
        String shipped;
        try (var input = getClass().getResourceAsStream("/META-INF/pii/registry-schema.sql")) {
            shipped = new String(input.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
        }

        assertThat(shipped).isEqualTo(frozen);
    }

    @Test
    void runtimeDatabaseIdentityCannotWriteRegistry() {
        assertThatThrownBy(() -> {
            try (Connection connection = runtimeDataSource.getConnection();
                Statement statement = connection.createStatement()) {
                statement.executeUpdate(
                        "UPDATE pii_security.pii_policy_registry "
                                + "SET application_namespace = 'tampered' WHERE id = 1");
            }
        })
                .isInstanceOf(java.sql.SQLException.class)
                .extracting(throwable -> ((java.sql.SQLException) throwable).getSQLState())
                .isEqualTo("42501");
    }

    @Test
    void databaseEnforcesIdentifierFingerprintAndSingleCurrentConstraints() {
        assertThatThrownBy(() -> execute("""
                UPDATE pii_security.pii_policy_registry
                   SET descriptor_fingerprint = 'NOT-A-FINGERPRINT'
                """))
                .isInstanceOf(java.sql.SQLException.class)
                .extracting(throwable -> ((java.sql.SQLException) throwable).getSQLState())
                .isEqualTo("23514");

        assertThatThrownBy(() -> insertKey("INVALID.VERSION", "opaque/k2", "READ_ONLY"))
                .isInstanceOf(java.sql.SQLException.class)
                .extracting(throwable -> ((java.sql.SQLException) throwable).getSQLState())
                .isEqualTo("23514");

        assertThatThrownBy(() -> insertKey("k2", "opaque/k2", "CURRENT"))
                .isInstanceOf(java.sql.SQLException.class)
                .extracting(throwable -> ((java.sql.SQLException) throwable).getSQLState())
                .isEqualTo("23505");
    }

    private ApprovedRuntimePolicy load(
            List<PiiFieldDescriptor> liveDescriptors,
            Map<String, String> mappings,
            TokenMacProvider provider) {
        var expectations = new RegistryExpectations("bank.cards", liveDescriptors, mappings);
        return new ApprovedRegistryLoader(runtimeDataSource).load(expectations, provider);
    }

    private static StubProvider provider() {
        return new StubProvider(
                "fixture-provider",
                "fixture-key-set",
                "k1",
                Set.of("k1"));
    }

    private static List<PiiFieldDescriptor> descriptors() {
        return List.of(new PiiFieldDescriptor(
                "customer.ssn", Kind.SSN, true, Mask.LAST4, "bank.Customer", "ssn"));
    }

    private static void insertApprovedPolicy(List<PiiFieldDescriptor> descriptors) throws Exception {
        String manifest = DescriptorManifestCodec.encode(descriptors);
        String fingerprint = DescriptorManifestCodec.fingerprint(manifest);
        try (Connection connection = adminDataSource.getConnection();
             var statement = connection.prepareStatement("""
                     INSERT INTO pii_security.pii_policy_registry (
                         id, application_namespace, protocol_profile, provider_profile,
                         key_set_id, descriptor_manifest, descriptor_fingerprint
                     ) VALUES (1, ?, 'p1/n1', 'HMAC_SHA256_PREHASH_V1',
                         'fixture-key-set', ?, ?)
                     """)) {
            statement.setString(1, "bank.cards");
            statement.setString(2, manifest);
            statement.setString(3, fingerprint);
            statement.executeUpdate();
        }
    }

    private void updateApprovedManifest(String manifest) throws Exception {
        try (Connection connection = adminDataSource.getConnection();
             var statement = connection.prepareStatement("""
                     UPDATE pii_security.pii_policy_registry
                        SET descriptor_manifest = ?,
                            descriptor_fingerprint = ?
                      WHERE id = 1
                     """)) {
            statement.setString(1, manifest);
            statement.setString(2, DescriptorManifestCodec.fingerprint(manifest));
            statement.executeUpdate();
        }
    }

    private Path writeCompiledArtifact(List<PiiFieldDescriptor> fields) throws Exception {
        String manifest = DescriptorManifestCodec.encode(fields);
        Path resources = temporary.resolve("META-INF/pii");
        Files.createDirectories(resources);
        Files.writeString(resources.resolve("descriptor-manifest.txt"), manifest);
        Files.writeString(
                resources.resolve("descriptor-fingerprint.txt"),
                DescriptorManifestCodec.fingerprint(manifest));
        return temporary;
    }

    private Path writeCompiledArtifactJar(List<PiiFieldDescriptor> fields) throws Exception {
        String manifest = DescriptorManifestCodec.encode(fields);
        Path artifact = temporary.resolve("application.jar");
        try (var output = new JarOutputStream(Files.newOutputStream(artifact))) {
            writeJarEntry(
                    output,
                    "BOOT-INF/classes/META-INF/pii/descriptor-manifest.txt",
                    manifest);
            writeJarEntry(
                    output,
                    "BOOT-INF/classes/META-INF/pii/descriptor-fingerprint.txt",
                    DescriptorManifestCodec.fingerprint(manifest));
        }
        return artifact;
    }

    private static void writeJarEntry(
            JarOutputStream output,
            String name,
            String value) throws Exception {
        output.putNextEntry(new JarEntry(name));
        output.write(value.getBytes(StandardCharsets.UTF_8));
        output.closeEntry();
    }

    private static void insertKey(String version, String opaqueRef, String state) throws Exception {
        try (Connection connection = adminDataSource.getConnection();
             var statement = connection.prepareStatement("""
                     INSERT INTO pii_security.pii_key_version_registry (
                         provider_id, key_set_id, logical_version, opaque_ref, state
                     ) VALUES ('fixture-provider', 'fixture-key-set', ?, ?, ?)
                     """)) {
            statement.setString(1, version);
            statement.setString(2, opaqueRef);
            statement.setString(3, state);
            statement.executeUpdate();
        }
    }

    private static void execute(String sql) throws Exception {
        try (Connection connection = adminDataSource.getConnection();
             Statement statement = connection.createStatement()) {
            statement.execute(sql);
        }
    }

    private static void assertReason(StartupReason reason, Runnable operation) {
        assertThatThrownBy(operation::run)
                .isInstanceOf(StartupValidationException.class)
                .extracting(throwable -> ((StartupValidationException) throwable).reason())
                .isEqualTo(reason);
    }

    private record StubProvider(
            String providerId,
            String keySetId,
            String currentVersion,
            Set<String> liveVersions) implements TokenMacProvider {

        @Override
        public Map<String, String> keyMappings() {
            return liveVersions.stream().collect(java.util.stream.Collectors.toUnmodifiableMap(
                    version -> version,
                    version -> "opaque/" + version));
        }

        @Override
        public byte[] macDigest(String logicalVersion, byte[] sha256Digest) {
            throw new AssertionError("registry validation must not invoke MAC");
        }

        @Override
        public void close() {
        }
    }
}
