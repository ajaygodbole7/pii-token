package io.github.ajaygodbole7.piitoken.test;

import io.github.ajaygodbole7.piitoken.descriptor.DescriptorManifestCodec;
import io.github.ajaygodbole7.piitoken.descriptor.PiiFieldDescriptor;
import io.github.ajaygodbole7.piitoken.runtime.ApprovedRuntimePolicy;

import javax.sql.DataSource;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Test-only fixture that provisions the approved policy and key registry into
 * a consumer-owned PostgreSQL test database.
 *
 * <p>The fixture uses the same schema resource as the production migration
 * template. It requires a migration-capable {@link DataSource} and never
 * belongs on an application runtime classpath.</p>
 */
public final class RegistryTestFixture {

    private static final String POLICY_INSERT = """
            INSERT INTO pii_security.pii_policy_registry (
                id,
                application_namespace,
                protocol_profile,
                provider_profile,
                key_set_id,
                descriptor_manifest,
                descriptor_fingerprint
            ) VALUES (1, ?, ?, 'HMAC_SHA256_PREHASH_V1', ?, ?, ?)
            """;
    private static final String KEY_INSERT = """
            INSERT INTO pii_security.pii_key_version_registry (
                provider_id,
                key_set_id,
                logical_version,
                opaque_ref,
                state
            ) VALUES (?, ?, ?, ?, ?)
            """;

    private final String applicationNamespace;
    private final String providerId;
    private final String keySetId;
    private final String manifest;
    private final String fingerprint;
    private final List<KeyVersion> keyVersions;

    private RegistryTestFixture(
            String applicationNamespace,
            String providerId,
            String keySetId,
            String manifest,
            List<KeyVersion> keyVersions) {
        this.applicationNamespace =
                Objects.requireNonNull(applicationNamespace, "applicationNamespace");
        this.providerId = Objects.requireNonNull(providerId, "providerId");
        this.keySetId = Objects.requireNonNull(keySetId, "keySetId");
        DescriptorManifestCodec.decode(manifest);
        this.manifest = manifest;
        this.fingerprint = DescriptorManifestCodec.fingerprint(manifest);
        this.keyVersions = List.copyOf(keyVersions);
        validateKeyVersions(this.keyVersions);
    }

    /**
     * Creates a fixture from logical field descriptors.
     *
     * @param applicationNamespace application token namespace
     * @param providerId provider identifier stored in the key registry
     * @param keySetId provider key-set identifier
     * @param descriptors descriptors emitted for the consumer
     * @param keyVersions approved logical key versions
     * @return immutable registry fixture
     */
    public static RegistryTestFixture fromDescriptors(
            String applicationNamespace,
            String providerId,
            String keySetId,
            List<PiiFieldDescriptor> descriptors,
            List<KeyVersion> keyVersions) {
        return fromManifest(
                applicationNamespace,
                providerId,
                keySetId,
                DescriptorManifestCodec.encode(descriptors),
                keyVersions);
    }

    /**
     * Creates a fixture from a canonical generated descriptor manifest.
     *
     * @param applicationNamespace application token namespace
     * @param providerId provider identifier stored in the key registry
     * @param keySetId provider key-set identifier
     * @param manifest canonical generated descriptor manifest
     * @param keyVersions approved logical key versions
     * @return immutable registry fixture
     */
    public static RegistryTestFixture fromManifest(
            String applicationNamespace,
            String providerId,
            String keySetId,
            String manifest,
            List<KeyVersion> keyVersions) {
        return new RegistryTestFixture(
                applicationNamespace,
                providerId,
                keySetId,
                Objects.requireNonNull(manifest, "manifest"),
                Objects.requireNonNull(keyVersions, "keyVersions"));
    }

    /**
     * Returns the canonical descriptor manifest that will be approved.
     *
     * @return canonical manifest
     */
    public String manifest() {
        return manifest;
    }

    /**
     * Returns the SHA-256 fingerprint of the approved manifest.
     *
     * @return lowercase hexadecimal fingerprint
     */
    public String fingerprint() {
        return fingerprint;
    }

    /**
     * Provisions the fixed security schema, policy row, and key-version rows in
     * one transaction.
     *
     * @param dataSource migration-capable PostgreSQL data source
     */
    public void provision(DataSource dataSource) {
        Objects.requireNonNull(dataSource, "dataSource");
        try (Connection connection = dataSource.getConnection()) {
            boolean originalAutoCommit = connection.getAutoCommit();
            connection.setAutoCommit(false);
            try {
                executeSchema(connection);
                insertPolicy(connection);
                insertKeyVersions(connection);
                connection.commit();
            }
            catch (RuntimeException | SQLException exception) {
                rollback(connection);
                throw new IllegalStateException(
                        "PII_TEST_REGISTRY_PROVISIONING_FAILED",
                        exception);
            }
            finally {
                connection.setAutoCommit(originalAutoCommit);
            }
        }
        catch (SQLException exception) {
            throw new IllegalStateException(
                    "PII_TEST_REGISTRY_CONNECTION_FAILED",
                    exception);
        }
    }

    private void executeSchema(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute(registrySchema());
        }
    }

    private void insertPolicy(Connection connection) throws SQLException {
        try (PreparedStatement statement =
                     connection.prepareStatement(POLICY_INSERT)) {
            statement.setString(1, applicationNamespace);
            statement.setString(
                    2,
                    ApprovedRuntimePolicy.COMPILED_PROTOCOL_PROFILE);
            statement.setString(3, keySetId);
            statement.setString(4, manifest);
            statement.setString(5, fingerprint);
            statement.executeUpdate();
        }
    }

    private void insertKeyVersions(Connection connection) throws SQLException {
        try (PreparedStatement statement =
                     connection.prepareStatement(KEY_INSERT)) {
            for (KeyVersion keyVersion : keyVersions) {
                statement.setString(1, providerId);
                statement.setString(2, keySetId);
                statement.setString(3, keyVersion.logicalVersion());
                statement.setString(4, keyVersion.opaqueReference());
                statement.setString(5, keyVersion.state().name());
                statement.addBatch();
            }
            statement.executeBatch();
        }
    }

    private static String registrySchema() {
        try (InputStream input = RegistryTestFixture.class.getResourceAsStream(
                "/META-INF/pii/registry-schema.sql")) {
            if (input == null) {
                throw new IllegalStateException(
                        "PII_REGISTRY_SCHEMA_UNAVAILABLE");
            }
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }
        catch (IOException exception) {
            throw new IllegalStateException(
                    "PII_REGISTRY_SCHEMA_UNAVAILABLE",
                    exception);
        }
    }

    private static void validateKeyVersions(List<KeyVersion> keyVersions) {
        if (keyVersions.isEmpty()) {
            throw new IllegalArgumentException("KEY_VERSIONS_REQUIRED");
        }
        Set<String> logicalVersions = new HashSet<>();
        int current = 0;
        int live = 0;
        for (KeyVersion keyVersion : keyVersions) {
            Objects.requireNonNull(keyVersion, "keyVersion");
            if (!logicalVersions.add(keyVersion.logicalVersion())) {
                throw new IllegalArgumentException(
                        "DUPLICATE_LOGICAL_VERSION");
            }
            if (keyVersion.state() == KeyState.CURRENT) {
                current++;
            }
            if (keyVersion.state() != KeyState.RETIRED) {
                live++;
            }
        }
        if (current != 1 || live > 4) {
            throw new IllegalArgumentException(
                    "INVALID_LIVE_KEY_VERSION_SET");
        }
    }

    private static void rollback(Connection connection) {
        try {
            connection.rollback();
        }
        catch (SQLException ignored) {
            // Preserve the content-free provisioning failure.
        }
    }

    /**
     * Registry state for one logical key version.
     */
    public enum KeyState {
        /**
         * Version selected for new writes.
         */
        CURRENT,

        /**
         * Version accepted only for existing tokens.
         */
        READ_ONLY,

        /**
         * Version no longer accepted at runtime.
         */
        RETIRED
    }

    /**
     * One approved provider-key mapping.
     *
     * @param logicalVersion token-visible logical version
     * @param opaqueReference immutable provider reference
     * @param state registry lifecycle state
     */
    public record KeyVersion(
            String logicalVersion,
            String opaqueReference,
            KeyState state) {

        /**
         * Creates and validates an approved key mapping.
         */
        public KeyVersion {
            Objects.requireNonNull(logicalVersion, "logicalVersion");
            Objects.requireNonNull(opaqueReference, "opaqueReference");
            Objects.requireNonNull(state, "state");
        }
    }
}
