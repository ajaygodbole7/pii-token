package io.github.ajaygodbole7.piitoken.runtime;

import io.github.ajaygodbole7.piitoken.descriptor.DescriptorManifestCodec;
import io.github.ajaygodbole7.piitoken.descriptor.DescriptorDriftReport;
import io.github.ajaygodbole7.piitoken.descriptor.PiiFieldDescriptor;
import io.github.ajaygodbole7.piitoken.provider.TokenMacProvider;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

final class ApprovedRegistryLoader {

    private final DataSource dataSource;

    ApprovedRegistryLoader(DataSource dataSource) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
    }

    ApprovedRuntimePolicy load(
            RegistryExpectations expectations,
            TokenMacProvider provider) {
        Objects.requireNonNull(expectations, "expectations");
        Objects.requireNonNull(provider, "provider");
        try (Connection connection = dataSource.getConnection()) {
            try {
                configureTransaction(connection);
                verifyTransactionMode(connection);
                PolicyRow row = readPolicyRow(connection);
                validatePolicy(row, expectations, provider);
                Map<String, ApprovedKeyVersion> liveKeys = readAndValidateKeys(
                        connection,
                        expectations,
                        provider,
                        row.keySetId());
                ApprovedRuntimePolicy.validateNamespace(row.applicationNamespace());
                ApprovedRuntimePolicy policy = ApprovedRuntimePolicy.validated(
                        row.applicationNamespace(),
                        provider.providerId(),
                        row.keySetId(),
                        liveKeys,
                        expectations.descriptors());
                connection.commit();
                return policy;
            }
            catch (StartupValidationException exception) {
                rollback(connection);
                throw exception;
            }
            catch (IllegalArgumentException exception) {
                rollback(connection);
                throw new StartupValidationException(StartupReason.POLICY_INVALID);
            }
            catch (SQLException exception) {
                rollback(connection);
                throw new StartupValidationException(StartupReason.REGISTRY_IO);
            }
        }
        catch (SQLException exception) {
            throw new StartupValidationException(StartupReason.REGISTRY_IO);
        }
    }

    private static void configureTransaction(Connection connection) throws SQLException {
        connection.setReadOnly(true);
        connection.setTransactionIsolation(Connection.TRANSACTION_REPEATABLE_READ);
        connection.setAutoCommit(false);
    }

    private static void verifyTransactionMode(Connection connection) throws SQLException {
        if (!connection.isReadOnly()
                || connection.getTransactionIsolation() != Connection.TRANSACTION_REPEATABLE_READ
                || connection.getAutoCommit()) {
            throw new StartupValidationException(StartupReason.TRANSACTION_MODE_INVALID);
        }
        try (Statement statement = connection.createStatement();
             ResultSet result = statement.executeQuery("""
                     SELECT current_setting('transaction_isolation') AS isolation,
                            current_setting('transaction_read_only') AS read_only
                     """)) {
            if (!result.next()
                    || !"repeatable read".equals(result.getString("isolation"))
                    || !"on".equals(result.getString("read_only"))
                    || result.next()) {
                throw new StartupValidationException(StartupReason.TRANSACTION_MODE_INVALID);
            }
        }
    }

    private static PolicyRow readPolicyRow(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement();
             ResultSet result = statement.executeQuery("""
                     SELECT application_namespace, protocol_profile, provider_profile,
                            key_set_id, descriptor_manifest, descriptor_fingerprint
                       FROM pii_security.pii_policy_registry
                      WHERE id = 1
                     """)) {
            if (!result.next()) {
                throw new StartupValidationException(StartupReason.POLICY_ROW_MISSING);
            }
            PolicyRow row = new PolicyRow(
                    result.getString("application_namespace"),
                    result.getString("protocol_profile"),
                    result.getString("provider_profile"),
                    result.getString("key_set_id"),
                    result.getString("descriptor_manifest"),
                    result.getString("descriptor_fingerprint"));
            if (result.next()) {
                throw new StartupValidationException(StartupReason.POLICY_IDENTITY_DRIFT);
            }
            return row;
        }
    }

    private static void validatePolicy(
            PolicyRow row,
            RegistryExpectations expectations,
            TokenMacProvider provider) {
        if (!Objects.equals(expectations.applicationNamespace(), row.applicationNamespace())
                || !Objects.equals(provider.keySetId(), row.keySetId())
                || !ApprovedRuntimePolicy.PROVIDER_PROFILE.equals(row.providerProfile())) {
            throw new StartupValidationException(StartupReason.POLICY_IDENTITY_DRIFT);
        }
        if (!ApprovedRuntimePolicy.COMPILED_PROTOCOL_PROFILE.equals(row.protocolProfile())) {
            throw new StartupValidationException(StartupReason.COMPILED_PROFILE_MISMATCH);
        }

        String storedFingerprint = DescriptorManifestCodec.fingerprint(row.descriptorManifest());
        if (!storedFingerprint.equals(row.descriptorFingerprint())) {
            throw new StartupValidationException(StartupReason.MANIFEST_INTEGRITY);
        }
        try {
            DescriptorManifestCodec.decode(row.descriptorManifest());
        }
        catch (IllegalArgumentException exception) {
            throw new StartupValidationException(StartupReason.MANIFEST_INVALID);
        }
        String liveManifest = DescriptorManifestCodec.encode(expectations.descriptors());
        if (!DescriptorManifestCodec.fingerprint(liveManifest).equals(row.descriptorFingerprint())) {
            DescriptorDriftReport report = DescriptorDriftReport.compare(
                    row.descriptorManifest(),
                    liveManifest);
            throw new StartupValidationException(
                    StartupReason.DESCRIPTOR_DRIFT,
                    report.render(row.descriptorFingerprint()));
        }
    }

    private static Map<String, ApprovedKeyVersion> readAndValidateKeys(
            Connection connection,
            RegistryExpectations expectations,
            TokenMacProvider provider,
            String keySetId) throws SQLException {
        if (provider.providerId() == null
                || provider.providerId().isBlank()
                || !Objects.equals(provider.keySetId(), keySetId)) {
            throw new StartupValidationException(StartupReason.PROVIDER_IDENTITY_DRIFT);
        }

        Map<String, ApprovedKeyVersion> live = new LinkedHashMap<>();
        int currentCount = 0;
        int readOnlyCount = 0;
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT logical_version, opaque_ref, state
                  FROM pii_security.pii_key_version_registry
                 WHERE provider_id = ? AND key_set_id = ?
                """)) {
            statement.setString(1, provider.providerId());
            statement.setString(2, keySetId);
            try (ResultSet result = statement.executeQuery()) {
                while (result.next()) {
                    KeyState state;
                    try {
                        state = KeyState.valueOf(result.getString("state"));
                    }
                    catch (IllegalArgumentException | NullPointerException exception) {
                        throw new StartupValidationException(StartupReason.KEY_STATE_INVALID);
                    }
                    if (state == KeyState.RETIRED) {
                        continue;
                    }
                    String logicalVersion = result.getString("logical_version");
                    ApprovedKeyVersion approval;
                    try {
                        approval = new ApprovedKeyVersion(
                                logicalVersion,
                                result.getString("opaque_ref"),
                                state);
                    }
                    catch (IllegalArgumentException | NullPointerException exception) {
                        throw new StartupValidationException(StartupReason.KEY_STATE_INVALID);
                    }
                    if (live.putIfAbsent(logicalVersion, approval) != null) {
                        throw new StartupValidationException(StartupReason.KEY_STATE_INVALID);
                    }
                    if (state == KeyState.CURRENT) {
                        currentCount++;
                    }
                    else {
                        readOnlyCount++;
                    }
                }
            }
        }
        if (live.isEmpty()) {
            throw new StartupValidationException(StartupReason.PROVIDER_IDENTITY_DRIFT);
        }
        if (currentCount != 1 || readOnlyCount > 3 || live.size() > 4) {
            throw new StartupValidationException(StartupReason.KEY_STATE_INVALID);
        }

        Map<String, String> approvedMappings = new LinkedHashMap<>();
        live.forEach((version, approval) ->
                approvedMappings.put(version, approval.opaqueReference()));
        if (!approvedMappings.equals(expectations.expectedLiveMappings())) {
            throw new StartupValidationException(StartupReason.KEY_MAPPING_DRIFT);
        }

        Set<String> providerLive = provider.liveVersions();
        String registryCurrent = live.values().stream()
                .filter(version -> version.state() == KeyState.CURRENT)
                .map(ApprovedKeyVersion::logicalVersion)
                .findFirst()
                .orElseThrow();
        if (providerLive == null
                || !providerLive.equals(live.keySet())
                || !Objects.equals(provider.currentVersion(), registryCurrent)) {
            throw new StartupValidationException(StartupReason.PROVIDER_KEY_STATE_DRIFT);
        }
        return live;
    }

    private static void rollback(Connection connection) {
        try {
            connection.rollback();
        }
        catch (SQLException ignored) {
            // The original typed failure remains authoritative and content-free.
        }
    }

    private record PolicyRow(
            String applicationNamespace,
            String protocolProfile,
            String providerProfile,
            String keySetId,
            String descriptorManifest,
            String descriptorFingerprint) {
    }
}
