package io.github.ajaygodbole7.piitoken.descriptor;

import io.github.ajaygodbole7.piitoken.annotation.Mask;

import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Renders owner-reviewed migration artifacts from canonical descriptors.
 */
public final class OwnerMigrationArtifacts {

    public static final String APPROVED_FINGERPRINT_PLACEHOLDER =
            "<currently-approved-descriptor-fingerprint>";
    public static final String MIGRATION_ROOT = "META-INF/pii/migrations/fields/";

    private static final Pattern FINGERPRINT = Pattern.compile("[0-9a-f]{64}");

    private OwnerMigrationArtifacts() {
    }

    public static String fieldBlockResource(String descriptorId) {
        Objects.requireNonNull(descriptorId, "descriptorId");
        if (!descriptorId.matches("[a-z0-9.-]{3,64}")) {
            throw new IllegalArgumentException("INVALID_DESCRIPTOR_ID");
        }
        return MIGRATION_ROOT + descriptorId + ".sql";
    }

    public static String fieldDdl(PiiFieldDescriptor field) {
        Objects.requireNonNull(field, "field");
        DescriptorManifestCodec.encode(List.of(field));

        String placeholder = field.id().replace('.', '_').replace('-', '_');
        String table = "<table_" + placeholder + ">";
        String column = "<column_" + placeholder + ">";
        String qualifiedTable = "<schema>." + table;
        String family = field.searchable() ? "b2" : "v2";
        String regex = field.searchable()
                ? "^b2\\.[a-z0-9][a-z0-9_-]{0,31}\\.n1\\.[0-9a-f]{64}$"
                : "^v2\\.[a-z0-9][a-z0-9_-]{0,31}\\.n1\\.[0-9a-f]{32}"
                        + "\\.[0-9a-f]{64}$";
        int minimum = field.searchable() ? 72 : 105;
        int maximum = field.searchable() ? 103 : 136;

        StringBuilder sql = new StringBuilder();
        sql.append("-- BEGIN PII FIELD BLOCK: ")
                .append(field.id())
                .append('\n')
                .append("-- ")
                .append(field.entityClassName())
                .append('#')
                .append(field.fieldName())
                .append(" | ")
                .append(family)
                .append('\n')
                .append("-- Replace every angle-bracket placeholder with reviewed physical names.\n")
                .append("-- Apply this block only when the descriptor-aware diagnostic names it.\n")
                .append("ALTER TABLE ")
                .append(qualifiedTable)
                .append("\n    ADD CONSTRAINT <constraint_")
                .append(placeholder)
                .append("_token>\n    CHECK (\n        ")
                .append(column)
                .append(" IS NULL\n        OR (\n            ")
                .append(column)
                .append(" ~ '")
                .append(regex)
                .append("'\n            AND octet_length(")
                .append(column)
                .append(") BETWEEN ")
                .append(minimum)
                .append(" AND ")
                .append(maximum)
                .append("\n        )\n    );\n");
        if (field.mask() == Mask.LAST4) {
            String suffix = "<suffix_column_" + placeholder + ">";
            sql.append("ALTER TABLE ")
                    .append(qualifiedTable)
                    .append("\n    ADD CONSTRAINT <constraint_")
                    .append(placeholder)
                    .append("_suffix>\n    CHECK (\n        (")
                    .append(column)
                    .append(" IS NULL AND ")
                    .append(suffix)
                    .append(" IS NULL)\n        OR (\n            ")
                    .append(column)
                    .append(" IS NOT NULL\n            AND ")
                    .append(suffix)
                    .append(" ~ '^[0-9]{4}$'\n        )\n    );\n");
        }
        if (field.searchable()) {
            sql.append("CREATE INDEX <index_")
                    .append(placeholder)
                    .append("_token>\n    ON ")
                    .append(qualifiedTable)
                    .append(" (")
                    .append(column)
                    .append(");\n");
        }
        sql.append("-- END PII FIELD BLOCK: ")
                .append(field.id())
                .append('\n');
        return sql.toString();
    }

    public static String migrationPlan(List<PiiFieldDescriptor> fields) {
        String manifest = DescriptorManifestCodec.encode(fields);
        List<PiiFieldDescriptor> canonical = DescriptorManifestCodec.decode(manifest);
        StringBuilder sql = new StringBuilder("""
                -- Generated owner-applied migration plan.
                -- The library never executes this SQL.
                -- Do not execute every field block. Review and apply only the individual
                -- field resources named by the descriptor-aware diagnostic.
                --
                -- Available field blocks:
                """);
        if (canonical.isEmpty()) {
            sql.append("-- (none)\n");
        }
        else {
            for (PiiFieldDescriptor field : canonical) {
                sql.append("-- ")
                        .append(field.id())
                        .append(" -> ")
                        .append(fieldBlockResource(field.id()))
                        .append('\n');
            }
        }
        sql.append("\n")
                .append(guardedPolicyUpdate(manifest, APPROVED_FINGERPRINT_PLACEHOLDER));
        return sql.toString();
    }

    public static String guardedPolicyUpdate(
            String compiledManifest,
            String approvedFingerprint) {
        Objects.requireNonNull(compiledManifest, "compiledManifest");
        Objects.requireNonNull(approvedFingerprint, "approvedFingerprint");
        DescriptorManifestCodec.decode(compiledManifest);
        if (!APPROVED_FINGERPRINT_PLACEHOLDER.equals(approvedFingerprint)
                && !FINGERPRINT.matcher(approvedFingerprint).matches()) {
            throw new IllegalArgumentException("INVALID_APPROVED_FINGERPRINT");
        }
        String compiledFingerprint = DescriptorManifestCodec.fingerprint(compiledManifest);
        return """
                -- BEGIN GUARDED PII POLICY UPDATE
                -- Review all reported classifications before applying. A token-domain
                -- change requires recollection/new namespace; this UPDATE alone is unsafe.
                UPDATE pii_security.pii_policy_registry
                   SET descriptor_manifest = '%s',
                       descriptor_fingerprint = '%s'
                 WHERE id = 1
                   AND descriptor_fingerprint = '%s';
                -- Require exactly one affected row or roll back.
                -- END GUARDED PII POLICY UPDATE
                """.formatted(
                sqlLiteral(compiledManifest),
                compiledFingerprint,
                approvedFingerprint);
    }

    private static String sqlLiteral(String value) {
        return value.replace("'", "''");
    }
}
