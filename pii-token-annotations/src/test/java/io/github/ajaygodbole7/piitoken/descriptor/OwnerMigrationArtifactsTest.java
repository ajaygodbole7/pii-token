package io.github.ajaygodbole7.piitoken.descriptor;

import io.github.ajaygodbole7.piitoken.annotation.Kind;
import io.github.ajaygodbole7.piitoken.annotation.Mask;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class OwnerMigrationArtifactsTest {

    @Test
    void emitsOneFieldBlockAndASeparateGuardedApprovalPlan() {
        var searchable = new PiiFieldDescriptor(
                "customer.ssn",
                Kind.SSN,
                true,
                Mask.LAST4,
                "bank.Customer",
                "ssn");
        var matchOnly = new PiiFieldDescriptor(
                "customer.pan",
                Kind.PAN,
                false,
                Mask.NONE,
                "bank.Customer",
                "pan");

        String fieldBlock = OwnerMigrationArtifacts.fieldDdl(searchable);
        String plan = OwnerMigrationArtifacts.migrationPlan(List.of(searchable, matchOnly));

        assertThat(fieldBlock)
                .startsWith("-- BEGIN PII FIELD BLOCK: customer.ssn")
                .contains(
                        "<column_customer_ssn> ~ '^b2\\.",
                        "<suffix_column_customer_ssn> ~ '^[0-9]{4}$'",
                        "CREATE INDEX <index_customer_ssn_token>")
                .endsWith("-- END PII FIELD BLOCK: customer.ssn\n");
        assertThat(plan)
                .contains(
                        "Do not execute every field block",
                        "customer.pan -> META-INF/pii/migrations/fields/customer.pan.sql",
                        "customer.ssn -> META-INF/pii/migrations/fields/customer.ssn.sql",
                        "UPDATE pii_security.pii_policy_registry",
                        "descriptor_manifest = 'customer.pan|PAN|false|NONE|bank.Customer|pan",
                        "descriptor_fingerprint = '",
                        "AND descriptor_fingerprint = '"
                                + OwnerMigrationArtifacts.APPROVED_FINGERPRINT_PLACEHOLDER + "'")
                .doesNotContain("ALTER TABLE", "CREATE INDEX");
    }

    @Test
    void rejectsAnInvalidCasFingerprintWithoutEchoingManifestContent() {
        String manifest = DescriptorManifestCodec.encode(List.of(new PiiFieldDescriptor(
                "customer.ssn",
                Kind.SSN,
                true,
                Mask.NONE,
                "bank.Customer",
                "ssn")));

        assertThatThrownBy(() -> OwnerMigrationArtifacts.guardedPolicyUpdate(
                manifest,
                "NOT-A-FINGERPRINT"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("INVALID_APPROVED_FINGERPRINT")
                .hasMessageNotContaining(manifest);
    }
}
