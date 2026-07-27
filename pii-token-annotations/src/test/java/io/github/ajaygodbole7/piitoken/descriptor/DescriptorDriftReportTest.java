package io.github.ajaygodbole7.piitoken.descriptor;

import io.github.ajaygodbole7.piitoken.annotation.Kind;
import io.github.ajaygodbole7.piitoken.annotation.Mask;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class DescriptorDriftReportTest {

    @Test
    void reportsAddedRemovedAndAttributeLevelChangesWithNamedBlocks() {
        String approved = manifest(
                descriptor("customer.pan", Kind.PAN, false, Mask.NONE, "Customer", "pan"),
                descriptor("customer.ssn", Kind.SSN, true, Mask.NONE, "Customer", "ssn"),
                descriptor("customer.tax", Kind.SSN, false, Mask.NONE, "Customer", "taxId"));
        String compiled = manifest(
                descriptor("customer.email", Kind.PAN, false, Mask.NONE, "Customer", "email"),
                descriptor("customer.ssn", Kind.SSN, false, Mask.LAST4, "Client", "ssn"),
                descriptor("customer.tax-id", Kind.SSN, false, Mask.NONE, "Customer", "taxId"));
        String approvedFingerprint = DescriptorManifestCodec.fingerprint(approved);

        DescriptorDriftReport report = DescriptorDriftReport.compare(approved, compiled);
        String rendered = report.render(approvedFingerprint);

        assertThat(report.hasChanges()).isTrue();
        assertThat(report.hasTokenDomainChange()).isTrue();
        assertThat(report.changedFieldBlockIds())
                .containsExactly("customer.email", "customer.ssn", "customer.tax-id");
        assertThat(rendered)
                .contains(
                        "- ADDED customer.email",
                        "classifications=NEW_FIELD_SCHEMA_APPROVAL",
                        "- REMOVED customer.pan",
                        "classifications=REMOVED_FIELD_SCHEMA_APPROVAL",
                        "- ALTERED customer.ssn",
                        "searchable: true -> false",
                        "mask: NONE -> LAST4",
                        "entity: Customer -> Client",
                        "TOKEN_DOMAIN_CHANGE",
                        "COORDINATED_MAPPING_MIGRATION",
                        "FORWARD_ONLY_MASK_CHANGE",
                        "- ALTERED customer.tax -> customer.tax-id",
                        "id: customer.tax -> customer.tax-id",
                        "META-INF/pii/migrations/fields/customer.email.sql",
                        "UPDATE pii_security.pii_policy_registry",
                        "AND descriptor_fingerprint = '" + approvedFingerprint + "'",
                        "registry UPDATE alone is unsafe")
                .doesNotContain(
                        "plaintext",
                        "token=",
                        "salt=",
                        "mac=");
    }

    @Test
    void mappingOnlyChangeDoesNotClaimTokenDomainChange() {
        String approved = manifest(
                descriptor("customer.ssn", Kind.SSN, true, Mask.NONE, "Customer", "ssn"));
        String compiled = manifest(
                descriptor("customer.ssn", Kind.SSN, true, Mask.NONE, "Client", "ssn"));

        DescriptorDriftReport report = DescriptorDriftReport.compare(approved, compiled);
        String rendered = report.render(DescriptorManifestCodec.fingerprint(approved));

        assertThat(report.hasTokenDomainChange()).isFalse();
        assertThat(rendered)
                .contains("classifications=COORDINATED_MAPPING_MIGRATION")
                .doesNotContain("warning=TOKEN_DOMAIN_CHANGE");
    }

    @Test
    void refusesToRenderRepairSqlAgainstAnUnverifiedApprovedFingerprint() {
        String approved = manifest(
                descriptor("customer.ssn", Kind.SSN, true, Mask.NONE, "Customer", "ssn"));
        String compiled = manifest(
                descriptor("customer.ssn", Kind.SSN, false, Mask.NONE, "Customer", "ssn"));

        assertThatThrownBy(() -> DescriptorDriftReport.compare(approved, compiled)
                .render("0".repeat(64)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("APPROVED_FINGERPRINT_MISMATCH")
                .hasMessageNotContaining(approved)
                .hasMessageNotContaining(compiled);
    }

    private static String manifest(PiiFieldDescriptor... fields) {
        return DescriptorManifestCodec.encode(List.of(fields));
    }

    private static PiiFieldDescriptor descriptor(
            String id,
            Kind kind,
            boolean searchable,
            Mask mask,
            String entity,
            String field) {
        return new PiiFieldDescriptor(id, kind, searchable, mask, entity, field);
    }
}
