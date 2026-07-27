package io.github.ajaygodbole7.piitoken.descriptor;

import io.github.ajaygodbole7.piitoken.annotation.Kind;
import io.github.ajaygodbole7.piitoken.annotation.Mask;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class DescriptorManifestCodecTest {

    private static final String CANONICAL = """
            customer.pan|PAN|false|NONE|pii.slice.Customer|pan
            customer.ssn|SSN|true|LAST4|pii.slice.Customer|ssn""";

    @Test
    void reproducesFrozenCanonicalManifestAndFingerprint() {
        List<PiiFieldDescriptor> descriptors = List.of(
                descriptor("customer.ssn", Kind.SSN, true, Mask.LAST4, "ssn"),
                descriptor("customer.pan", Kind.PAN, false, Mask.NONE, "pan"));

        String manifest = DescriptorManifestCodec.encode(descriptors);

        assertThat(manifest).isEqualTo(CANONICAL);
        assertThat(DescriptorManifestCodec.fingerprint(manifest))
                .isEqualTo("8602d6bbac41b47b4ae93816ac876f126e15a41ac932dc09fec88b8538d76d51");
        assertThat(DescriptorManifestCodec.decode(manifest)).containsExactlyElementsOf(
                List.of(
                        descriptor("customer.pan", Kind.PAN, false, Mask.NONE, "pan"),
                        descriptor("customer.ssn", Kind.SSN, true, Mask.LAST4, "ssn")));
    }

    @Test
    void emptySetHasZeroByteRepresentation() {
        assertThat(DescriptorManifestCodec.encode(List.of())).isEmpty();
        assertThat(DescriptorManifestCodec.decode("")).isEmpty();
    }

    @Test
    void rejectsDuplicateIds() {
        var descriptor = descriptor("customer.ssn", Kind.SSN, false, Mask.NONE, "ssn");

        assertInvalid(() -> DescriptorManifestCodec.encode(List.of(descriptor, descriptor)));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "customer.ssn|SSN|TRUE|LAST4|pii.slice.Customer|ssn",
            "customer.ssn|SSN|true|LAST4|pii.slice.Customer|ssn\n",
            "\ncustomer.ssn|SSN|true|LAST4|pii.slice.Customer|ssn",
            "customer.ssn|SSN|true|LAST4|pii.slice.Customer|ssn\r",
            "customer.ssn|SSN|true|LAST4|pii.slice.Customer|ssn|extra",
            "customer.ssn|SSN|true|LAST4|pii.slice.Customer",
            "customer.ssn|SSN|true|LAST4|pii.slice.Customer|ssn\ncustomer.pan|PAN|false|NONE|pii.slice.Customer|pan"
    })
    void rejectsEveryNonCanonicalRepresentationWithoutEchoingIt(String manifest) {
        assertThatThrownBy(() -> DescriptorManifestCodec.decode(manifest))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("INVALID_DESCRIPTOR_MANIFEST")
                .hasMessageNotContaining(manifest);
    }

    private static PiiFieldDescriptor descriptor(
            String id,
            Kind kind,
            boolean searchable,
            Mask mask,
            String field) {
        return new PiiFieldDescriptor(id, kind, searchable, mask, "pii.slice.Customer", field);
    }

    private static void assertInvalid(Runnable operation) {
        assertThatThrownBy(operation::run)
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("INVALID_DESCRIPTOR_MANIFEST");
    }
}
