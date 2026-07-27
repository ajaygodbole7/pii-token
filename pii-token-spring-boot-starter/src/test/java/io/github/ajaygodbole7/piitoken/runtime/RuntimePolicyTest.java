package io.github.ajaygodbole7.piitoken.runtime;

import io.github.ajaygodbole7.piitoken.annotation.Kind;
import io.github.ajaygodbole7.piitoken.annotation.Mask;
import io.github.ajaygodbole7.piitoken.descriptor.PiiFieldDescriptor;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Modifier;
import java.util.LinkedHashMap;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RuntimePolicyTest {

    @Test
    void gateIsClosedByDefaultAndSingleAssignment() {
        var gate = new PiiRuntimeGate();
        ApprovedRuntimePolicy policy = policy();

        assertThatThrownBy(gate::require)
                .isInstanceOf(PiiGateClosedException.class)
                .hasMessage("PII_RUNTIME_GATE_CLOSED");

        gate.open(policy);
        assertThat(gate.require()).isSameAs(policy);
        assertThatThrownBy(() -> gate.open(policy))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("PII_RUNTIME_GATE_ALREADY_OPEN");
    }

    @Test
    void policyIsImmutableAndAsciiOrdersLiveVersions() {
        var mappings = new LinkedHashMap<String, ApprovedKeyVersion>();
        mappings.put("z9", new ApprovedKeyVersion("z9", "opaque-z", KeyState.READ_ONLY));
        mappings.put("a1", new ApprovedKeyVersion("a1", "opaque-a", KeyState.READ_ONLY));
        mappings.put("k2", new ApprovedKeyVersion("k2", "opaque-k", KeyState.CURRENT));

        ApprovedRuntimePolicy policy = ApprovedRuntimePolicy.validated(
                "bank.cards",
                "provider",
                "key-set",
                mappings,
                List.of(descriptor()));

        assertThat(policy.liveKeyVersions()).containsExactly("a1", "k2", "z9");
        assertThat(policy.currentWriteVersion()).isEqualTo("k2");
        assertThat(policy.descriptors()).containsExactly(descriptor());
        assertThatThrownBy(() -> policy.liveKeyVersions().add("x"))
                .isInstanceOf(UnsupportedOperationException.class);
        assertThat(policy.toString()).doesNotContain("opaque-a", "customer.ssn");
    }

    @Test
    void policyCannotBeConstructedThroughPublicApi() {
        assertThat(ApprovedRuntimePolicy.class.getDeclaredConstructors())
                .allMatch(constructor -> !Modifier.isPublic(constructor.getModifiers()));
        assertThat(ApprovedRuntimePolicy.class.getDeclaredMethods())
                .filteredOn(method -> Modifier.isStatic(method.getModifiers())
                        && method.getReturnType() == ApprovedRuntimePolicy.class)
                .allMatch(method -> !Modifier.isPublic(method.getModifiers()));
    }

    private static ApprovedRuntimePolicy policy() {
        return ApprovedRuntimePolicy.validated(
                "bank.cards",
                "provider",
                "key-set",
                java.util.Map.of(
                        "k1", new ApprovedKeyVersion("k1", "opaque-k1", KeyState.CURRENT)),
                List.of(descriptor()));
    }

    private static PiiFieldDescriptor descriptor() {
        return new PiiFieldDescriptor(
                "customer.ssn",
                Kind.SSN,
                true,
                Mask.LAST4,
                "bank.Customer",
                "ssn");
    }
}
