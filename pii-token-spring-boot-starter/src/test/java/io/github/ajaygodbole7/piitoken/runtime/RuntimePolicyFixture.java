package io.github.ajaygodbole7.piitoken.runtime;

import io.github.ajaygodbole7.piitoken.descriptor.PiiFieldDescriptor;
import io.github.ajaygodbole7.piitoken.descriptor.PiiFieldAccess;

import java.util.LinkedHashMap;
import java.util.List;

/**
 * Test-only construction bridge for the package-private approved-policy
 * factory and runtime-gate opener.
 */
public final class RuntimePolicyFixture {

    private RuntimePolicyFixture() {
    }

    public static PiiRuntimeGate openGate(List<PiiFieldDescriptor> descriptors) {
        var versions = new LinkedHashMap<String, ApprovedKeyVersion>();
        versions.put("k1", new ApprovedKeyVersion(
                "k1",
                "opaque-k1",
                KeyState.READ_ONLY));
        versions.put("k2", new ApprovedKeyVersion(
                "k2",
                "opaque-k2",
                KeyState.CURRENT));
        ApprovedRuntimePolicy policy = ApprovedRuntimePolicy.validated(
                "bank.cards",
                "provider",
                "key-set",
                versions,
                descriptors);
        PiiRuntimeGate gate = new PiiRuntimeGate();
        gate.open(policy);
        return gate;
    }

    public static GeneratedPiiModel generatedModel(List<PiiFieldAccess<?>> fields) {
        return new GeneratedPiiModel(fields);
    }
}
