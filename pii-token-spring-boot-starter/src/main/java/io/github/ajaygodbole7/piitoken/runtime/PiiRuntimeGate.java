package io.github.ajaygodbole7.piitoken.runtime;

import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

public final class PiiRuntimeGate {

    private final AtomicReference<ApprovedRuntimePolicy> policy = new AtomicReference<>();

    void open(ApprovedRuntimePolicy approvedPolicy) {
        Objects.requireNonNull(approvedPolicy, "approvedPolicy");
        if (!policy.compareAndSet(null, approvedPolicy)) {
            throw new IllegalStateException("PII_RUNTIME_GATE_ALREADY_OPEN");
        }
    }

    public ApprovedRuntimePolicy require() {
        ApprovedRuntimePolicy approved = policy.get();
        if (approved == null) {
            throw new PiiGateClosedException();
        }
        return approved;
    }
}
