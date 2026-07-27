package io.github.ajaygodbole7.piitoken.runtime;

public final class PiiGateClosedException extends IllegalStateException {

    PiiGateClosedException() {
        super("PII_RUNTIME_GATE_CLOSED");
    }
}
