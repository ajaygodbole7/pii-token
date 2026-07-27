package io.github.ajaygodbole7.piitoken.protocol;

import java.util.Objects;

/**
 * A content-free protocol failure safe to propagate without protected values.
 */
public final class PiiProtocolException extends RuntimeException {

    private final ProtocolReason reason;

    PiiProtocolException(ProtocolReason reason) {
        super(Objects.requireNonNull(reason, "reason").name());
        this.reason = reason;
    }

    public ProtocolReason reason() {
        return reason;
    }
}
