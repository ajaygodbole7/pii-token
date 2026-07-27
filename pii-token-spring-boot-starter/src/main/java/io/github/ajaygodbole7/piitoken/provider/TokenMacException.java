package io.github.ajaygodbole7.piitoken.provider;

import java.util.Objects;

/**
 * Typed provider failure that never carries request or token content.
 */
public final class TokenMacException extends RuntimeException {

    private final ProviderFailureReason reason;

    public TokenMacException(ProviderFailureReason reason) {
        super(Objects.requireNonNull(reason, "reason").name());
        this.reason = reason;
    }

    public ProviderFailureReason reason() {
        return reason;
    }
}
