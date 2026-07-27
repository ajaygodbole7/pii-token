package io.github.ajaygodbole7.piitoken.runtime;

import java.util.Objects;

public final class StartupValidationException extends RuntimeException {

    private final StartupReason reason;

    StartupValidationException(StartupReason reason) {
        super(Objects.requireNonNull(reason, "reason").name());
        this.reason = reason;
    }

    StartupValidationException(StartupReason reason, String diagnostic) {
        super(Objects.requireNonNull(reason, "reason").name()
                + "\n"
                + Objects.requireNonNull(diagnostic, "diagnostic"));
        this.reason = reason;
    }

    public StartupReason reason() {
        return reason;
    }
}
