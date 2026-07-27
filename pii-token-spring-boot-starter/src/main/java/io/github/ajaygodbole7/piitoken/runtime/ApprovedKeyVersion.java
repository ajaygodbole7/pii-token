package io.github.ajaygodbole7.piitoken.runtime;

import java.util.Objects;
import java.util.regex.Pattern;

record ApprovedKeyVersion(String logicalVersion, String opaqueReference, KeyState state) {

    private static final Pattern LOGICAL_VERSION = Pattern.compile("[a-z0-9][a-z0-9_-]{0,31}");

    ApprovedKeyVersion {
        Objects.requireNonNull(logicalVersion, "logicalVersion");
        Objects.requireNonNull(opaqueReference, "opaqueReference");
        Objects.requireNonNull(state, "state");
        if (!LOGICAL_VERSION.matcher(logicalVersion).matches() || opaqueReference.isBlank()) {
            throw new IllegalArgumentException("INVALID_KEY_VERSION_APPROVAL");
        }
    }

    @Override
    public String toString() {
        return "ApprovedKeyVersion[REDACTED]";
    }
}
