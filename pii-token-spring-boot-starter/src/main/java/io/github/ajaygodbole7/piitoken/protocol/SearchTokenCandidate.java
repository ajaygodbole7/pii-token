package io.github.ajaygodbole7.piitoken.protocol;

import java.util.Objects;

record SearchTokenCandidate(String keyVersion, int normalizerVersion, String token) {

    SearchTokenCandidate {
        Objects.requireNonNull(keyVersion, "keyVersion");
        Objects.requireNonNull(token, "token");
    }

    @Override
    public String toString() {
        return "SearchTokenCandidate[REDACTED]";
    }
}
