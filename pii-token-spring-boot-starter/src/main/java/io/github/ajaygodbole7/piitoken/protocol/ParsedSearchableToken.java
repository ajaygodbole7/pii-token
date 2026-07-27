package io.github.ajaygodbole7.piitoken.protocol;

import java.util.Arrays;
import java.util.Objects;

record ParsedSearchableToken(String keyVersion, byte[] mac) {

    ParsedSearchableToken {
        Objects.requireNonNull(keyVersion, "keyVersion");
        mac = mac.clone();
    }

    @Override
    public byte[] mac() {
        return mac.clone();
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof ParsedSearchableToken that
                && keyVersion.equals(that.keyVersion)
                && Arrays.equals(mac, that.mac);
    }

    @Override
    public int hashCode() {
        return 31 * keyVersion.hashCode() + Arrays.hashCode(mac);
    }

    @Override
    public String toString() {
        return "ParsedSearchableToken[REDACTED]";
    }
}
