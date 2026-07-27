package io.github.ajaygodbole7.piitoken.protocol;

import java.util.Arrays;
import java.util.Objects;

record ParsedMatchOnlyToken(String keyVersion, byte[] salt, byte[] mac) {

    ParsedMatchOnlyToken {
        Objects.requireNonNull(keyVersion, "keyVersion");
        salt = salt.clone();
        mac = mac.clone();
    }

    @Override
    public byte[] salt() {
        return salt.clone();
    }

    @Override
    public byte[] mac() {
        return mac.clone();
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof ParsedMatchOnlyToken that
                && keyVersion.equals(that.keyVersion)
                && Arrays.equals(salt, that.salt)
                && Arrays.equals(mac, that.mac);
    }

    @Override
    public int hashCode() {
        int result = 31 * keyVersion.hashCode() + Arrays.hashCode(salt);
        return 31 * result + Arrays.hashCode(mac);
    }

    @Override
    public String toString() {
        return "ParsedMatchOnlyToken[REDACTED]";
    }
}
