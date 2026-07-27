package io.github.ajaygodbole7.piitoken.protocol;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

record NormalizedValue(String value, byte[] ascii) {

    NormalizedValue {
        Objects.requireNonNull(value, "value");
        ascii = ascii.clone();
    }

    static NormalizedValue of(String value) {
        return new NormalizedValue(value, value.getBytes(StandardCharsets.US_ASCII));
    }

    @Override
    public byte[] ascii() {
        return ascii.clone();
    }

    String last4() {
        return value.substring(value.length() - 4);
    }

    @Override
    public String toString() {
        return "NormalizedValue[REDACTED]";
    }
}
