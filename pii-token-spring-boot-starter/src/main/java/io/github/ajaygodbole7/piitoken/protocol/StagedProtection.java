package io.github.ajaygodbole7.piitoken.protocol;

record StagedProtection(String token, String last4) {

    @Override
    public String toString() {
        return "StagedProtection[REDACTED]";
    }
}
