package io.github.ajaygodbole7.piitoken.protocol;

@FunctionalInterface
interface SaltSource {

    void nextBytes(byte[] target);
}
