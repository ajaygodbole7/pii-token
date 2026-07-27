package io.github.ajaygodbole7.piitoken.protocol;

import java.security.SecureRandom;

final class SecureSaltSource implements SaltSource {

    private final SecureRandom secureRandom = new SecureRandom();

    @Override
    public void nextBytes(byte[] target) {
        secureRandom.nextBytes(target);
    }
}
