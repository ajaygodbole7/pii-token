package io.github.ajaygodbole7.piitoken.vault;

/**
 * Supplies a Vault token at call time.
 *
 * <p>The application owns authentication and renewal. Implementations should
 * return a narrowly scoped token that can update only the configured Transit
 * HMAC path. The provider does not retain or log the token.
 */
@FunctionalInterface
public interface VaultTokenSupplier {

    String token();
}
