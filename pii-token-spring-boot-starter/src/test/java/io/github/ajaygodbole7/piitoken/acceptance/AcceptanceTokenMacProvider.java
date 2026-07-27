package io.github.ajaygodbole7.piitoken.acceptance;

import io.github.ajaygodbole7.piitoken.provider.ProviderFailureReason;
import io.github.ajaygodbole7.piitoken.provider.TokenMacException;
import io.github.ajaygodbole7.piitoken.provider.TokenMacProvider;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

final class AcceptanceTokenMacProvider implements TokenMacProvider {

    private final AtomicInteger calls = new AtomicInteger();

    @Override
    public String providerId() {
        return "test-provider";
    }

    @Override
    public String keySetId() {
        return "acceptance-key-set";
    }

    @Override
    public String currentVersion() {
        return "k2";
    }

    @Override
    public Set<String> liveVersions() {
        return Set.of("k1", "k2");
    }

    @Override
    public Map<String, String> keyMappings() {
        return Map.of("k1", "opaque-k1", "k2", "opaque-k2");
    }

    @Override
    public byte[] macDigest(String logicalVersion, byte[] sha256Digest) {
        if (logicalVersion == null
                || sha256Digest == null
                || sha256Digest.length != 32) {
            throw new TokenMacException(ProviderFailureReason.INVALID_INPUT);
        }
        if (!liveVersions().contains(logicalVersion)) {
            throw new TokenMacException(ProviderFailureReason.UNKNOWN_VERSION);
        }
        calls.incrementAndGet();
        try {
            byte[] key = MessageDigest.getInstance("SHA-256")
                    .digest(("TEST-ONLY-" + logicalVersion)
                            .getBytes(StandardCharsets.US_ASCII));
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(sha256Digest);
        }
        catch (Exception exception) {
            throw new AssertionError(exception);
        }
    }

    int calls() {
        return calls.get();
    }

    void resetCalls() {
        calls.set(0);
    }

    @Override
    public void close() {
    }
}
