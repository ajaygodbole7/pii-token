package io.github.ajaygodbole7.piitoken.provider;

import java.util.Map;
import java.util.Set;

/**
 * Provider-neutral HMAC-SHA-256 over a precomputed SHA-256 digest.
 *
 * <p>A production implementation keeps key material non-exportable and accepts
 * only the exact 32-byte SHA-256 digest supplied to {@link #macDigest}. The
 * provider must treat identity and version metadata as immutable snapshots,
 * reject unknown logical versions before a remote call, and own one bounded
 * retry layer, total deadline, and concurrency cap.
 *
 * <p>Implementations must not mutate caller-owned digest arrays. Failures use
 * {@link TokenMacException} with content-free reason codes. A null logical
 * version, null digest, or invalid digest length is
 * {@link ProviderFailureReason#INVALID_INPUT}; an unmapped logical version is
 * {@link ProviderFailureReason#UNKNOWN_VERSION}.
 */
public interface TokenMacProvider extends AutoCloseable {

    String providerId();

    String keySetId();

    String currentVersion();

    Set<String> liveVersions();

    /**
     * Returns the immutable logical-version to provider-key-reference mapping.
     *
     * <p>The opaque values must identify the same remote keys used by
     * {@link #macDigest}. Startup compares this mapping directly with the
     * approved registry; applications must not maintain a duplicate mapping.
     */
    Map<String, String> keyMappings();

    /**
     * Computes HMAC-SHA-256 over exactly the supplied 32-byte SHA-256 digest.
     *
     * <p>The digest is already hashed and must not be hashed again. The result
     * is exactly 32 bytes. A logical version is resolved only through the
     * provider's immutable allowlisted mapping.
     */
    byte[] macDigest(String logicalVersion, byte[] sha256Digest);

    @Override
    void close();
}
