package io.github.ajaygodbole7.piitoken.protocol;

import io.github.ajaygodbole7.piitoken.annotation.Mask;
import io.github.ajaygodbole7.piitoken.provider.TokenMacProvider;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

final class P1N1TokenEngine {

    private static final Comparator<String> ASCII_ORDER = Comparator.naturalOrder();

    private final TokenMacProvider provider;
    private final SaltSource saltSource;

    P1N1TokenEngine(TokenMacProvider provider, SaltSource saltSource) {
        this.provider = Objects.requireNonNull(provider, "provider");
        this.saltSource = Objects.requireNonNull(saltSource, "saltSource");
    }

    StagedProtection protect(TokenContext context, String presentedValue) {
        if (presentedValue == null) {
            return new StagedProtection(null, null);
        }

        NormalizedValue normalized = N1Normalizer.normalize(
                context.descriptor().kind(),
                presentedValue);
        byte[] domain = ProtocolBytes.domain(context.applicationNamespace(), context.descriptor());
        byte[] salt = context.descriptor().searchable() ? null : nextSalt();
        byte[] digest = ProtocolBytes.sha256(
                ProtocolBytes.message(domain, normalized.ascii(), salt));
        byte[] mac = mac(context.currentVersion(), digest);
        String token = context.descriptor().searchable()
                ? TokenCodec.encodeSearchable(context.currentVersion(), mac)
                : TokenCodec.encodeMatchOnly(context.currentVersion(), salt, mac);
        String last4 = context.descriptor().mask() == Mask.LAST4 ? normalized.last4() : null;
        return new StagedProtection(token, last4);
    }

    SearchTokenSet searchTokens(TokenContext context, String candidate) {
        if (!context.descriptor().searchable()) {
            throw new PiiProtocolException(ProtocolReason.WRONG_OPERATION);
        }
        NormalizedValue normalized = N1Normalizer.normalize(context.descriptor().kind(), candidate);
        byte[] domain = ProtocolBytes.domain(context.applicationNamespace(), context.descriptor());
        byte[] digest = ProtocolBytes.sha256(ProtocolBytes.message(domain, normalized.ascii(), null));
        List<String> versions = context.liveVersions().stream().sorted(ASCII_ORDER).toList();
        List<SearchTokenCandidate> candidates = new ArrayList<>(versions.size());
        Set<String> outputTokens = new HashSet<>(versions.size());
        for (String version : versions) {
            String token = TokenCodec.encodeSearchable(version, mac(version, digest));
            if (!outputTokens.add(token)) {
                throw new PiiProtocolException(ProtocolReason.DUPLICATE_TOKEN);
            }
            candidates.add(new SearchTokenCandidate(
                    version,
                    ProtocolBytes.NORMALIZER_VERSION,
                    token));
        }
        return new SearchTokenSet(candidates);
    }

    MatchResult verify(TokenContext context, String candidate, String storedToken) {
        return context.descriptor().searchable()
                ? verifySearchable(context, candidate, storedToken)
                : verifyMatchOnly(context, candidate, storedToken);
    }

    private MatchResult verifySearchable(
            TokenContext context,
            String candidate,
            String storedToken) {
        ParsedSearchableToken parsed = TokenCodec.parseSearchable(storedToken);
        requireLiveVersion(context, parsed.keyVersion());
        SearchTokenSet generated = searchTokens(context, candidate);
        byte[] storedBytes = storedToken.getBytes(StandardCharsets.US_ASCII);
        boolean match = false;
        for (SearchTokenCandidate generatedToken : generated.candidates()) {
            match |= MessageDigest.isEqual(
                    storedBytes,
                    generatedToken.token().getBytes(StandardCharsets.US_ASCII));
        }
        return match ? MatchResult.MATCH : MatchResult.NO_MATCH;
    }

    private MatchResult verifyMatchOnly(
            TokenContext context,
            String candidate,
            String storedToken) {
        ParsedMatchOnlyToken parsed = TokenCodec.parseMatchOnly(storedToken);
        requireLiveVersion(context, parsed.keyVersion());
        NormalizedValue normalized = N1Normalizer.normalize(context.descriptor().kind(), candidate);
        byte[] domain = ProtocolBytes.domain(context.applicationNamespace(), context.descriptor());
        byte[] digest = ProtocolBytes.sha256(
                ProtocolBytes.message(domain, normalized.ascii(), parsed.salt()));
        byte[] expected = mac(parsed.keyVersion(), digest);
        return MessageDigest.isEqual(parsed.mac(), expected)
                ? MatchResult.MATCH
                : MatchResult.NO_MATCH;
    }

    private static void requireLiveVersion(TokenContext context, String keyVersion) {
        if (!context.liveVersions().contains(keyVersion)) {
            throw new PiiProtocolException(ProtocolReason.UNKNOWN_KEY_VERSION);
        }
    }

    private byte[] nextSalt() {
        byte[] salt = new byte[ProtocolBytes.SALT_BYTES];
        saltSource.nextBytes(salt);
        return salt;
    }

    private byte[] mac(String version, byte[] digest) {
        byte[] mac = provider.macDigest(version, digest.clone());
        if (mac == null || mac.length != ProtocolBytes.DIGEST_BYTES) {
            throw new PiiProtocolException(ProtocolReason.INVALID_PROVIDER_OUTPUT);
        }
        return mac.clone();
    }
}
