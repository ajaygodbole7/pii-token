package io.github.ajaygodbole7.piitoken.protocol;

import io.github.ajaygodbole7.piitoken.annotation.Kind;
import io.github.ajaygodbole7.piitoken.annotation.Mask;
import io.github.ajaygodbole7.piitoken.descriptor.PiiFieldDescriptor;
import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TokenEngineTest {

    private static final byte[] KEY = HexFormat.of().parseHex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    private static final byte[] FIXED_SALT =
            HexFormat.of().parseHex("000102030405060708090a0b0c0d0e0f");

    @Test
    void nullStagesNullsWithoutSaltOrProviderWork() {
        var provider = new CountingProvider("k1", Set.of("k1"));
        var saltSource = new CountingSaltSource();
        var engine = new P1N1TokenEngine(provider, saltSource);

        assertThat(engine.protect(context(false, Mask.LAST4, "k1", List.of("k1")), null))
                .isEqualTo(new StagedProtection(null, null));
        assertThat(provider.calls).isZero();
        assertThat(provider.metadataCalls).isZero();
        assertThat(saltSource.calls).isZero();
    }

    @Test
    void invalidValueFailsBeforeSaltAndProvider() {
        var provider = new CountingProvider("k1", Set.of("k1"));
        var saltSource = new CountingSaltSource();
        var engine = new P1N1TokenEngine(provider, saltSource);

        assertThatThrownBy(() -> engine.protect(
                context(false, Mask.NONE, "k1", List.of("k1")), "invalid"))
                .isInstanceOf(PiiProtocolException.class)
                .hasMessage(ProtocolReason.INVALID_VALUE.name());
        assertThat(provider.calls).isZero();
        assertThat(provider.metadataCalls).isZero();
        assertThat(saltSource.calls).isZero();
    }

    @Test
    void protectStagesTokenAndLast4FromOneNormalizedValue() {
        var provider = new CountingProvider("k1", Set.of("k1"));
        var engine = new P1N1TokenEngine(provider, bytes ->
                System.arraycopy(FIXED_SALT, 0, bytes, 0, bytes.length));

        StagedProtection staged = engine.protect(
                context(false, Mask.LAST4, "k1", List.of("k1")),
                "123-45-6789");

        assertThat(staged.token()).startsWith("v2.k1.n1.");
        assertThat(staged.last4()).isEqualTo("6789");
        assertThat(provider.calls).isOne();
    }

    @Test
    void searchableRotationIsAsciiSortedBoundedAndDuplicateFree() {
        var provider = new CountingProvider("k2", Set.of("z9", "a1", "k2"));
        var engine = new P1N1TokenEngine(provider, new CountingSaltSource());

        SearchTokenSet tokens = engine.searchTokens(
                context(true, Mask.NONE, "k2", List.of("z9", "a1", "k2")),
                "123-45-6789");

        assertThat(tokens.candidates())
                .extracting(SearchTokenCandidate::keyVersion)
                .containsExactly("a1", "k2", "z9");
        assertThat(tokens.candidates()).extracting(SearchTokenCandidate::normalizerVersion)
                .containsOnly(1);
        assertThat(provider.requestedVersions).containsExactly("a1", "k2", "z9");
        assertThat(provider.calls).isEqualTo(3);
    }

    @Test
    void unknownStoredVersionFailsBeforeProviderForBothFamilies() {
        var provider = new CountingProvider("k1", Set.of("k1"));
        var engine = new P1N1TokenEngine(provider, bytes ->
                System.arraycopy(FIXED_SALT, 0, bytes, 0, bytes.length));
        String mac = "00".repeat(32);
        String salt = "00".repeat(16);

        assertThatThrownBy(() -> engine.verify(
                context(true, Mask.NONE, "k1", List.of("k1")),
                "123-45-6789",
                "b2.retired.n1." + mac))
                .isInstanceOf(PiiProtocolException.class)
                .hasMessage(ProtocolReason.UNKNOWN_KEY_VERSION.name());
        assertThatThrownBy(() -> engine.verify(
                context(false, Mask.NONE, "k1", List.of("k1")),
                "123-45-6789",
                "v2.retired.n1." + salt + "." + mac))
                .isInstanceOf(PiiProtocolException.class)
                .hasMessage(ProtocolReason.UNKNOWN_KEY_VERSION.name());

        assertThat(provider.calls).isZero();
        assertThat(provider.metadataCalls).isZero();
    }

    @Test
    void malformedStoredSearchableTokenIsErrorNotNoMatchAndCallsNoProvider() {
        var provider = new CountingProvider("k1", Set.of("k1"));
        var engine = new P1N1TokenEngine(provider, new CountingSaltSource());

        assertThatThrownBy(() -> engine.verify(
                context(true, Mask.NONE, "k1", List.of("k1")),
                "123-45-6789",
                "plaintext"))
                .isInstanceOf(PiiProtocolException.class);
        assertThat(provider.calls).isZero();
        assertThat(provider.metadataCalls).isZero();
    }

    @Test
    void searchableAndMatchOnlyVerificationReturnSemanticResult() {
        var provider = new CountingProvider("k1", Set.of("k1"));
        var engine = new P1N1TokenEngine(provider, bytes ->
                System.arraycopy(FIXED_SALT, 0, bytes, 0, bytes.length));
        var searchable = context(true, Mask.NONE, "k1", List.of("k1"));
        var matchOnly = context(false, Mask.NONE, "k1", List.of("k1"));
        String b2 = engine.protect(searchable, "123-45-6789").token();
        String v2 = engine.protect(matchOnly, "123-45-6789").token();

        assertThat(engine.verify(searchable, "123456789", b2)).isEqualTo(MatchResult.MATCH);
        assertThat(engine.verify(searchable, "987654321", b2)).isEqualTo(MatchResult.NO_MATCH);
        assertThat(engine.verify(matchOnly, "123456789", v2)).isEqualTo(MatchResult.MATCH);
        assertThat(engine.verify(matchOnly, "987654321", v2)).isEqualTo(MatchResult.NO_MATCH);
    }

    @Test
    void badProviderOutputLengthFailsClosedWithoutContent() {
        TestMacProvider provider = new CountingProvider("k1", Set.of("k1")) {
            @Override
            public byte[] macDigest(String version, byte[] digest) {
                super.macDigest(version, digest);
                return new byte[31];
            }
        };
        var engine = new P1N1TokenEngine(provider, new CountingSaltSource());

        assertThatThrownBy(() -> engine.protect(
                context(true, Mask.NONE, "k1", List.of("k1")),
                "123-45-6789"))
                .isInstanceOf(PiiProtocolException.class)
                .hasMessage(ProtocolReason.INVALID_PROVIDER_OUTPUT.name());
    }

    @Test
    void policyRejectsDuplicateOrExcessLiveVersions() {
        assertThatThrownBy(() -> context(true, Mask.NONE, "k1", List.of("k1", "k1")))
                .isInstanceOf(PiiProtocolException.class)
                .hasMessage(ProtocolReason.DUPLICATE_KEY_VERSION.name());
        assertThatThrownBy(() -> context(
                true, Mask.NONE, "k1", List.of("k1", "k2", "k3", "k4", "k5")))
                .isInstanceOf(PiiProtocolException.class)
                .hasMessage(ProtocolReason.INVALID_LIVE_KEY_SET.name());
    }

    private static TokenContext context(
            boolean searchable,
            Mask mask,
            String currentVersion,
            List<String> liveVersions) {
        return new TokenContext(
                "bank.cards",
                new PiiFieldDescriptor(
                        "customer.ssn",
                        Kind.SSN,
                        searchable,
                        mask,
                        "bank.Customer",
                        "ssn"),
                currentVersion,
                liveVersions);
    }

    private static class CountingProvider implements TestMacProvider {
        private final String current;
        private final Set<String> live;
        private int calls;
        private int metadataCalls;
        private final List<String> requestedVersions = new ArrayList<>();

        private CountingProvider(String current, Set<String> live) {
            this.current = current;
            this.live = new LinkedHashSet<>(live);
        }

        @Override
        public String currentVersion() {
            metadataCalls++;
            return current;
        }

        @Override
        public Set<String> liveVersions() {
            metadataCalls++;
            return Set.copyOf(live);
        }

        @Override
        public byte[] macDigest(String version, byte[] digest) {
            calls++;
            requestedVersions.add(version);
            try {
                Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(new SecretKeySpec(KEY, "HmacSHA256"));
                return mac.doFinal(digest);
            }
            catch (Exception exception) {
                throw new AssertionError(exception);
            }
        }
    }

    private static final class CountingSaltSource implements SaltSource {
        private int calls;

        @Override
        public void nextBytes(byte[] target) {
            calls++;
            System.arraycopy(FIXED_SALT, 0, target, 0, target.length);
        }
    }
}
