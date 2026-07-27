package io.github.ajaygodbole7.piitoken.protocol;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.HexFormat;
import java.util.Random;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TokenCodecTest {

    private static final HexFormat HEX = HexFormat.of();
    private static final byte[] MAC = HEX.parseHex(
            "18c182504e1b5c3b7107cb683152e9a8bdf1d4a38b7c7a4ca04b646251e82d77");
    private static final byte[] SALT = HEX.parseHex("000102030405060708090a0b0c0d0e0f");

    @Test
    void roundTripsCanonicalFamilies() {
        String searchable = TokenCodec.encodeSearchable("k2026_01", MAC);
        String matchOnly = TokenCodec.encodeMatchOnly("k2026_01", SALT, MAC);

        assertThat(TokenCodec.parseSearchable(searchable))
                .isEqualTo(new ParsedSearchableToken("k2026_01", MAC));
        assertThat(TokenCodec.parseMatchOnly(matchOnly))
                .isEqualTo(new ParsedMatchOnlyToken("k2026_01", SALT, MAC));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "B2.k1.n1.18c182504e1b5c3b7107cb683152e9a8bdf1d4a38b7c7a4ca04b646251e82d77",
            "b2.k1.n01.18c182504e1b5c3b7107cb683152e9a8bdf1d4a38b7c7a4ca04b646251e82d77",
            "b2.k1.n1.18C182504E1B5C3B7107CB683152E9A8BDF1D4A38B7C7A4CA04B646251E82D77",
            " b2.k1.n1.18c182504e1b5c3b7107cb683152e9a8bdf1d4a38b7c7a4ca04b646251e82d77",
            "b2.k1.n1.18c182504e1b5c3b7107cb683152e9a8bdf1d4a38b7c7a4ca04b646251e82d77.extra",
            "b2.K1.n1.18c182504e1b5c3b7107cb683152e9a8bdf1d4a38b7c7a4ca04b646251e82d77",
            "b2.k1.n1.💳"
    })
    void rejectsNonCanonicalSearchableTokens(String token) {
        assertInvalid(() -> TokenCodec.parseSearchable(token), token);
    }

    @Test
    void rejectsWrongFamilyWithTypedContentFreeReason() {
        String token = TokenCodec.encodeMatchOnly("k1", SALT, MAC);

        assertThatThrownBy(() -> TokenCodec.parseSearchable(token))
                .isInstanceOf(PiiProtocolException.class)
                .hasMessage(ProtocolReason.WRONG_TOKEN_FAMILY.name())
                .hasMessageNotContaining(token);
    }

    @Test
    void rejectsDatabaseOversizeBeforeFamilyParsing() {
        String token = "x".repeat(161);

        assertThatThrownBy(() -> TokenCodec.parseSearchable(token))
                .isInstanceOf(PiiProtocolException.class)
                .hasMessage(ProtocolReason.TOKEN_TOO_LONG.name())
                .hasMessageNotContaining(token);
    }

    @Test
    void acceptsExactMatchOnlyMaximumAndRejectsOneByteBeyondIt() {
        String maximumVersion = "k".repeat(32);
        String maximum = TokenCodec.encodeMatchOnly(maximumVersion, SALT, MAC);
        assertThat(maximum).hasSize(TokenCodec.MATCH_ONLY_MAX_LENGTH);
        assertThat(TokenCodec.parseMatchOnly(maximum).keyVersion())
                .isEqualTo(maximumVersion);

        String tooLong = maximum + "0";
        assertThat(tooLong).hasSize(TokenCodec.MATCH_ONLY_MAX_LENGTH + 1);
        assertInvalid(() -> TokenCodec.parseMatchOnly(tooLong), tooLong);
    }

    @Test
    void encodedArraysAreDefensivelyCopied() {
        var parsed = TokenCodec.parseMatchOnly(TokenCodec.encodeMatchOnly("k1", SALT, MAC));
        byte[] returnedSalt = parsed.salt();
        byte[] returnedMac = parsed.mac();
        returnedSalt[0] ^= 1;
        returnedMac[0] ^= 1;

        assertThat(parsed.salt()).isEqualTo(SALT);
        assertThat(parsed.mac()).isEqualTo(MAC);
    }

    @Test
    void randomizedCanonicalTokensRoundTripWithoutAlternateEncodings() {
        Random random = new Random(0x50314e31L);
        for (int iteration = 0; iteration < 1_000; iteration++) {
            byte[] mac = new byte[32];
            byte[] salt = new byte[16];
            random.nextBytes(mac);
            random.nextBytes(salt);
            String version = randomKeyVersion(random);

            String searchable = TokenCodec.encodeSearchable(version, mac);
            String matchOnly = TokenCodec.encodeMatchOnly(version, salt, mac);

            assertThat(TokenCodec.encodeSearchable(
                    TokenCodec.parseSearchable(searchable).keyVersion(),
                    TokenCodec.parseSearchable(searchable).mac()))
                    .isEqualTo(searchable);
            ParsedMatchOnlyToken parsed = TokenCodec.parseMatchOnly(matchOnly);
            assertThat(TokenCodec.encodeMatchOnly(parsed.keyVersion(), parsed.salt(), parsed.mac()))
                    .isEqualTo(matchOnly);
        }
    }

    private static String randomKeyVersion(Random random) {
        String alphabet = "abcdefghijklmnopqrstuvwxyz0123456789_-";
        int length = 1 + random.nextInt(32);
        StringBuilder value = new StringBuilder(length);
        value.append("abcdefghijklmnopqrstuvwxyz0123456789".charAt(random.nextInt(36)));
        for (int index = 1; index < length; index++) {
            value.append(alphabet.charAt(random.nextInt(alphabet.length())));
        }
        return value.toString();
    }

    private static void assertInvalid(Runnable operation, String content) {
        assertThatThrownBy(operation::run)
                .isInstanceOf(PiiProtocolException.class)
                .hasMessage(ProtocolReason.INVALID_TOKEN.name())
                .hasMessageNotContaining(content);
    }
}
