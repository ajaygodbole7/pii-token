package io.github.ajaygodbole7.piitoken.protocol;

import java.util.HexFormat;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class TokenCodec {

    static final int DATABASE_MAX_LENGTH = 160;
    static final int SEARCHABLE_MIN_LENGTH = 72;
    static final int SEARCHABLE_MAX_LENGTH = 103;
    static final int MATCH_ONLY_MIN_LENGTH = 105;
    static final int MATCH_ONLY_MAX_LENGTH = 136;

    private static final Pattern KEY_VERSION = Pattern.compile("[a-z0-9][a-z0-9_-]{0,31}");
    private static final Pattern SEARCHABLE = Pattern.compile(
            "b2\\.([a-z0-9][a-z0-9_-]{0,31})\\.n1\\.([0-9a-f]{64})");
    private static final Pattern MATCH_ONLY = Pattern.compile(
            "v2\\.([a-z0-9][a-z0-9_-]{0,31})\\.n1\\.([0-9a-f]{32})\\.([0-9a-f]{64})");
    private static final HexFormat HEX = HexFormat.of();

    private TokenCodec() {
    }

    static String encodeSearchable(String keyVersion, byte[] mac) {
        validateKeyVersion(keyVersion);
        requireLength(mac, ProtocolBytes.DIGEST_BYTES);
        return "b2." + keyVersion + ".n1." + HEX.formatHex(mac);
    }

    static String encodeMatchOnly(String keyVersion, byte[] salt, byte[] mac) {
        validateKeyVersion(keyVersion);
        requireLength(salt, ProtocolBytes.SALT_BYTES);
        requireLength(mac, ProtocolBytes.DIGEST_BYTES);
        return "v2." + keyVersion + ".n1." + HEX.formatHex(salt) + "." + HEX.formatHex(mac);
    }

    static ParsedSearchableToken parseSearchable(String token) {
        enforceTotalBound(token);
        if (token.startsWith("v2.")) {
            throw new PiiProtocolException(ProtocolReason.WRONG_TOKEN_FAMILY);
        }
        if (token.length() < SEARCHABLE_MIN_LENGTH || token.length() > SEARCHABLE_MAX_LENGTH) {
            throw invalidToken();
        }
        Matcher matcher = SEARCHABLE.matcher(token);
        if (!matcher.matches()) {
            throw invalidToken();
        }
        return new ParsedSearchableToken(matcher.group(1), parseHex(matcher.group(2)));
    }

    static ParsedMatchOnlyToken parseMatchOnly(String token) {
        enforceTotalBound(token);
        if (token.startsWith("b2.")) {
            throw new PiiProtocolException(ProtocolReason.WRONG_TOKEN_FAMILY);
        }
        if (token.length() < MATCH_ONLY_MIN_LENGTH || token.length() > MATCH_ONLY_MAX_LENGTH) {
            throw invalidToken();
        }
        Matcher matcher = MATCH_ONLY.matcher(token);
        if (!matcher.matches()) {
            throw invalidToken();
        }
        return new ParsedMatchOnlyToken(
                matcher.group(1),
                parseHex(matcher.group(2)),
                parseHex(matcher.group(3)));
    }

    static void validateKeyVersion(String keyVersion) {
        if (keyVersion == null || !KEY_VERSION.matcher(keyVersion).matches()) {
            throw new PiiProtocolException(ProtocolReason.INVALID_KEY_VERSION);
        }
    }

    private static void enforceTotalBound(String token) {
        if (token == null) {
            throw invalidToken();
        }
        if (token.length() > DATABASE_MAX_LENGTH) {
            throw new PiiProtocolException(ProtocolReason.TOKEN_TOO_LONG);
        }
    }

    private static byte[] parseHex(String value) {
        try {
            return HEX.parseHex(value);
        }
        catch (IllegalArgumentException exception) {
            throw invalidToken();
        }
    }

    private static void requireLength(byte[] value, int required) {
        if (value == null || value.length != required) {
            throw new PiiProtocolException(ProtocolReason.INVALID_PROVIDER_OUTPUT);
        }
    }

    private static PiiProtocolException invalidToken() {
        return new PiiProtocolException(ProtocolReason.INVALID_TOKEN);
    }
}
