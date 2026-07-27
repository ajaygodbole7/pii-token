package io.github.ajaygodbole7.piitoken.protocol;

import io.github.ajaygodbole7.piitoken.descriptor.PiiFieldDescriptor;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;
import java.util.regex.Pattern;

final class ProtocolBytes {

    static final String COMPILED_PROFILE = "p1/n1";
    static final int NORMALIZER_VERSION = 1;
    static final String NORMALIZER_SEGMENT = "n1";
    static final int SALT_BYTES = 16;
    static final int DIGEST_BYTES = 32;

    private static final byte[] DOMAIN_TAG = "pii-tok|1|".getBytes(StandardCharsets.US_ASCII);
    private static final Pattern IDENTIFIER = Pattern.compile("[a-z0-9.-]{3,64}");

    private ProtocolBytes() {
    }

    static byte[] domain(String applicationNamespace, PiiFieldDescriptor descriptor) {
        if (applicationNamespace == null || !IDENTIFIER.matcher(applicationNamespace).matches()) {
            throw new PiiProtocolException(ProtocolReason.INVALID_NAMESPACE);
        }
        Objects.requireNonNull(descriptor, "descriptor");
        if (!IDENTIFIER.matcher(descriptor.id()).matches()) {
            throw new PiiProtocolException(ProtocolReason.INVALID_FIELD_ID);
        }

        ByteArrayOutputStream output = new ByteArrayOutputStream(150);
        output.writeBytes(DOMAIN_TAG);
        output.write(descriptor.searchable() ? 1 : 0);
        output.writeBytes(lp(applicationNamespace.getBytes(StandardCharsets.US_ASCII)));
        output.writeBytes(lp(descriptor.id().getBytes(StandardCharsets.US_ASCII)));
        output.writeBytes(lp(descriptor.kind().name().getBytes(StandardCharsets.US_ASCII)));
        output.write((NORMALIZER_VERSION >>> 8) & 0xff);
        output.write(NORMALIZER_VERSION & 0xff);
        return output.toByteArray();
    }

    static byte[] lp(byte[] value) {
        Objects.requireNonNull(value, "value");
        if (value.length > 65_535) {
            throw new IllegalArgumentException("LP_LENGTH_EXCEEDED");
        }
        byte[] framed = new byte[value.length + 2];
        framed[0] = (byte) ((value.length >>> 8) & 0xff);
        framed[1] = (byte) (value.length & 0xff);
        System.arraycopy(value, 0, framed, 2, value.length);
        return framed;
    }

    static byte[] message(byte[] domain, byte[] normalizedAscii, byte[] salt) {
        Objects.requireNonNull(domain, "domain");
        Objects.requireNonNull(normalizedAscii, "normalizedAscii");
        if (salt != null && salt.length != SALT_BYTES) {
            throw new IllegalArgumentException("INVALID_SALT_LENGTH");
        }

        byte[] framedDomain = lp(domain);
        int saltLength = salt == null ? 0 : salt.length;
        byte[] message = new byte[framedDomain.length + saltLength + normalizedAscii.length];
        int offset = 0;
        System.arraycopy(framedDomain, 0, message, offset, framedDomain.length);
        offset += framedDomain.length;
        if (salt != null) {
            System.arraycopy(salt, 0, message, offset, salt.length);
            offset += salt.length;
        }
        System.arraycopy(normalizedAscii, 0, message, offset, normalizedAscii.length);
        return message;
    }

    static byte[] sha256(byte[] message) {
        Objects.requireNonNull(message, "message");
        try {
            return MessageDigest.getInstance("SHA-256").digest(message);
        }
        catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA_256_UNAVAILABLE", impossible);
        }
    }
}
