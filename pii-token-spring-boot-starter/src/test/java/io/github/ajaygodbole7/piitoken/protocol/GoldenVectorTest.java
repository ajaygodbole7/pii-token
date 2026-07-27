package io.github.ajaygodbole7.piitoken.protocol;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.ajaygodbole7.piitoken.annotation.Kind;
import io.github.ajaygodbole7.piitoken.annotation.Mask;
import io.github.ajaygodbole7.piitoken.descriptor.PiiFieldDescriptor;
import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class GoldenVectorTest {

    private static final HexFormat HEX = HexFormat.of();

    @Test
    void productionProtocolReproducesEveryPublishedIntermediateAndToken() throws Exception {
        JsonNode fixture = new ObjectMapper().readTree(Files.readString(
                Path.of("..", "docs", "golden-vectors", "p1-n1.json")));

        assertThat(fixture.path("protocolProfile").textValue()).isEqualTo("p1/n1");
        assertThat(fixture.path("vectors")).hasSize(2);

        for (JsonNode vector : fixture.path("vectors")) {
            JsonNode input = vector.path("inputs");
            JsonNode expected = vector.path("expected");
            Kind kind = Kind.valueOf(input.path("kind").textValue());
            boolean searchable = input.path("searchable").booleanValue();
            var descriptor = new PiiFieldDescriptor(
                    input.path("piiId").textValue(),
                    kind,
                    searchable,
                    Mask.NONE,
                    "fixture.Entity",
                    "value");

            NormalizedValue normalized = N1Normalizer.normalize(kind, input.path("presentedValue").textValue());
            byte[] domain = ProtocolBytes.domain(
                    input.path("applicationNamespace").textValue(),
                    descriptor);
            byte[] salt = input.path("saltHex").isNull()
                    ? null
                    : HEX.parseHex(input.path("saltHex").textValue());
            byte[] message = ProtocolBytes.message(domain, normalized.ascii(), salt);
            byte[] digest = ProtocolBytes.sha256(message);
            byte[] mac = hmac(
                    HEX.parseHex(input.path("hmacKeyHex").textValue()),
                    digest);

            assertThat(normalized.value()).isEqualTo(expected.path("normalizedValue").textValue());
            assertThat(normalized.ascii()).isEqualTo(HEX.parseHex(expected.path("normalizedValueHex").textValue()));
            assertThat(domain).isEqualTo(HEX.parseHex(expected.path("domainHex").textValue()));
            assertThat(ProtocolBytes.lp(domain)).isEqualTo(HEX.parseHex(expected.path("lpDomainHex").textValue()));
            assertThat(message).isEqualTo(HEX.parseHex(expected.path("messageHex").textValue()));
            assertThat(digest).isEqualTo(HEX.parseHex(expected.path("sha256DigestHex").textValue()));
            assertThat(mac).isEqualTo(HEX.parseHex(expected.path("hmacSha256Hex").textValue()));

            String token = searchable
                    ? TokenCodec.encodeSearchable(input.path("logicalKeyVersion").textValue(), mac)
                    : TokenCodec.encodeMatchOnly(input.path("logicalKeyVersion").textValue(), salt, mac);
            assertThat(token).isEqualTo(expected.path("token").textValue());

            var provider = new FixtureProvider(input.path("logicalKeyVersion").textValue(),
                    HEX.parseHex(input.path("hmacKeyHex").textValue()));
            var context = new TokenContext(
                    input.path("applicationNamespace").textValue(),
                    descriptor,
                    input.path("logicalKeyVersion").textValue(),
                    List.of(input.path("logicalKeyVersion").textValue()));
            var engine = new P1N1TokenEngine(provider, bytes -> System.arraycopy(salt, 0, bytes, 0, bytes.length));

            assertThat(engine.protect(context, input.path("presentedValue").textValue()).token())
                    .isEqualTo(expected.path("token").textValue());
            assertThat(provider.lastDigest).isEqualTo(digest);
        }
    }

    @Test
    void corruptedGoldenMacNegativeControlIsDiscriminating() throws Exception {
        JsonNode vector = new ObjectMapper().readTree(Files.readString(
                        Path.of("..", "docs", "golden-vectors", "p1-n1.json")))
                .path("vectors")
                .get(0);
        JsonNode input = vector.path("inputs");
        JsonNode expected = vector.path("expected");
        var descriptor = new PiiFieldDescriptor(
                input.path("piiId").textValue(),
                Kind.valueOf(input.path("kind").textValue()),
                input.path("searchable").booleanValue(),
                Mask.NONE,
                "fixture.Entity",
                "value");
        byte[] normalized = N1Normalizer.normalize(
                        descriptor.kind(),
                        input.path("presentedValue").textValue())
                .ascii();
        byte[] digest = ProtocolBytes.sha256(ProtocolBytes.message(
                ProtocolBytes.domain(
                        input.path("applicationNamespace").textValue(),
                        descriptor),
                normalized,
                null));
        String recomputed = HEX.formatHex(hmac(
                HEX.parseHex(input.path("hmacKeyHex").textValue()),
                digest));
        String published = expected.path("hmacSha256Hex").textValue();
        char replacement = published.charAt(0) == '0' ? '1' : '0';
        String corrupted = replacement + published.substring(1);

        assertThat(recomputed).isEqualTo(published).isNotEqualTo(corrupted);
    }

    private static byte[] hmac(byte[] key, byte[] digest) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(digest);
    }

    private static final class FixtureProvider implements TestMacProvider {
        private final String version;
        private final byte[] key;
        private byte[] lastDigest;

        private FixtureProvider(String version, byte[] key) {
            this.version = version;
            this.key = key.clone();
        }

        @Override
        public String currentVersion() {
            return version;
        }

        @Override
        public java.util.Set<String> liveVersions() {
            return java.util.Set.of(version);
        }

        @Override
        public byte[] macDigest(String requestedVersion, byte[] digest) {
            assertThat(requestedVersion).isEqualTo(version);
            lastDigest = digest.clone();
            try {
                return hmac(key, digest);
            }
            catch (Exception exception) {
                throw new AssertionError(exception);
            }
        }
    }
}
