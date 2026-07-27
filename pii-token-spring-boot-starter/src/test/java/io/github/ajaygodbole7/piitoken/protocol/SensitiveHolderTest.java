package io.github.ajaygodbole7.piitoken.protocol;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Modifier;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class SensitiveHolderTest {

    @Test
    void holderToStringsNeverExposeProtectedContent() {
        String plaintext = "123456789";
        String token = "b2.k1.n1." + "ab".repeat(32);
        String last4 = "6789";
        byte[] mac = new byte[32];
        byte[] salt = new byte[16];

        assertRedacted(NormalizedValue.of(plaintext).toString(), plaintext);
        assertRedacted(new ParsedSearchableToken("k1", mac).toString(), token);
        assertRedacted(new ParsedMatchOnlyToken("k1", salt, mac).toString(), token);
        assertRedacted(new StagedProtection(token, last4).toString(), token, last4);
        var candidate = new SearchTokenCandidate("k1", 1, token);
        assertRedacted(candidate.toString(), token);
        assertRedacted(new SearchTokenSet(List.of(candidate)).toString(), token);
    }

    @Test
    void parsedTokenHoldersRemainPackagePrivate() {
        assertThat(Modifier.isPublic(ParsedSearchableToken.class.getModifiers())).isFalse();
        assertThat(Modifier.isPublic(ParsedMatchOnlyToken.class.getModifiers())).isFalse();
    }

    private static void assertRedacted(String rendered, String... forbidden) {
        assertThat(rendered).contains("REDACTED");
        for (String value : forbidden) {
            assertThat(rendered).doesNotContain(value);
        }
    }
}
