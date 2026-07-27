package io.github.ajaygodbole7.piitoken.protocol;

import io.github.ajaygodbole7.piitoken.annotation.Kind;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class N1NormalizerTest {

    @ParameterizedTest
    @MethodSource("acceptedValues")
    void acceptsOnlyFrozenN1Grammar(Kind kind, String presented, String normalized) {
        assertThat(N1Normalizer.normalize(kind, presented).value()).isEqualTo(normalized);
    }

    static Stream<Arguments> acceptedValues() {
        return Stream.of(
                Arguments.of(Kind.SSN, "123456789", "123456789"),
                Arguments.of(Kind.SSN, "123-45-6789", "123456789"),
                Arguments.of(Kind.PAN, "4111111111111111", "4111111111111111"),
                Arguments.of(Kind.PAN, "4111 1111 1111 1111", "4111111111111111"),
                Arguments.of(Kind.PAN, "4111-1111-1111-1111", "4111111111111111"),
                Arguments.of(Kind.PAN, "4222 2222 2222 2", "4222222222222"),
                Arguments.of(Kind.PAN, "400000000002", "400000000002"),
                Arguments.of(Kind.PAN, "4000000000000000006", "4000000000000000006"));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "", " 123456789", "123456789 ", "123 45 6789", "123--45-6789",
            "１２３４５６７８９", "123–45–6789", "123-456-789"
    })
    void rejectsInvalidSsnWithoutEchoingContent(String value) {
        assertInvalid(Kind.SSN, value);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "", "4111 1111-1111 1111", "41111111111", "41111111111111111111",
            "41111 1111 1111", "4111  1111 1111", "4111_1111_1111_1111",
            "4111 1111 1111 1112", "４１１１１１１１１１１１１１１１"
    })
    void rejectsInvalidPanWithoutEchoingContent(String value) {
        assertInvalid(Kind.PAN, value);
    }

    @Test
    void last4ComesFromNormalizedAscii() {
        assertThat(N1Normalizer.normalize(Kind.SSN, "123-45-6789").last4()).isEqualTo("6789");
        assertThat(N1Normalizer.normalize(Kind.PAN, "4111 1111 1111 1111").last4()).isEqualTo("1111");
    }

    private static void assertInvalid(Kind kind, String value) {
        var assertion = assertThatThrownBy(() -> N1Normalizer.normalize(kind, value))
                .isInstanceOf(PiiProtocolException.class)
                .hasMessage(ProtocolReason.INVALID_VALUE.name());
        if (!value.isEmpty()) {
            assertion.hasMessageNotContaining(value);
        }
    }
}
