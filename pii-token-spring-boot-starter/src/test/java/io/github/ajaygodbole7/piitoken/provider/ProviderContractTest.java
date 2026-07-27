package io.github.ajaygodbole7.piitoken.provider;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

class ProviderContractTest {

    @Test
    void spiExposesOnlyPrehashedMacCapability() {
        assertThat(Arrays.stream(TokenMacProvider.class.getDeclaredMethods())
                .map(Method::getName))
                .containsExactlyInAnyOrder(
                        "providerId",
                        "keySetId",
                        "currentVersion",
                        "liveVersions",
                        "keyMappings",
                        "macDigest",
                        "close")
                .noneMatch(name -> name.toLowerCase().contains("keymaterial")
                        || name.toLowerCase().contains("encrypt")
                        || name.toLowerCase().contains("decrypt")
                        || name.toLowerCase().contains("sign"));
    }

    @Test
    void providerFailuresCarryOnlyTypedReason() {
        var failure = new TokenMacException(ProviderFailureReason.AUTH_FAILED);

        assertThat(failure.reason()).isEqualTo(ProviderFailureReason.AUTH_FAILED);
        assertThat(failure).hasMessage("AUTH_FAILED");
    }

    @Test
    void providerFailureReasonsAreStableAndIncludeCallerInputRejection() {
        assertThat(ProviderFailureReason.values()).containsExactly(
                ProviderFailureReason.INVALID_INPUT,
                ProviderFailureReason.AUTH_FAILED,
                ProviderFailureReason.THROTTLED,
                ProviderFailureReason.UNAVAILABLE,
                ProviderFailureReason.DEADLINE,
                ProviderFailureReason.INTERRUPTED,
                ProviderFailureReason.UNKNOWN_VERSION,
                ProviderFailureReason.INVALID_RESPONSE);
    }
}
