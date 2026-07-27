package io.github.ajaygodbole7.piitoken.protocol;

import io.github.ajaygodbole7.piitoken.provider.TokenMacProvider;

import java.util.Map;
import java.util.stream.Collectors;

interface TestMacProvider extends TokenMacProvider {

    @Override
    default String providerId() {
        return "test-fixture";
    }

    @Override
    default String keySetId() {
        return "test-only";
    }

    @Override
    default Map<String, String> keyMappings() {
        return liveVersions().stream().collect(Collectors.toUnmodifiableMap(
                version -> version,
                version -> "test-only-" + version));
    }

    @Override
    default void close() {
    }
}
