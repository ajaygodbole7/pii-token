package io.github.ajaygodbole7.piitoken.runtime;

import io.github.ajaygodbole7.piitoken.descriptor.PiiFieldDescriptor;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

record RegistryExpectations(
        String applicationNamespace,
        List<PiiFieldDescriptor> descriptors,
        Map<String, String> expectedLiveMappings) {

    RegistryExpectations {
        Objects.requireNonNull(applicationNamespace, "applicationNamespace");
        descriptors = List.copyOf(Objects.requireNonNull(descriptors, "descriptors"));
        expectedLiveMappings = Map.copyOf(new LinkedHashMap<>(
                Objects.requireNonNull(expectedLiveMappings, "expectedLiveMappings")));
    }

    @Override
    public String toString() {
        return "RegistryExpectations[REDACTED]";
    }
}
