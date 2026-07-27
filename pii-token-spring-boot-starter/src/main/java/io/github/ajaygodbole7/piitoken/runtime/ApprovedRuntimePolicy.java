package io.github.ajaygodbole7.piitoken.runtime;

import io.github.ajaygodbole7.piitoken.descriptor.PiiFieldDescriptor;

import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;

public final class ApprovedRuntimePolicy {

    public static final String COMPILED_PROTOCOL_PROFILE = "p1/n1";
    public static final String PROVIDER_PROFILE = "HMAC_SHA256_PREHASH_V1";

    private static final Pattern NAMESPACE = Pattern.compile("[a-z0-9.-]{3,64}");

    private final String applicationNamespace;
    private final String providerId;
    private final String keySetId;
    private final Map<String, ApprovedKeyVersion> keyVersions;
    private final List<PiiFieldDescriptor> descriptors;
    private final String currentWriteVersion;

    private ApprovedRuntimePolicy(
            String applicationNamespace,
            String providerId,
            String keySetId,
            Map<String, ApprovedKeyVersion> keyVersions,
            List<PiiFieldDescriptor> descriptors) {
        validateNamespace(applicationNamespace);
        this.applicationNamespace = requireIdentity(applicationNamespace);
        this.providerId = requireIdentity(providerId);
        this.keySetId = requireIdentity(keySetId);
        Objects.requireNonNull(keyVersions, "keyVersions");
        Objects.requireNonNull(descriptors, "descriptors");

        LinkedHashMap<String, ApprovedKeyVersion> ordered = new LinkedHashMap<>();
        keyVersions.entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .forEach(entry -> {
                    if (!entry.getKey().equals(entry.getValue().logicalVersion())) {
                        throw new IllegalArgumentException("INVALID_KEY_VERSION_APPROVAL");
                    }
                    ordered.put(entry.getKey(), entry.getValue());
                });
        if (ordered.isEmpty() || ordered.size() > 4) {
            throw new IllegalArgumentException("INVALID_LIVE_KEY_SET");
        }
        long currentCount = ordered.values().stream()
                .filter(version -> version.state() == KeyState.CURRENT)
                .count();
        long readOnlyCount = ordered.values().stream()
                .filter(version -> version.state() == KeyState.READ_ONLY)
                .count();
        if (currentCount != 1 || readOnlyCount > 3
                || ordered.values().stream().anyMatch(version -> version.state() == KeyState.RETIRED)) {
            throw new IllegalArgumentException("INVALID_LIVE_KEY_SET");
        }
        this.currentWriteVersion = ordered.values().stream()
                .filter(version -> version.state() == KeyState.CURRENT)
                .map(ApprovedKeyVersion::logicalVersion)
                .findFirst()
                .orElseThrow();
        this.keyVersions = Map.copyOf(ordered);
        this.descriptors = descriptors.stream()
                .sorted(Comparator.comparing(PiiFieldDescriptor::id))
                .toList();
    }

    static ApprovedRuntimePolicy validated(
            String applicationNamespace,
            String providerId,
            String keySetId,
            Map<String, ApprovedKeyVersion> keyVersions,
            List<PiiFieldDescriptor> descriptors) {
        return new ApprovedRuntimePolicy(
                applicationNamespace,
                providerId,
                keySetId,
                keyVersions,
                descriptors);
    }

    public String applicationNamespace() {
        return applicationNamespace;
    }

    public String providerId() {
        return providerId;
    }

    public String keySetId() {
        return keySetId;
    }

    public List<String> liveKeyVersions() {
        return keyVersions.keySet().stream().sorted().toList();
    }

    public String currentWriteVersion() {
        return currentWriteVersion;
    }

    public List<PiiFieldDescriptor> descriptors() {
        return descriptors;
    }

    boolean isLive(String logicalVersion) {
        return keyVersions.containsKey(logicalVersion);
    }

    String opaqueReference(String logicalVersion) {
        ApprovedKeyVersion approval = keyVersions.get(logicalVersion);
        if (approval == null) {
            throw new IllegalArgumentException("UNKNOWN_LOGICAL_KEY_VERSION");
        }
        return approval.opaqueReference();
    }

    @Override
    public String toString() {
        return "ApprovedRuntimePolicy[REDACTED]";
    }

    private static String requireIdentity(String value) {
        Objects.requireNonNull(value, "value");
        if (value.isBlank()) {
            throw new IllegalArgumentException("INVALID_POLICY_IDENTITY");
        }
        return value;
    }

    static void validateNamespace(String namespace) {
        if (namespace == null || !NAMESPACE.matcher(namespace).matches()) {
            throw new IllegalArgumentException("INVALID_APPLICATION_NAMESPACE");
        }
    }
}
