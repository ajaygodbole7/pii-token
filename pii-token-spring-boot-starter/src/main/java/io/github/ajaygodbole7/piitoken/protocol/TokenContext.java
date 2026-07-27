package io.github.ajaygodbole7.piitoken.protocol;

import io.github.ajaygodbole7.piitoken.descriptor.PiiFieldDescriptor;

import java.util.HashSet;
import java.util.List;
import java.util.Objects;

record TokenContext(
        String applicationNamespace,
        PiiFieldDescriptor descriptor,
        String currentVersion,
        List<String> liveVersions) {

    TokenContext {
        Objects.requireNonNull(descriptor, "descriptor");
        Objects.requireNonNull(liveVersions, "liveVersions");
        ProtocolBytes.domain(applicationNamespace, descriptor);
        TokenCodec.validateKeyVersion(currentVersion);
        liveVersions = List.copyOf(liveVersions);
        if (liveVersions.isEmpty() || liveVersions.size() > 4) {
            throw new PiiProtocolException(ProtocolReason.INVALID_LIVE_KEY_SET);
        }
        for (String version : liveVersions) {
            TokenCodec.validateKeyVersion(version);
        }
        if (new HashSet<>(liveVersions).size() != liveVersions.size()) {
            throw new PiiProtocolException(ProtocolReason.DUPLICATE_KEY_VERSION);
        }
        if (!liveVersions.contains(currentVersion)) {
            throw new PiiProtocolException(ProtocolReason.INVALID_LIVE_KEY_SET);
        }
    }
}
