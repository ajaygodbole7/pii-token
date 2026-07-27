package io.github.ajaygodbole7.piitoken.protocol;

import java.util.List;

record SearchTokenSet(List<SearchTokenCandidate> candidates) {

    SearchTokenSet {
        candidates = List.copyOf(candidates);
        if (candidates.isEmpty() || candidates.size() > 4) {
            throw new PiiProtocolException(ProtocolReason.INVALID_LIVE_KEY_SET);
        }
    }

    @Override
    public String toString() {
        return "SearchTokenSet[REDACTED]";
    }
}
