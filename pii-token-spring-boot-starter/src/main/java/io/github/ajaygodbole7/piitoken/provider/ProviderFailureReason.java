package io.github.ajaygodbole7.piitoken.provider;

/**
 * Content-free provider-boundary failure classifications.
 */
public enum ProviderFailureReason {
    INVALID_INPUT,
    AUTH_FAILED,
    THROTTLED,
    UNAVAILABLE,
    DEADLINE,
    INTERRUPTED,
    UNKNOWN_VERSION,
    INVALID_RESPONSE
}
