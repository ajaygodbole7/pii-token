package io.github.ajaygodbole7.piitoken.vault;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.ajaygodbole7.piitoken.provider.ProviderFailureReason;
import io.github.ajaygodbole7.piitoken.provider.TokenMacException;
import io.github.ajaygodbole7.piitoken.provider.TokenMacProvider;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Flow;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * HashiCorp Vault Transit implementation of the token MAC boundary.
 *
 * <p>Each logical version is pinned to an explicit numeric Transit key
 * version. The adapter sends exactly the caller's 32-byte digest as the HMAC
 * input and never asks Vault to use the latest key version.
 */
public final class VaultTransitTokenMacProvider implements TokenMacProvider {

    public static final String PROVIDER_ID = "hashicorp-vault-transit";

    private static final int SHA256_BYTES = 32;
    private static final int MAX_RESPONSE_BYTES = 4096;
    private static final Pattern SAFE_PATH_SEGMENT =
            Pattern.compile("[A-Za-z0-9][A-Za-z0-9_-]{0,127}");
    private static final Pattern LOGICAL_VERSION =
            Pattern.compile("[a-z][a-z0-9_-]{0,31}");
    private static final Pattern VERSIONED_HMAC =
            Pattern.compile("vault:v([1-9][0-9]*):([A-Za-z0-9+/]+={0,2})");

    private final URI hmacEndpoint;
    private final String namespace;
    private final String keySetId;
    private final String currentVersion;
    private final Map<String, Integer> transitVersions;
    private final Map<String, String> keyMappings;
    private final Duration totalDeadline;
    private final Duration retryDelay;
    private final int maxAttempts;
    private final Semaphore concurrency;
    private final VaultTokenSupplier tokenSupplier;
    private final HttpClient httpClient;
    private final boolean ownsHttpClient;
    private final ObjectMapper objectMapper;
    private final AtomicBoolean closed = new AtomicBoolean();

    public VaultTransitTokenMacProvider(
            VaultTransitProperties properties,
            VaultTokenSupplier tokenSupplier) {
        this(properties, tokenSupplier, null, true);
    }

    /**
     * Creates a provider with an application-owned HTTP client, for example one
     * configured with a corporate trust store, mTLS identity, or proxy.
     */
    public VaultTransitTokenMacProvider(
            VaultTransitProperties properties,
            VaultTokenSupplier tokenSupplier,
            HttpClient httpClient) {
        this(properties, tokenSupplier, httpClient, false);
    }

    private VaultTransitTokenMacProvider(
            VaultTransitProperties properties,
            VaultTokenSupplier tokenSupplier,
            HttpClient httpClient,
            boolean ownsHttpClient) {
        Objects.requireNonNull(properties, "properties");
        this.tokenSupplier = Objects.requireNonNull(tokenSupplier, "tokenSupplier");
        if (!ownsHttpClient) {
            Objects.requireNonNull(httpClient, "httpClient");
        }

        URI address = validAddress(
                properties.getAddress(),
                properties.isAllowInsecureHttp());
        String mount = safePathSegment(properties.getMount());
        String keyName = safePathSegment(properties.getKeyName());
        this.namespace = validNamespace(properties.getNamespace());
        this.keySetId = nonSecretIdentifier(properties.getKeySetId());
        this.currentVersion = logicalVersion(properties.getCurrentVersion());
        this.transitVersions = validVersions(properties.getVersions());
        if (!transitVersions.containsKey(currentVersion)) {
            throw invalidConfiguration();
        }
        this.keyMappings = opaqueMappings(mount, keyName, transitVersions);
        this.totalDeadline = positive(properties.getTotalDeadline());
        this.retryDelay = nonNegative(properties.getRetryDelay());
        this.maxAttempts = bounded(properties.getMaxAttempts(), 1, 3);
        int maxConcurrency = bounded(properties.getMaxConcurrency(), 1, 10_000);
        this.concurrency = new Semaphore(maxConcurrency, true);
        this.hmacEndpoint = endpoint(address, mount, keyName);
        this.httpClient = ownsHttpClient
                ? defaultHttpClient(properties)
                : httpClient;
        this.ownsHttpClient = ownsHttpClient;
        this.objectMapper = new ObjectMapper();
    }

    @Override
    public String providerId() {
        return PROVIDER_ID;
    }

    @Override
    public String keySetId() {
        return keySetId;
    }

    @Override
    public String currentVersion() {
        return currentVersion;
    }

    @Override
    public Set<String> liveVersions() {
        return transitVersions.keySet();
    }

    @Override
    public Map<String, String> keyMappings() {
        return keyMappings;
    }

    @Override
    public byte[] macDigest(String logicalVersion, byte[] sha256Digest) {
        if (logicalVersion == null
                || sha256Digest == null
                || sha256Digest.length != SHA256_BYTES) {
            throw failure(ProviderFailureReason.INVALID_INPUT);
        }
        Integer transitVersion = transitVersions.get(logicalVersion);
        if (transitVersion == null) {
            throw failure(ProviderFailureReason.UNKNOWN_VERSION);
        }
        if (closed.get()) {
            throw failure(ProviderFailureReason.UNAVAILABLE);
        }

        long deadline = saturatedAdd(System.nanoTime(), totalDeadline.toNanos());
        byte[] digest = sha256Digest.clone();
        acquirePermit(deadline);
        try {
            for (int attempt = 1; attempt <= maxAttempts; attempt++) {
                try {
                    return requestMac(transitVersion, digest, deadline);
                }
                catch (TokenMacException exception) {
                    if (attempt == maxAttempts || !retryable(exception.reason())) {
                        throw exception;
                    }
                    waitBeforeRetry(deadline);
                }
            }
            throw failure(ProviderFailureReason.UNAVAILABLE);
        }
        finally {
            concurrency.release();
        }
    }

    @Override
    public void close() {
        if (closed.compareAndSet(false, true) && ownsHttpClient) {
            httpClient.close();
        }
    }

    private byte[] requestMac(
            int transitVersion,
            byte[] sha256Digest,
            long deadline) {
        String token;
        try {
            token = tokenSupplier.token();
        }
        catch (RuntimeException exception) {
            throw failure(ProviderFailureReason.AUTH_FAILED);
        }
        if (!validHeaderValue(token)) {
            throw failure(ProviderFailureReason.AUTH_FAILED);
        }
        Duration remaining = remaining(deadline);

        ObjectNode payload = objectMapper.createObjectNode();
        payload.put("input", Base64.getEncoder().encodeToString(sha256Digest));
        payload.put("key_version", transitVersion);

        HttpRequest.Builder request = HttpRequest.newBuilder(hmacEndpoint)
                .timeout(remaining)
                .header("Content-Type", "application/json")
                .header("X-Vault-Token", token)
                .POST(HttpRequest.BodyPublishers.ofString(payload.toString()));
        if (namespace != null) {
            request.header("X-Vault-Namespace", namespace);
        }

        HttpResponse<byte[]> response;
        try {
            response = httpClient.send(
                    request.build(),
                    responseInfo -> responseInfo.statusCode() == 200
                            ? new LimitedBodySubscriber(MAX_RESPONSE_BYTES)
                            : HttpResponse.BodySubscribers.replacing(new byte[0]));
        }
        catch (HttpTimeoutException exception) {
            throw failure(ProviderFailureReason.DEADLINE);
        }
        catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw failure(ProviderFailureReason.INTERRUPTED);
        }
        catch (IOException exception) {
            throw failure(hasCause(exception, BodyLimitExceededException.class)
                    ? ProviderFailureReason.INVALID_RESPONSE
                    : ProviderFailureReason.UNAVAILABLE);
        }
        catch (RuntimeException exception) {
            throw failure(ProviderFailureReason.UNAVAILABLE);
        }

        if (response.statusCode() != 200) {
            throw failure(reasonForStatus(response.statusCode()));
        }
        byte[] mac = parseMac(response.body(), transitVersion);
        return mac;
    }

    private byte[] parseMac(byte[] response, int expectedVersion) {
        try {
            JsonNode hmacNode = objectMapper.readTree(response)
                    .path("data")
                    .path("hmac");
            if (!hmacNode.isTextual()) {
                throw failure(ProviderFailureReason.INVALID_RESPONSE);
            }
            Matcher matcher = VERSIONED_HMAC.matcher(hmacNode.textValue());
            if (!matcher.matches()
                    || Integer.parseInt(matcher.group(1)) != expectedVersion) {
                throw failure(ProviderFailureReason.INVALID_RESPONSE);
            }
            byte[] mac = Base64.getDecoder().decode(matcher.group(2));
            if (mac.length != SHA256_BYTES) {
                throw failure(ProviderFailureReason.INVALID_RESPONSE);
            }
            return mac;
        }
        catch (TokenMacException exception) {
            throw exception;
        }
        catch (RuntimeException | IOException exception) {
            throw failure(ProviderFailureReason.INVALID_RESPONSE);
        }
    }

    private void acquirePermit(long deadline) {
        try {
            long remainingNanos = deadline - System.nanoTime();
            if (remainingNanos <= 0
                    || !concurrency.tryAcquire(remainingNanos, TimeUnit.NANOSECONDS)) {
                throw failure(ProviderFailureReason.DEADLINE);
            }
        }
        catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw failure(ProviderFailureReason.INTERRUPTED);
        }
    }

    private void waitBeforeRetry(long deadline) {
        long delayNanos = retryDelay.toNanos();
        if (delayNanos == 0) {
            remaining(deadline);
            return;
        }
        long remainingNanos = deadline - System.nanoTime();
        if (remainingNanos <= delayNanos) {
            throw failure(ProviderFailureReason.DEADLINE);
        }
        try {
            TimeUnit.NANOSECONDS.sleep(delayNanos);
        }
        catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw failure(ProviderFailureReason.INTERRUPTED);
        }
    }

    private static ProviderFailureReason reasonForStatus(int status) {
        return switch (status) {
            case 400 -> ProviderFailureReason.INVALID_INPUT;
            case 401, 403 -> ProviderFailureReason.AUTH_FAILED;
            case 408 -> ProviderFailureReason.DEADLINE;
            case 429 -> ProviderFailureReason.THROTTLED;
            default -> status >= 500
                    ? ProviderFailureReason.UNAVAILABLE
                    : ProviderFailureReason.INVALID_RESPONSE;
        };
    }

    private static boolean retryable(ProviderFailureReason reason) {
        return reason == ProviderFailureReason.THROTTLED
                || reason == ProviderFailureReason.UNAVAILABLE;
    }

    private static URI validAddress(URI address, boolean allowInsecureHttp) {
        if (address == null
                || !address.isAbsolute()
                || address.getHost() == null
                || address.getUserInfo() != null
                || address.getQuery() != null
                || address.getFragment() != null
                || !(address.getPath().isEmpty() || address.getPath().equals("/"))) {
            throw invalidConfiguration();
        }
        if (!address.getScheme().equals("https")
                && !(allowInsecureHttp && address.getScheme().equals("http"))) {
            throw invalidConfiguration();
        }
        return address;
    }

    private static URI endpoint(URI address, String mount, String keyName) {
        String base = address.toString();
        if (!base.endsWith("/")) {
            base += "/";
        }
        return URI.create(base + "v1/" + mount + "/hmac/" + keyName + "/sha2-256");
    }

    private static String safePathSegment(String value) {
        if (value == null || !SAFE_PATH_SEGMENT.matcher(value).matches()) {
            throw invalidConfiguration();
        }
        return value;
    }

    private static String logicalVersion(String value) {
        if (value == null || !LOGICAL_VERSION.matcher(value).matches()) {
            throw invalidConfiguration();
        }
        return value;
    }

    private static String nonSecretIdentifier(String value) {
        if (value == null
                || value.isBlank()
                || value.length() > 128
                || containsControlCharacter(value)) {
            throw invalidConfiguration();
        }
        return value;
    }

    private static String validNamespace(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        if (value.length() > 256 || !validHeaderValue(value)) {
            throw invalidConfiguration();
        }
        return value;
    }

    private static Map<String, Integer> validVersions(Map<String, Integer> versions) {
        if (versions == null || versions.isEmpty() || versions.size() > 4) {
            throw invalidConfiguration();
        }
        var copy = new LinkedHashMap<String, Integer>();
        for (Map.Entry<String, Integer> entry : versions.entrySet()) {
            String logical = logicalVersion(entry.getKey());
            Integer numeric = entry.getValue();
            if (numeric == null || numeric < 1) {
                throw invalidConfiguration();
            }
            copy.put(logical, numeric);
        }
        if (Set.copyOf(copy.values()).size() != copy.size()) {
            throw invalidConfiguration();
        }
        return Map.copyOf(copy);
    }

    private static Map<String, String> opaqueMappings(
            String mount,
            String keyName,
            Map<String, Integer> versions) {
        var mappings = new LinkedHashMap<String, String>();
        versions.forEach((logical, numeric) -> mappings.put(
                logical,
                "vault-transit:" + mount + ":" + keyName + ":v" + numeric));
        return Map.copyOf(mappings);
    }

    private static Duration positive(Duration value) {
        if (value == null || value.isZero() || value.isNegative()) {
            throw invalidConfiguration();
        }
        try {
            value.toNanos();
        }
        catch (ArithmeticException exception) {
            throw invalidConfiguration();
        }
        return value;
    }

    private static Duration nonNegative(Duration value) {
        if (value == null || value.isNegative()) {
            throw invalidConfiguration();
        }
        try {
            value.toNanos();
        }
        catch (ArithmeticException exception) {
            throw invalidConfiguration();
        }
        return value;
    }

    private static int bounded(int value, int minimum, int maximum) {
        if (value < minimum || value > maximum) {
            throw invalidConfiguration();
        }
        return value;
    }

    private static Duration remaining(long deadline) {
        long nanos = deadline - System.nanoTime();
        if (nanos <= 0) {
            throw failure(ProviderFailureReason.DEADLINE);
        }
        return Duration.ofNanos(nanos);
    }

    private static long saturatedAdd(long left, long right) {
        long result = left + right;
        if (((left ^ result) & (right ^ result)) < 0) {
            return Long.MAX_VALUE;
        }
        return result;
    }

    private static boolean containsControlCharacter(String value) {
        return value.chars().anyMatch(Character::isISOControl);
    }

    private static boolean validHeaderValue(String value) {
        return value != null
                && !value.isBlank()
                && value.chars().allMatch(character ->
                character >= 0x21 && character <= 0x7e);
    }

    private static HttpClient defaultHttpClient(VaultTransitProperties properties) {
        Objects.requireNonNull(properties, "properties");
        return HttpClient.newBuilder()
                .connectTimeout(positive(properties.getTotalDeadline()))
                .build();
    }

    private static boolean hasCause(Throwable failure, Class<? extends Throwable> type) {
        Throwable candidate = failure;
        while (candidate != null) {
            if (type.isInstance(candidate)) {
                return true;
            }
            candidate = candidate.getCause();
        }
        return false;
    }

    private static IllegalArgumentException invalidConfiguration() {
        return new IllegalArgumentException("VAULT_CONFIGURATION_INVALID");
    }

    private static TokenMacException failure(ProviderFailureReason reason) {
        return new TokenMacException(reason);
    }

    private static final class LimitedBodySubscriber
            implements HttpResponse.BodySubscriber<byte[]> {

        private final int maximumBytes;
        private final ByteArrayOutputStream output = new ByteArrayOutputStream();
        private final CompletableFuture<byte[]> body = new CompletableFuture<>();
        private Flow.Subscription subscription;
        private int received;

        private LimitedBodySubscriber(int maximumBytes) {
            this.maximumBytes = maximumBytes;
        }

        @Override
        public CompletionStage<byte[]> getBody() {
            return body;
        }

        @Override
        public void onSubscribe(Flow.Subscription subscription) {
            if (this.subscription != null) {
                subscription.cancel();
                return;
            }
            this.subscription = subscription;
            subscription.request(1);
        }

        @Override
        public void onNext(List<ByteBuffer> buffers) {
            try {
                for (ByteBuffer buffer : buffers) {
                    int next = buffer.remaining();
                    if (received > maximumBytes - next) {
                        subscription.cancel();
                        body.completeExceptionally(new BodyLimitExceededException());
                        return;
                    }
                    received += next;
                    byte[] bytes = new byte[next];
                    buffer.get(bytes);
                    output.writeBytes(bytes);
                }
                subscription.request(1);
            }
            catch (RuntimeException exception) {
                subscription.cancel();
                body.completeExceptionally(new BodyLimitExceededException());
            }
        }

        @Override
        public void onError(Throwable throwable) {
            body.completeExceptionally(throwable);
        }

        @Override
        public void onComplete() {
            body.complete(output.toByteArray());
        }
    }

    private static final class BodyLimitExceededException extends RuntimeException {

        private BodyLimitExceededException() {
            super("VAULT_RESPONSE_TOO_LARGE");
        }
    }
}
