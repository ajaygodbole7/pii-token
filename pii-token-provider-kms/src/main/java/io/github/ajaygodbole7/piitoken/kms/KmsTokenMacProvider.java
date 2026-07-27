package io.github.ajaygodbole7.piitoken.kms;

import io.github.ajaygodbole7.piitoken.provider.ProviderFailureReason;
import io.github.ajaygodbole7.piitoken.provider.TokenMacException;
import io.github.ajaygodbole7.piitoken.provider.TokenMacProvider;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.core.client.config.ClientOverrideConfiguration;
import software.amazon.awssdk.core.exception.ApiCallAttemptTimeoutException;
import software.amazon.awssdk.core.exception.ApiCallTimeoutException;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.retries.StandardRetryStrategy;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DependencyTimeoutException;
import software.amazon.awssdk.services.kms.model.DisabledException;
import software.amazon.awssdk.services.kms.model.GenerateMacRequest;
import software.amazon.awssdk.services.kms.model.GenerateMacResponse;
import software.amazon.awssdk.services.kms.model.InvalidArnException;
import software.amazon.awssdk.services.kms.model.InvalidGrantTokenException;
import software.amazon.awssdk.services.kms.model.InvalidKeyUsageException;
import software.amazon.awssdk.services.kms.model.KeyUnavailableException;
import software.amazon.awssdk.services.kms.model.KmsException;
import software.amazon.awssdk.services.kms.model.KmsInternalException;
import software.amazon.awssdk.services.kms.model.KmsInvalidStateException;
import software.amazon.awssdk.services.kms.model.MacAlgorithmSpec;
import software.amazon.awssdk.services.kms.model.NotFoundException;

import java.io.IOException;
import java.net.URI;
import java.time.Duration;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Pattern;

/**
 * AWS KMS implementation of the token MAC boundary.
 *
 * <p>Each logical version is pinned to one immutable KMS key ARN. The adapter
 * sends exactly the caller-supplied 32-byte digest to {@code GenerateMac} with
 * {@code HMAC_SHA_256}. It never resolves aliases and never hashes the digest
 * locally or through a second preprocessing step.
 */
public final class KmsTokenMacProvider implements TokenMacProvider {

    public static final String PROVIDER_ID = "aws-kms-hmac";

    private static final int SHA256_BYTES = 32;
    private static final Pattern LOGICAL_VERSION =
            Pattern.compile("[a-z][a-z0-9_-]{0,31}");
    private static final Pattern REGION =
            Pattern.compile("[a-z0-9][a-z0-9-]{1,30}[a-z0-9]");
    private static final Pattern KEY_ARN = Pattern.compile(
            "arn:[a-z0-9][a-z0-9-]{0,31}"
                    + ":kms:[a-z0-9-]{3,32}:[0-9]{12}:key/"
                    + "(?:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                    + "[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|mrk-[0-9a-fA-F]{32})");

    private final String keySetId;
    private final String currentVersion;
    private final Map<String, String> keyArns;
    private final Duration totalDeadline;
    private final Duration retryDelay;
    private final int maxAttempts;
    private final Semaphore concurrency;
    private final KmsClient kmsClient;
    private final boolean ownsKmsClient;
    private final Set<Thread> inFlight = ConcurrentHashMap.newKeySet();
    private final AtomicBoolean closed = new AtomicBoolean();

    /**
     * Creates a provider that owns a retry-disabled AWS KMS client.
     */
    public KmsTokenMacProvider(KmsHmacProperties properties) {
        this(properties, defaultClient(properties), true);
    }

    /**
     * Creates a provider around an application-owned client.
     *
     * <p>The caller must configure this client with SDK retries disabled. The
     * provider does not close an application-owned client.
     */
    public KmsTokenMacProvider(
            KmsHmacProperties properties,
            KmsClient kmsClient) {
        this(properties, retryDisabled(kmsClient), false);
    }

    KmsTokenMacProvider(
            KmsHmacProperties properties,
            KmsClient kmsClient,
            boolean ownsKmsClient) {
        Objects.requireNonNull(properties, "properties");
        Objects.requireNonNull(kmsClient, "kmsClient");

        this.keySetId = nonSecretIdentifier(properties.getKeySetId());
        this.currentVersion = logicalVersion(properties.getCurrentVersion());
        this.keyArns = validKeyArns(properties.getKeyArns());
        if (!keyArns.containsKey(currentVersion)) {
            throw invalidConfiguration();
        }
        this.totalDeadline = positive(properties.getTotalDeadline());
        this.retryDelay = nonNegative(properties.getRetryDelay());
        this.maxAttempts = bounded(properties.getMaxAttempts(), 1, 3);
        this.concurrency = new Semaphore(
                bounded(properties.getMaxConcurrency(), 1, 10_000),
                true);
        this.kmsClient = kmsClient;
        this.ownsKmsClient = ownsKmsClient;
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
        return keyArns.keySet();
    }

    @Override
    public Map<String, String> keyMappings() {
        return keyArns;
    }

    @Override
    public byte[] macDigest(String logicalVersion, byte[] sha256Digest) {
        if (logicalVersion == null
                || sha256Digest == null
                || sha256Digest.length != SHA256_BYTES) {
            throw failure(ProviderFailureReason.INVALID_INPUT);
        }
        String keyArn = keyArns.get(logicalVersion);
        if (keyArn == null) {
            throw failure(ProviderFailureReason.UNKNOWN_VERSION);
        }
        if (closed.get()) {
            throw failure(ProviderFailureReason.UNAVAILABLE);
        }

        long deadline = saturatedAdd(System.nanoTime(), totalDeadline.toNanos());
        byte[] digest = sha256Digest.clone();
        try {
            for (int attempt = 1; attempt <= maxAttempts; attempt++) {
                try {
                    return requestMac(keyArn, digest, deadline);
                }
                catch (AttemptFailure failure) {
                    if (attempt == maxAttempts || !failure.retryable()) {
                        throw failure(failure.reason());
                    }
                    waitBeforeRetry(deadline);
                }
            }
            throw failure(ProviderFailureReason.UNAVAILABLE);
        }
        finally {
            Arrays.fill(digest, (byte) 0);
        }
    }

    @Override
    public void close() {
        if (closed.compareAndSet(false, true)) {
            inFlight.forEach(Thread::interrupt);
            if (ownsKmsClient) {
                kmsClient.close();
            }
        }
    }

    private byte[] requestMac(
            String keyArn,
            byte[] sha256Digest,
            long deadline) {
        acquirePermit(deadline);
        byte[] requestDigest = sha256Digest.clone();
        var outcome = new CompletableFuture<byte[]>();
        Thread task = Thread.ofVirtual().unstarted(() -> {
            try {
                if (closed.get()) {
                    throw new AttemptFailure(
                            ProviderFailureReason.UNAVAILABLE,
                            false);
                }
                if (deadline - System.nanoTime() <= 0) {
                    throw new AttemptFailure(
                            ProviderFailureReason.DEADLINE,
                            false);
                }
                outcome.complete(invokeKms(keyArn, requestDigest));
            }
            catch (AttemptFailure failure) {
                outcome.completeExceptionally(failure);
            }
            catch (RuntimeException failure) {
                outcome.completeExceptionally(new AttemptFailure(
                        ProviderFailureReason.UNAVAILABLE,
                        true));
            }
            finally {
                Arrays.fill(requestDigest, (byte) 0);
                concurrency.release();
                inFlight.remove(Thread.currentThread());
            }
        });
        inFlight.add(task);
        try {
            task.start();
        }
        catch (RuntimeException failure) {
            inFlight.remove(task);
            Arrays.fill(requestDigest, (byte) 0);
            concurrency.release();
            throw new AttemptFailure(
                    ProviderFailureReason.UNAVAILABLE,
                    false);
        }

        try {
            long remainingNanos = deadline - System.nanoTime();
            if (remainingNanos <= 0) {
                task.interrupt();
                throw failure(ProviderFailureReason.DEADLINE);
            }
            return outcome.get(remainingNanos, TimeUnit.NANOSECONDS);
        }
        catch (TimeoutException exception) {
            task.interrupt();
            throw failure(ProviderFailureReason.DEADLINE);
        }
        catch (InterruptedException exception) {
            task.interrupt();
            Thread.currentThread().interrupt();
            throw failure(ProviderFailureReason.INTERRUPTED);
        }
        catch (ExecutionException exception) {
            Throwable cause = exception.getCause();
            if (cause instanceof AttemptFailure providerFailure) {
                throw providerFailure;
            }
            throw new AttemptFailure(
                    ProviderFailureReason.UNAVAILABLE,
                    true);
        }
    }

    private byte[] invokeKms(String keyArn, byte[] sha256Digest) {
        GenerateMacRequest request = GenerateMacRequest.builder()
                .keyId(keyArn)
                .macAlgorithm(MacAlgorithmSpec.HMAC_SHA_256)
                .message(SdkBytes.fromByteArray(sha256Digest))
                .build();
        try {
            GenerateMacResponse response = kmsClient.generateMac(request);
            if (response == null
                    || !keyArn.equals(response.keyId())
                    || response.macAlgorithm()
                    != MacAlgorithmSpec.HMAC_SHA_256
                    || response.mac() == null) {
                throw new AttemptFailure(
                        ProviderFailureReason.INVALID_RESPONSE,
                        false);
            }
            byte[] mac = response.mac().asByteArray();
            if (mac.length != SHA256_BYTES) {
                throw new AttemptFailure(
                        ProviderFailureReason.INVALID_RESPONSE,
                        false);
            }
            return mac;
        }
        catch (AttemptFailure failure) {
            throw failure;
        }
        catch (RuntimeException failure) {
            throw mapFailure(failure);
        }
    }

    private static AttemptFailure mapFailure(RuntimeException failure) {
        if (failure instanceof NotFoundException
                || failure instanceof KmsInvalidStateException
                || failure instanceof DisabledException
                || failure instanceof KeyUnavailableException) {
            return new AttemptFailure(
                    ProviderFailureReason.UNAVAILABLE,
                    false);
        }
        if (failure instanceof InvalidArnException
                || failure instanceof InvalidGrantTokenException
                || failure instanceof InvalidKeyUsageException) {
            return new AttemptFailure(
                    ProviderFailureReason.INVALID_INPUT,
                    false);
        }
        if (failure instanceof DependencyTimeoutException
                || failure instanceof ApiCallTimeoutException
                || failure instanceof ApiCallAttemptTimeoutException) {
            return new AttemptFailure(
                    ProviderFailureReason.DEADLINE,
                    false);
        }
        if (failure instanceof KmsInternalException) {
            return new AttemptFailure(
                    ProviderFailureReason.UNAVAILABLE,
                    true);
        }
        if (failure instanceof KmsException kmsFailure) {
            return mapKmsFailure(kmsFailure);
        }
        if (failure instanceof SdkClientException clientFailure) {
            if (hasCause(clientFailure, IOException.class)) {
                return new AttemptFailure(
                        ProviderFailureReason.UNAVAILABLE,
                        true);
            }
            return new AttemptFailure(
                    ProviderFailureReason.AUTH_FAILED,
                    false);
        }
        return new AttemptFailure(
                ProviderFailureReason.UNAVAILABLE,
                true);
    }

    private static AttemptFailure mapKmsFailure(KmsException failure) {
        String errorCode = failure.awsErrorDetails() == null
                ? null
                : failure.awsErrorDetails().errorCode();
        if ("ThrottlingException".equals(errorCode)) {
            return new AttemptFailure(
                    ProviderFailureReason.THROTTLED,
                    true);
        }
        if ("AccessDeniedException".equals(errorCode)
                || "UnrecognizedClientException".equals(errorCode)
                || "InvalidSignatureException".equals(errorCode)
                || "InvalidClientTokenId".equals(errorCode)
                || "ExpiredTokenException".equals(errorCode)) {
            return new AttemptFailure(
                    ProviderFailureReason.AUTH_FAILED,
                    false);
        }
        return mapStatus(failure.statusCode());
    }

    private static AttemptFailure mapStatus(int status) {
        return switch (status) {
            case 400 -> new AttemptFailure(
                    ProviderFailureReason.INVALID_INPUT,
                    false);
            case 401, 403 -> new AttemptFailure(
                    ProviderFailureReason.AUTH_FAILED,
                    false);
            case 408 -> new AttemptFailure(
                    ProviderFailureReason.DEADLINE,
                    false);
            case 429 -> new AttemptFailure(
                    ProviderFailureReason.THROTTLED,
                    true);
            default -> status >= 500
                    ? new AttemptFailure(
                            ProviderFailureReason.UNAVAILABLE,
                            true)
                    : new AttemptFailure(
                            ProviderFailureReason.INVALID_RESPONSE,
                            false);
        };
    }

    private void acquirePermit(long deadline) {
        try {
            long remainingNanos = deadline - System.nanoTime();
            if (remainingNanos <= 0
                    || !concurrency.tryAcquire(
                    remainingNanos,
                    TimeUnit.NANOSECONDS)) {
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
            remainingNanos(deadline);
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

    static KmsClient defaultClient(KmsHmacProperties properties) {
        String regionName = properties.getRegion();
        if (regionName == null || !REGION.matcher(regionName).matches()) {
            throw invalidConfiguration();
        }
        ClientOverrideConfiguration override =
                ClientOverrideConfiguration.builder()
                        .retryStrategy(StandardRetryStrategy.builder()
                                .maxAttempts(1)
                                .build())
                        .apiCallTimeout(positive(properties.getTotalDeadline()))
                        .apiCallAttemptTimeout(
                                positive(properties.getTotalDeadline()))
                        .build();
        var builder = KmsClient.builder()
                .region(Region.of(regionName))
                .overrideConfiguration(override);
        URI endpoint = validEndpoint(
                properties.getEndpointOverride(),
                properties.isAllowInsecureHttp());
        if (endpoint != null) {
            builder.endpointOverride(endpoint);
        }
        return builder.build();
    }

    private static KmsClient retryDisabled(KmsClient client) {
        Objects.requireNonNull(client, "kmsClient");
        try {
            var retryStrategy = client.serviceClientConfiguration()
                    .overrideConfiguration()
                    .retryStrategy()
                    .orElse(null);
            if (retryStrategy == null || retryStrategy.maxAttempts() != 1) {
                throw invalidConfiguration();
            }
        }
        catch (IllegalArgumentException failure) {
            throw failure;
        }
        catch (RuntimeException failure) {
            throw invalidConfiguration();
        }
        return client;
    }

    private static URI validEndpoint(URI endpoint, boolean allowInsecureHttp) {
        if (endpoint == null) {
            return null;
        }
        if (!endpoint.isAbsolute()
                || endpoint.getHost() == null
                || endpoint.getUserInfo() != null
                || endpoint.getQuery() != null
                || endpoint.getFragment() != null
                || !(endpoint.getPath().isEmpty()
                || endpoint.getPath().equals("/"))) {
            throw invalidConfiguration();
        }
        if (!endpoint.getScheme().equals("https")
                && !(allowInsecureHttp
                && endpoint.getScheme().equals("http"))) {
            throw invalidConfiguration();
        }
        return endpoint;
    }

    private static Map<String, String> validKeyArns(
            Map<String, String> configured) {
        if (configured == null
                || configured.isEmpty()
                || configured.size() > 4) {
            throw invalidConfiguration();
        }
        var copy = new LinkedHashMap<String, String>();
        for (Map.Entry<String, String> entry : configured.entrySet()) {
            String logical = logicalVersion(entry.getKey());
            String arn = entry.getValue();
            if (arn == null || !KEY_ARN.matcher(arn).matches()) {
                throw invalidConfiguration();
            }
            copy.put(logical, arn);
        }
        if (Set.copyOf(copy.values()).size() != copy.size()) {
            throw invalidConfiguration();
        }
        return Map.copyOf(copy);
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
                || value.chars().anyMatch(Character::isISOControl)) {
            throw invalidConfiguration();
        }
        return value;
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

    private static long remainingNanos(long deadline) {
        long nanos = deadline - System.nanoTime();
        if (nanos <= 0) {
            throw failure(ProviderFailureReason.DEADLINE);
        }
        return nanos;
    }

    private static long saturatedAdd(long left, long right) {
        long result = left + right;
        if (((left ^ result) & (right ^ result)) < 0) {
            return Long.MAX_VALUE;
        }
        return result;
    }

    private static boolean hasCause(
            Throwable failure,
            Class<? extends Throwable> type) {
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
        return new IllegalArgumentException("KMS_CONFIGURATION_INVALID");
    }

    private static TokenMacException failure(ProviderFailureReason reason) {
        return new TokenMacException(reason);
    }

    private static final class AttemptFailure extends RuntimeException {

        private final ProviderFailureReason reason;
        private final boolean retryable;

        private AttemptFailure(
                ProviderFailureReason reason,
                boolean retryable) {
            super(reason.name(), null, false, false);
            this.reason = reason;
            this.retryable = retryable;
        }

        private ProviderFailureReason reason() {
            return reason;
        }

        private boolean retryable() {
            return retryable;
        }
    }
}
