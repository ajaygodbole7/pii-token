package io.github.ajaygodbole7.piitoken.kms;

import io.github.ajaygodbole7.piitoken.provider.ProviderFailureReason;
import io.github.ajaygodbole7.piitoken.provider.TokenMacException;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.awscore.exception.AwsErrorDetails;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.core.exception.ApiCallTimeoutException;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DependencyTimeoutException;
import software.amazon.awssdk.services.kms.model.DisabledException;
import software.amazon.awssdk.services.kms.model.GenerateMacRequest;
import software.amazon.awssdk.services.kms.model.GenerateMacResponse;
import software.amazon.awssdk.services.kms.model.InvalidArnException;
import software.amazon.awssdk.services.kms.model.KeyUnavailableException;
import software.amazon.awssdk.services.kms.model.KmsException;
import software.amazon.awssdk.services.kms.model.KmsInternalException;
import software.amazon.awssdk.services.kms.model.KmsInvalidStateException;
import software.amazon.awssdk.services.kms.model.MacAlgorithmSpec;
import software.amazon.awssdk.services.kms.model.NotFoundException;

import java.io.IOException;
import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
class KmsTokenMacProviderTest {

    private static final String K1_ARN =
            "arn:aws:kms:us-east-1:123456789012:key/"
                    + "11111111-1111-1111-1111-111111111111";
    private static final String K2_ARN =
            "arn:aws:kms:us-east-1:123456789012:key/"
                    + "22222222-2222-2222-2222-222222222222";
    private static final byte[] MAC = fixedBytes(0x40);

    @Test
    void pinsTheKeyArnAndSendsExactlyTheCallerDigest() {
        var client = new StubKmsClient();
        byte[] digest = fixedBytes(0x10);
        byte[] original = digest.clone();
        client.onGenerateMac(ignored -> response(K1_ARN, MAC));

        try (var provider = provider(
                client,
                Map.of("k1", K1_ARN),
                "k1",
                2,
                Duration.ofSeconds(1),
                32)) {
            byte[] result = provider.macDigest("k1", digest);

            assertThat(result).containsExactly(MAC);
            assertThat(result).isNotSameAs(MAC);
            assertThat(digest).containsExactly(original);
            GenerateMacRequest request = client.requests().getFirst();
            assertThat(request.keyId()).isEqualTo(K1_ARN);
            assertThat(request.macAlgorithm())
                    .isEqualTo(MacAlgorithmSpec.HMAC_SHA_256);
            assertThat(request.message().asByteArray())
                    .containsExactly(digest);
            assertThat(provider.providerId())
                    .isEqualTo(KmsTokenMacProvider.PROVIDER_ID);
            assertThat(provider.keySetId()).isEqualTo("kms-test-key-set");
            assertThat(provider.currentVersion()).isEqualTo("k1");
            assertThat(provider.liveVersions()).containsExactly("k1");
            assertThat(provider.keyMappings())
                    .containsExactly(Map.entry("k1", K1_ARN));
        }
    }

    @Test
    void rejectsUnknownVersionsAndMalformedDigestsBeforeCallingKms() {
        var client = new StubKmsClient();
        try (var provider = provider(
                client,
                Map.of("k1", K1_ARN),
                "k1",
                1,
                Duration.ofSeconds(1),
                32)) {
            assertReason(
                    ProviderFailureReason.UNKNOWN_VERSION,
                    () -> provider.macDigest("k2", new byte[32]));
            assertReason(
                    ProviderFailureReason.INVALID_INPUT,
                    () -> provider.macDigest("k1", new byte[31]));
            assertReason(
                    ProviderFailureReason.INVALID_INPUT,
                    () -> provider.macDigest(null, new byte[32]));
            assertReason(
                    ProviderFailureReason.INVALID_INPUT,
                    () -> provider.macDigest("k1", null));
        }

        assertThat(client.callCount()).isZero();
    }

    @Test
    void rejectsAliasesDuplicateKeysMissingCurrentAndInvalidEndpoints() {
        KmsHmacProperties aliasProperties = properties(
                Map.of("k1", K1_ARN),
                "k1",
                1,
                Duration.ofSeconds(1),
                32);
        aliasProperties.setKeyArns(Map.of(
                "k1",
                "arn:aws:kms:us-east-1:123456789012:alias/pii-token"));
        assertInvalidConfiguration(() ->
                new KmsTokenMacProvider(
                        aliasProperties,
                        new StubKmsClient()));

        KmsHmacProperties duplicateProperties = properties(
                Map.of("k1", K1_ARN, "k2", K1_ARN),
                "k1",
                1,
                Duration.ofSeconds(1),
                32);
        assertInvalidConfiguration(() ->
                new KmsTokenMacProvider(
                        duplicateProperties,
                        new StubKmsClient()));

        KmsHmacProperties missingCurrentProperties = properties(
                Map.of("k1", K1_ARN),
                "k2",
                1,
                Duration.ofSeconds(1),
                32);
        assertInvalidConfiguration(() ->
                new KmsTokenMacProvider(
                        missingCurrentProperties,
                        new StubKmsClient()));

        KmsHmacProperties insecure = properties(
                Map.of("k1", K1_ARN),
                "k1",
                1,
                Duration.ofSeconds(1),
                32);
        insecure.setEndpointOverride(URI.create("http://127.0.0.1:4566"));
        assertInvalidConfiguration(() -> new KmsTokenMacProvider(insecure));

        KmsHmacProperties retryProperties = properties(
                Map.of("k1", K1_ARN),
                "k1",
                1,
                Duration.ofSeconds(1),
                32);
        assertInvalidConfiguration(() -> new KmsTokenMacProvider(
                retryProperties,
                new StubKmsClient(3)));
    }

    @Test
    void ownedClientDisablesSdkRetries() {
        KmsHmacProperties properties = properties(
                Map.of("k1", K1_ARN),
                "k1",
                1,
                Duration.ofSeconds(1),
                32);

        try (KmsClient client = KmsTokenMacProvider.defaultClient(properties)) {
            assertThat(client.serviceClientConfiguration()
                    .overrideConfiguration()
                    .retryStrategy()
                    .orElseThrow()
                    .maxAttempts()).isOne();
        }
    }

    @Test
    void rejectsWrongKeyIdAndNonSha256MacResponses() {
        var client = new StubKmsClient();
        var responses = List.of(
                response(K2_ARN, MAC),
                response(K1_ARN, new byte[31]),
                GenerateMacResponse.builder()
                        .keyId(K1_ARN)
                        .build(),
                GenerateMacResponse.builder()
                        .keyId(K1_ARN)
                        .macAlgorithm(MacAlgorithmSpec.HMAC_SHA_512)
                        .mac(SdkBytes.fromByteArray(MAC))
                        .build());
        var next = new AtomicInteger();
        client.onGenerateMac(ignored -> responses.get(next.getAndIncrement()));

        try (var provider = provider(
                client,
                Map.of("k1", K1_ARN),
                "k1",
                1,
                Duration.ofSeconds(1),
                32)) {
            assertReason(
                    ProviderFailureReason.INVALID_RESPONSE,
                    () -> provider.macDigest("k1", new byte[32]));
            assertReason(
                    ProviderFailureReason.INVALID_RESPONSE,
                    () -> provider.macDigest("k1", new byte[32]));
            assertReason(
                    ProviderFailureReason.INVALID_RESPONSE,
                    () -> provider.macDigest("k1", new byte[32]));
            assertReason(
                    ProviderFailureReason.INVALID_RESPONSE,
                    () -> provider.macDigest("k1", new byte[32]));
        }
    }

    @Test
    void mapsSdkFailuresToContentFreeReasons() {
        List<FailureCase> cases = List.of(
                new FailureCase(
                        NotFoundException.builder()
                                .message("key and account must not escape")
                                .statusCode(400)
                                .build(),
                        ProviderFailureReason.UNAVAILABLE),
                new FailureCase(
                        DisabledException.builder()
                                .message("key and account must not escape")
                                .statusCode(400)
                                .build(),
                        ProviderFailureReason.UNAVAILABLE),
                new FailureCase(
                        KmsInvalidStateException.builder()
                                .message("key and account must not escape")
                                .statusCode(400)
                                .build(),
                        ProviderFailureReason.UNAVAILABLE),
                new FailureCase(
                        KeyUnavailableException.builder()
                                .message("key and account must not escape")
                                .statusCode(500)
                                .build(),
                        ProviderFailureReason.UNAVAILABLE),
                new FailureCase(
                        kmsFailure("ThrottlingException", 400),
                        ProviderFailureReason.THROTTLED),
                new FailureCase(
                        kmsFailure("AccessDeniedException", 400),
                        ProviderFailureReason.AUTH_FAILED),
                new FailureCase(
                        InvalidArnException.builder()
                                .message("key and account must not escape")
                                .statusCode(400)
                                .build(),
                        ProviderFailureReason.INVALID_INPUT),
                new FailureCase(
                        DependencyTimeoutException.builder()
                                .message("key and account must not escape")
                                .statusCode(500)
                                .build(),
                        ProviderFailureReason.DEADLINE),
                new FailureCase(
                        ApiCallTimeoutException.create(1),
                        ProviderFailureReason.DEADLINE),
                new FailureCase(
                        KmsInternalException.builder()
                                .message("key and account must not escape")
                                .statusCode(500)
                                .build(),
                        ProviderFailureReason.UNAVAILABLE),
                new FailureCase(
                        SdkClientException.builder()
                                .message("credentials must not escape")
                                .build(),
                        ProviderFailureReason.AUTH_FAILED),
                new FailureCase(
                        SdkClientException.builder()
                                .message("network details must not escape")
                                .cause(new IOException("host must not escape"))
                                .build(),
                        ProviderFailureReason.UNAVAILABLE),
                new FailureCase(
                        kmsFailure("UnexpectedException", 418),
                        ProviderFailureReason.INVALID_RESPONSE));

        for (FailureCase failureCase : cases) {
            var client = new StubKmsClient();
            client.onGenerateMac(ignored -> {
                throw failureCase.failure();
            });
            try (var provider = provider(
                    client,
                    Map.of("k1", K1_ARN),
                    "k1",
                    1,
                    Duration.ofSeconds(1),
                    32)) {
                assertReason(
                        failureCase.reason(),
                        () -> provider.macDigest("k1", new byte[32]));
            }
        }
    }

    @Test
    void retriesOneTransientFailureAndUsesOnlyTheAdapterRetryLayer() {
        var client = new StubKmsClient();
        var calls = new AtomicInteger();
        client.onGenerateMac(ignored -> {
            if (calls.getAndIncrement() == 0) {
                throw kmsFailure("ThrottlingException", 400);
            }
            return response(K1_ARN, MAC);
        });

        try (var provider = provider(
                client,
                Map.of("k1", K1_ARN),
                "k1",
                2,
                Duration.ofSeconds(1),
                32)) {
            assertThat(provider.macDigest("k1", new byte[32]))
                    .containsExactly(MAC);
        }

        assertThat(client.callCount()).isEqualTo(2);
    }

    @Test
    void doesNotRetryPermanentKeyStateFailures() {
        var client = new StubKmsClient();
        client.onGenerateMac(ignored -> {
            throw DisabledException.builder()
                    .message("must not escape")
                    .statusCode(400)
                    .build();
        });

        try (var provider = provider(
                client,
                Map.of("k1", K1_ARN),
                "k1",
                2,
                Duration.ofSeconds(1),
                32)) {
            assertReason(
                    ProviderFailureReason.UNAVAILABLE,
                    () -> provider.macDigest("k1", new byte[32]));
        }

        assertThat(client.callCount()).isOne();
    }

    @Test
    void enforcesOneTotalDeadlineAcrossTheCall() {
        var client = new StubKmsClient();
        client.onGenerateMac(ignored -> {
            try {
                Thread.sleep(500);
            }
            catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
            }
            return response(K1_ARN, MAC);
        });

        try (var provider = provider(
                client,
                Map.of("k1", K1_ARN),
                "k1",
                2,
                Duration.ofMillis(50),
                32)) {
            assertReason(
                    ProviderFailureReason.DEADLINE,
                    () -> provider.macDigest("k1", new byte[32]));
        }
    }

    @RepeatedTest(3)
    void boundsConcurrentCallsAndExpiresQueuedCallers() throws Exception {
        var client = new StubKmsClient();
        var active = new AtomicInteger();
        var maximumActive = new AtomicInteger();
        var callsFinished = new CountDownLatch(2);
        client.onGenerateMac(ignored -> {
            int current = active.incrementAndGet();
            maximumActive.accumulateAndGet(current, Math::max);
            try {
                long finish = System.nanoTime()
                        + Duration.ofMillis(150).toNanos();
                while (true) {
                    long remaining = finish - System.nanoTime();
                    if (remaining <= 0) {
                        break;
                    }
                    try {
                        TimeUnit.NANOSECONDS.sleep(remaining);
                    }
                    catch (InterruptedException ignoredInterrupt) {
                        // Model an SDK call that does not stop immediately.
                    }
                }
            }
            finally {
                active.decrementAndGet();
                callsFinished.countDown();
            }
            return response(K1_ARN, MAC);
        });

        try (var provider = provider(
                client,
                Map.of("k1", K1_ARN),
                "k1",
                1,
                Duration.ofMillis(75),
                2);
             var callers = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Future<ProviderFailureReason>> results = IntStream.range(0, 8)
                    .mapToObj(ignored -> callers.submit(() -> {
                        try {
                            provider.macDigest("k1", new byte[32]);
                            throw new AssertionError("expected deadline");
                        }
                        catch (TokenMacException failure) {
                            return failure.reason();
                        }
                    }))
                    .toList();

            assertThat(results)
                    .extracting(Future::get)
                    .containsOnly(ProviderFailureReason.DEADLINE);
        }

        assertThat(maximumActive).hasValueLessThanOrEqualTo(2);
        assertThat(client.callCount()).isEqualTo(2);
        assertThat(callsFinished.await(1, TimeUnit.SECONDS)).isTrue();
    }

    @Test
    void interruptionIsDistinctAndReassertsTheCallerInterruptFlag()
            throws Exception {
        var client = new StubKmsClient();
        var entered = new CountDownLatch(1);
        var release = new CountDownLatch(1);
        client.onGenerateMac(ignored -> {
            entered.countDown();
            try {
                release.await();
            }
            catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
            }
            return response(K1_ARN, MAC);
        });
        var reason = new AtomicReference<ProviderFailureReason>();
        var interrupted = new AtomicBoolean();

        try (var provider = provider(
                client,
                Map.of("k1", K1_ARN),
                "k1",
                1,
                Duration.ofSeconds(5),
                1)) {
            Thread caller = Thread.ofVirtual().start(() -> {
                try {
                    provider.macDigest("k1", new byte[32]);
                }
                catch (TokenMacException failure) {
                    reason.set(failure.reason());
                    interrupted.set(Thread.currentThread().isInterrupted());
                }
            });
            assertThat(entered.await(1, TimeUnit.SECONDS)).isTrue();
            caller.interrupt();
            caller.join(Duration.ofSeconds(1));
            release.countDown();
        }

        assertThat(reason).hasValue(ProviderFailureReason.INTERRUPTED);
        assertThat(interrupted).isTrue();
    }

    @Test
    void closesOnlyAnOwnedClientAndRejectsCallsAfterClose() {
        var owned = new StubKmsClient();
        KmsHmacProperties properties = properties(
                Map.of("k1", K1_ARN),
                "k1",
                1,
                Duration.ofSeconds(1),
                32);
        var ownedProvider = new KmsTokenMacProvider(properties, owned, true);
        ownedProvider.close();
        ownedProvider.close();
        assertThat(owned.closeCount()).isOne();
        assertReason(
                ProviderFailureReason.UNAVAILABLE,
                () -> ownedProvider.macDigest("k1", new byte[32]));

        var callerOwned = new StubKmsClient();
        var callerProvider = new KmsTokenMacProvider(properties, callerOwned);
        callerProvider.close();
        assertThat(callerOwned.closeCount()).isZero();
    }

    private static KmsTokenMacProvider provider(
            KmsClient client,
            Map<String, String> keyArns,
            String current,
            int maxAttempts,
            Duration deadline,
            int maxConcurrency) {
        return new KmsTokenMacProvider(
                properties(
                        keyArns,
                        current,
                        maxAttempts,
                        deadline,
                        maxConcurrency),
                client);
    }

    private static KmsHmacProperties properties(
            Map<String, String> keyArns,
            String current,
            int maxAttempts,
            Duration deadline,
            int maxConcurrency) {
        var properties = new KmsHmacProperties();
        properties.setRegion("us-east-1");
        properties.setKeySetId("kms-test-key-set");
        properties.setCurrentVersion(current);
        properties.setKeyArns(keyArns);
        properties.setMaxAttempts(maxAttempts);
        properties.setTotalDeadline(deadline);
        properties.setMaxConcurrency(maxConcurrency);
        properties.setRetryDelay(Duration.ZERO);
        return properties;
    }

    private static GenerateMacResponse response(String keyArn, byte[] mac) {
        return GenerateMacResponse.builder()
                .keyId(keyArn)
                .macAlgorithm(MacAlgorithmSpec.HMAC_SHA_256)
                .mac(SdkBytes.fromByteArray(mac))
                .build();
    }

    private static KmsException kmsFailure(String code, int status) {
        KmsException.Builder builder = KmsException.builder();
        builder.message("provider text must not escape");
        builder.statusCode(status);
        builder.awsErrorDetails(AwsErrorDetails.builder()
                .errorCode(code)
                .errorMessage("provider text must not escape")
                .build());
        return (KmsException) builder.build();
    }

    private static byte[] fixedBytes(int start) {
        byte[] value = new byte[32];
        for (int index = 0; index < value.length; index++) {
            value[index] = (byte) (start + index);
        }
        return value;
    }

    private static void assertReason(
            ProviderFailureReason expected,
            Runnable operation) {
        assertThatThrownBy(operation::run)
                .isInstanceOfSatisfying(
                        TokenMacException.class,
                        failure -> assertThat(failure.reason())
                                .isEqualTo(expected))
                .hasMessage(expected.name())
                .hasNoCause();
    }

    private static void assertInvalidConfiguration(Runnable operation) {
        assertThatThrownBy(operation::run)
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("KMS_CONFIGURATION_INVALID")
                .hasNoCause();
    }

    private record FailureCase(
            RuntimeException failure,
            ProviderFailureReason reason) {
    }
}
