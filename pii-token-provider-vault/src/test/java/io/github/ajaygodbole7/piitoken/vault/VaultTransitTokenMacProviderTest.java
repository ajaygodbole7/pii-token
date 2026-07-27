package io.github.ajaygodbole7.piitoken.vault;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import io.github.ajaygodbole7.piitoken.provider.ProviderFailureReason;
import io.github.ajaygodbole7.piitoken.provider.TokenMacException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class VaultTransitTokenMacProviderTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final byte[] MAC = new byte[32];

    private HttpServer server;
    private ExecutorService serverExecutor;

    @AfterEach
    void stopServer() {
        if (server != null) {
            server.stop(0);
        }
        if (serverExecutor != null) {
            serverExecutor.close();
        }
    }

    @Test
    void pinsTheNumericVersionAndSendsExactlyTheCallerDigest() throws Exception {
        byte[] digest = new byte[32];
        for (int index = 0; index < digest.length; index++) {
            digest[index] = (byte) index;
            MAC[index] = (byte) (31 - index);
        }
        byte[] originalDigest = digest.clone();
        var calls = new AtomicInteger();
        start(exchange -> {
            calls.incrementAndGet();
            assertThat(exchange.getRequestURI().getPath())
                    .isEqualTo("/v1/transit/hmac/pii-token/sha2-256");
            assertThat(exchange.getRequestHeaders().getFirst("X-Vault-Token"))
                    .isEqualTo("runtime-token");
            JsonNode body = JSON.readTree(exchange.getRequestBody());
            assertThat(body.path("key_version").intValue()).isEqualTo(1);
            assertThat(Base64.getDecoder().decode(body.path("input").textValue()))
                    .containsExactly(digest);
            respond(exchange, 200, hmacResponse(1, MAC));
        });
        var provider = provider(Map.of("k1", 1), "k1", 2, Duration.ofSeconds(1));

        byte[] result = provider.macDigest("k1", digest);

        assertThat(result).containsExactly(MAC);
        assertThat(digest).containsExactly(originalDigest);
        assertThat(calls).hasValue(1);
        assertThat(provider.keyMappings()).containsExactly(
                Map.entry("k1", "vault-transit:transit:pii-token:v1"));
    }

    @Test
    void rejectsUnknownVersionsAndInvalidDigestsBeforeNetworkAccess() throws Exception {
        var calls = new AtomicInteger();
        start(exchange -> {
            calls.incrementAndGet();
            respond(exchange, 500, "");
        });
        var provider = provider(Map.of("k1", 1), "k1", 1, Duration.ofSeconds(1));

        assertReason(ProviderFailureReason.UNKNOWN_VERSION,
                () -> provider.macDigest("k2", new byte[32]));
        assertReason(ProviderFailureReason.INVALID_INPUT,
                () -> provider.macDigest("k1", new byte[31]));
        assertReason(ProviderFailureReason.INVALID_INPUT,
                () -> provider.macDigest(null, new byte[32]));

        assertThat(calls).hasValue(0);
    }

    @Test
    void rejectsWrongVersionAndNonSha256Response() throws Exception {
        var calls = new AtomicInteger();
        start(exchange -> {
            int call = calls.incrementAndGet();
            respond(exchange, 200, call == 1
                    ? hmacResponse(2, new byte[32])
                    : hmacResponse(1, new byte[31]));
        });
        var provider = provider(Map.of("k1", 1), "k1", 1, Duration.ofSeconds(1));

        assertReason(ProviderFailureReason.INVALID_RESPONSE,
                () -> provider.macDigest("k1", new byte[32]));
        assertReason(ProviderFailureReason.INVALID_RESPONSE,
                () -> provider.macDigest("k1", new byte[32]));
    }

    @Test
    void rejectsAnOversizedSuccessResponse() throws Exception {
        start(exchange -> respond(exchange, 200, "x".repeat(4097)));
        var provider = provider(Map.of("k1", 1), "k1", 1, Duration.ofSeconds(1));

        assertReason(ProviderFailureReason.INVALID_RESPONSE,
                () -> provider.macDigest("k1", new byte[32]));
    }

    @Test
    void retriesOnlyTheBoundedTransientFailure() throws Exception {
        var calls = new AtomicInteger();
        start(exchange -> {
            if (calls.incrementAndGet() == 1) {
                respond(exchange, 429, "{\"errors\":[\"sensitive backend text\"]}");
            }
            else {
                respond(exchange, 200, hmacResponse(1, MAC));
            }
        });
        var provider = provider(Map.of("k1", 1), "k1", 2, Duration.ofSeconds(1));

        assertThat(provider.macDigest("k1", new byte[32])).containsExactly(MAC);
        assertThat(calls).hasValue(2);
    }

    @Test
    void mapsHttpFailuresToContentFreeReasonsWithoutRetryingPermanentFailures()
            throws Exception {
        int[] statuses = {400, 401, 403, 404};
        ProviderFailureReason[] reasons = {
            ProviderFailureReason.INVALID_INPUT,
            ProviderFailureReason.AUTH_FAILED,
            ProviderFailureReason.AUTH_FAILED,
            ProviderFailureReason.INVALID_RESPONSE
        };
        var next = new AtomicInteger();
        start(exchange -> respond(
                exchange,
                statuses[next.getAndIncrement()],
                "{\"errors\":[\"must not escape\"]}"));
        var provider = provider(Map.of("k1", 1), "k1", 2, Duration.ofSeconds(1));

        for (ProviderFailureReason reason : reasons) {
            assertThatThrownBy(() -> provider.macDigest("k1", new byte[32]))
                    .isInstanceOf(TokenMacException.class)
                    .hasMessage(reason.name())
                    .hasNoCause();
        }
        assertThat(next).hasValue(statuses.length);
    }

    @Test
    void enforcesOneTotalDeadlineAcrossTheCall() throws Exception {
        start(exchange -> {
            try {
                Thread.sleep(250);
                respond(exchange, 200, hmacResponse(1, MAC));
            }
            catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
            }
            catch (IOException ignored) {
                // The deadline can close the client side first.
            }
        });
        var provider = provider(
                Map.of("k1", 1),
                "k1",
                2,
                Duration.ofMillis(75));

        assertReason(ProviderFailureReason.DEADLINE,
                () -> provider.macDigest("k1", new byte[32]));
    }

    @Test
    void boundsConcurrentRequestsAndExpiresQueuedCallersAtTheTotalDeadline()
            throws Exception {
        var active = new AtomicInteger();
        var maximumActive = new AtomicInteger();
        var requests = new AtomicInteger();
        start(exchange -> {
            requests.incrementAndGet();
            int current = active.incrementAndGet();
            maximumActive.accumulateAndGet(current, Math::max);
            try {
                Thread.sleep(250);
                respond(exchange, 200, hmacResponse(1, MAC));
            }
            catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
            }
            catch (IOException ignored) {
                // The total deadline closes the client side first.
            }
            finally {
                active.decrementAndGet();
            }
        });
        VaultTransitProperties properties = baseProperties(
                Map.of("k1", 1),
                "k1",
                1,
                Duration.ofMillis(75));
        properties.setAddress(java.net.URI.create(
                "http://127.0.0.1:" + server.getAddress().getPort()));
        properties.setAllowInsecureHttp(true);
        properties.setMaxConcurrency(2);

        try (var provider = new VaultTransitTokenMacProvider(
                properties,
                () -> "runtime-token");
             var callers = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Future<ProviderFailureReason>> results = IntStream.range(0, 8)
                    .mapToObj(ignored -> callers.submit(() -> {
                        try {
                            provider.macDigest("k1", new byte[32]);
                            throw new AssertionError("expected deadline");
                        }
                        catch (TokenMacException exception) {
                            return exception.reason();
                        }
                    }))
                    .toList();

            assertThat(results)
                    .extracting(Future::get)
                    .containsOnly(ProviderFailureReason.DEADLINE);
        }

        assertThat(maximumActive).hasValueLessThanOrEqualTo(2);
        assertThat(requests).hasValueLessThanOrEqualTo(2);
    }

    @Test
    void rejectsInsecureHttpUnlessItIsExplicitlyEnabledForTests() {
        VaultTransitProperties properties = baseProperties(
                Map.of("k1", 1),
                "k1",
                1,
                Duration.ofSeconds(1));
        properties.setAddress(java.net.URI.create("http://127.0.0.1:8200"));

        assertThatThrownBy(() ->
                new VaultTransitTokenMacProvider(properties, () -> "token"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("VAULT_CONFIGURATION_INVALID");
    }

    @Test
    void convertsTokenSupplierFailuresToContentFreeAuthFailure() {
        VaultTransitProperties properties = baseProperties(
                Map.of("k1", 1),
                "k1",
                1,
                Duration.ofSeconds(1));
        properties.setAddress(java.net.URI.create("https://vault.example.test"));
        var provider = new VaultTransitTokenMacProvider(
                properties,
                () -> {
                    throw new IllegalStateException("credential detail");
                });

        assertThatThrownBy(() -> provider.macDigest("k1", new byte[32]))
                .isInstanceOf(TokenMacException.class)
                .hasMessage(ProviderFailureReason.AUTH_FAILED.name())
                .hasNoCause();
    }

    @Test
    void closesOnlyTheHttpClientItOwns() throws Exception {
        VaultTransitProperties properties = baseProperties(
                Map.of("k1", 1),
                "k1",
                1,
                Duration.ofSeconds(1));
        properties.setAddress(java.net.URI.create("https://vault.example.test"));

        var ownedProvider = new VaultTransitTokenMacProvider(
                properties,
                () -> "runtime-token");
        HttpClient ownedClient = providerHttpClient(ownedProvider);
        assertThat(ownedClient.isTerminated()).isFalse();

        ownedProvider.close();
        ownedProvider.close();

        assertThat(ownedClient.isTerminated()).isTrue();

        HttpClient suppliedClient = HttpClient.newHttpClient();
        try {
            var suppliedProvider = new VaultTransitTokenMacProvider(
                    properties,
                    () -> "runtime-token",
                    suppliedClient);

            suppliedProvider.close();

            assertThat(suppliedClient.isTerminated()).isFalse();
        }
        finally {
            suppliedClient.close();
        }
    }

    @Test
    void mapsAndReassertsCallerInterruptionSeparatelyFromDeadline() {
        VaultTransitProperties properties = baseProperties(
                Map.of("k1", 1),
                "k1",
                1,
                Duration.ofSeconds(1));
        properties.setAddress(java.net.URI.create("https://vault.example.test"));
        var provider = new VaultTransitTokenMacProvider(
                properties,
                () -> "runtime-token");
        try {
            Thread.currentThread().interrupt();

            assertReason(
                    ProviderFailureReason.INTERRUPTED,
                    () -> provider.macDigest("k1", new byte[32]));
            assertThat(Thread.currentThread().isInterrupted()).isTrue();
        }
        finally {
            Thread.interrupted();
            provider.close();
        }
    }

    private VaultTransitTokenMacProvider provider(
            Map<String, Integer> versions,
            String currentVersion,
            int maxAttempts,
            Duration deadline) {
        VaultTransitProperties properties =
                baseProperties(versions, currentVersion, maxAttempts, deadline);
        properties.setAddress(java.net.URI.create(
                "http://127.0.0.1:" + server.getAddress().getPort()));
        properties.setAllowInsecureHttp(true);
        return new VaultTransitTokenMacProvider(properties, () -> "runtime-token");
    }

    private static VaultTransitProperties baseProperties(
            Map<String, Integer> versions,
            String currentVersion,
            int maxAttempts,
            Duration deadline) {
        var properties = new VaultTransitProperties();
        properties.setKeyName("pii-token");
        properties.setKeySetId("test-key-set");
        properties.setCurrentVersion(currentVersion);
        properties.setVersions(versions);
        properties.setMaxAttempts(maxAttempts);
        properties.setRetryDelay(Duration.ZERO);
        properties.setTotalDeadline(deadline);
        return properties;
    }

    private static HttpClient providerHttpClient(
            VaultTransitTokenMacProvider provider) throws Exception {
        var field = VaultTransitTokenMacProvider.class.getDeclaredField("httpClient");
        field.setAccessible(true);
        return (HttpClient) field.get(provider);
    }

    private void start(ThrowingHandler handler) throws IOException {
        server = HttpServer.create(
                new InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0),
                0);
        server.createContext("/", exchange -> {
            try {
                handler.handle(exchange);
            }
            finally {
                exchange.close();
            }
        });
        serverExecutor = Executors.newVirtualThreadPerTaskExecutor();
        server.setExecutor(serverExecutor);
        server.start();
    }

    private static String hmacResponse(int version, byte[] mac) {
        return "{\"data\":{\"hmac\":\"vault:v"
                + version
                + ":"
                + Base64.getEncoder().encodeToString(mac)
                + "\"}}";
    }

    private static void respond(HttpExchange exchange, int status, String body)
            throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
    }

    private static void assertReason(
            ProviderFailureReason reason,
            Runnable operation) {
        assertThatThrownBy(operation::run)
                .isInstanceOf(TokenMacException.class)
                .extracting(throwable -> ((TokenMacException) throwable).reason())
                .isEqualTo(reason);
    }

    @FunctionalInterface
    private interface ThrowingHandler {
        void handle(HttpExchange exchange) throws IOException;
    }
}
