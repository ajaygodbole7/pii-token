package io.github.ajaygodbole7.piitoken.kms;

import software.amazon.awssdk.core.client.config.ClientOverrideConfiguration;
import software.amazon.awssdk.retries.StandardRetryStrategy;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.KmsServiceClientConfiguration;
import software.amazon.awssdk.services.kms.model.GenerateMacRequest;
import software.amazon.awssdk.services.kms.model.GenerateMacResponse;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;

final class StubKmsClient implements KmsClient {

    private final List<GenerateMacRequest> requests =
            new CopyOnWriteArrayList<>();
    private final AtomicInteger closeCalls = new AtomicInteger();
    private final KmsServiceClientConfiguration configuration;
    private volatile Function<GenerateMacRequest, GenerateMacResponse> handler =
            ignored -> {
                throw new AssertionError("unexpected KMS call");
            };

    StubKmsClient() {
        this(1);
    }

    StubKmsClient(int sdkMaxAttempts) {
        this.configuration = KmsServiceClientConfiguration.builder()
                .overrideConfiguration(ClientOverrideConfiguration.builder()
                        .retryStrategy(StandardRetryStrategy.builder()
                                .maxAttempts(sdkMaxAttempts)
                                .build())
                        .build())
                .build();
    }

    void onGenerateMac(
            Function<GenerateMacRequest, GenerateMacResponse> handler) {
        this.handler = handler;
    }

    int callCount() {
        return requests.size();
    }

    List<GenerateMacRequest> requests() {
        return List.copyOf(requests);
    }

    int closeCount() {
        return closeCalls.get();
    }

    @Override
    public GenerateMacResponse generateMac(GenerateMacRequest request) {
        requests.add(request);
        return handler.apply(request);
    }

    @Override
    public String serviceName() {
        return "kms";
    }

    @Override
    public KmsServiceClientConfiguration serviceClientConfiguration() {
        return configuration;
    }

    @Override
    public void close() {
        closeCalls.incrementAndGet();
    }
}
