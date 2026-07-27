package io.github.ajaygodbole7.piitoken.kms;

import io.github.ajaygodbole7.piitoken.provider.TokenMacProvider;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import software.amazon.awssdk.services.kms.KmsClient;

import static org.assertj.core.api.Assertions.assertThat;

class KmsTokenMacAutoConfigurationTest {

    private static final String KEY_ARN =
            "arn:aws:kms:us-east-1:123456789012:key/"
                    + "11111111-1111-1111-1111-111111111111";

    private final ApplicationContextRunner runner =
            new ApplicationContextRunner()
                    .withConfiguration(AutoConfigurations.of(
                            KmsTokenMacAutoConfiguration.class));

    @Test
    void staysInactiveUnlessExplicitlyEnabled() {
        runner.run(context -> assertThat(context)
                .doesNotHaveBean(TokenMacProvider.class));
    }

    @Test
    void leavesAnApplicationOwnedClientOpenUntilTheContextClosesIt() {
        var client = new StubKmsClient();
        runner.withBean(KmsClient.class, () -> client)
                .withPropertyValues(validProperties())
                .run(context -> {
                    assertThat(context).hasSingleBean(TokenMacProvider.class);
                    assertThat(context.getBean(TokenMacProvider.class))
                            .isInstanceOf(KmsTokenMacProvider.class);
                    assertThat(client.closeCount()).isZero();
                });
        assertThat(client.closeCount()).isOne();
    }

    @Test
    void createsAndClosesAnOwnedRetryDisabledClient() {
        runner.withPropertyValues(validProperties())
                .run(context -> {
                    assertThat(context).hasSingleBean(TokenMacProvider.class);
                    assertThat(context.getBean(TokenMacProvider.class))
                            .isInstanceOf(KmsTokenMacProvider.class);
                });
    }

    @Test
    void backsOffWhenAnotherProviderAlreadyExists() {
        TokenMacProvider existing = new KmsTokenMacProvider(
                validKmsProperties(),
                new StubKmsClient());
        runner.withBean(TokenMacProvider.class, () -> existing)
                .withBean(KmsClient.class, StubKmsClient::new)
                .withPropertyValues(validProperties())
                .run(context -> assertThat(context)
                        .hasSingleBean(TokenMacProvider.class)
                        .getBean(TokenMacProvider.class)
                        .isSameAs(existing));
    }

    @Test
    void failsClosedForInvalidOrAmbiguousConfiguration() {
        runner.withBean(KmsClient.class, StubKmsClient::new)
                .withPropertyValues(
                        "pii.kms.enabled=true",
                        "pii.kms.region=us-east-1",
                        "pii.kms.key-set-id=test-key-set",
                        "pii.kms.current-version=k2",
                        "pii.kms.key-arns.k1=" + KEY_ARN)
                .run(context -> assertThat(context).hasFailed());

        runner.withPropertyValues(
                        "pii.kms.enabled=true",
                        "pii.kms.key-set-id=test-key-set",
                        "pii.kms.current-version=k1",
                        "pii.kms.key-arns.k1=" + KEY_ARN)
                .run(context -> assertThat(context).hasFailed());

        runner.withBean("firstKmsClient", KmsClient.class,
                        StubKmsClient::new)
                .withBean("secondKmsClient", KmsClient.class,
                        StubKmsClient::new)
                .withPropertyValues(validProperties())
                .run(context -> assertThat(context).hasFailed());
    }

    private static String[] validProperties() {
        return new String[] {
            "pii.kms.enabled=true",
            "pii.kms.region=us-east-1",
            "pii.kms.key-set-id=test-key-set",
            "pii.kms.current-version=k1",
            "pii.kms.key-arns.k1=" + KEY_ARN
        };
    }

    private static KmsHmacProperties validKmsProperties() {
        var properties = new KmsHmacProperties();
        properties.setRegion("us-east-1");
        properties.setKeySetId("test-key-set");
        properties.setCurrentVersion("k1");
        properties.setKeyArns(java.util.Map.of("k1", KEY_ARN));
        return properties;
    }
}
