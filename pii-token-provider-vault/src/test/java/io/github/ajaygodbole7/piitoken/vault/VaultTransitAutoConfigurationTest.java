package io.github.ajaygodbole7.piitoken.vault;

import io.github.ajaygodbole7.piitoken.provider.TokenMacProvider;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

class VaultTransitAutoConfigurationTest {

    private final ApplicationContextRunner contextRunner =
            new ApplicationContextRunner()
                    .withConfiguration(AutoConfigurations.of(
                            VaultTransitAutoConfiguration.class))
                    .withBean(VaultTokenSupplier.class, () -> () -> "test-token")
                    .withPropertyValues(
                            "pii.vault.address=https://vault.example.test:8200",
                            "pii.vault.key-name=pii-token",
                            "pii.vault.key-set-id=test-key-set",
                            "pii.vault.current-version=k2",
                            "pii.vault.versions.k1=1",
                            "pii.vault.versions.k2=2");

    @Test
    void bindsThePinnedVersionMapAndCreatesOneProvider() {
        contextRunner.run(context -> {
            assertThat(context).hasSingleBean(TokenMacProvider.class);
            TokenMacProvider provider = context.getBean(TokenMacProvider.class);
            assertThat(provider.currentVersion()).isEqualTo("k2");
            assertThat(provider.keyMappings()).containsExactlyInAnyOrderEntriesOf(
                    java.util.Map.of(
                            "k1", "vault-transit:transit:pii-token:v1",
                            "k2", "vault-transit:transit:pii-token:v2"));
        });
    }
}
