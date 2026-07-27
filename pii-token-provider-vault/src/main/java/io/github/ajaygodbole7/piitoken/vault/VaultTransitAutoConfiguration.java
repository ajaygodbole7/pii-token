package io.github.ajaygodbole7.piitoken.vault;

import io.github.ajaygodbole7.piitoken.provider.TokenMacProvider;
import io.github.ajaygodbole7.piitoken.runtime.PiiTokenAutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

@AutoConfiguration(before = PiiTokenAutoConfiguration.class)
@ConditionalOnBean(VaultTokenSupplier.class)
@EnableConfigurationProperties(VaultTransitProperties.class)
public class VaultTransitAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(TokenMacProvider.class)
    TokenMacProvider vaultTransitTokenMacProvider(
            VaultTransitProperties properties,
            VaultTokenSupplier tokenSupplier) {
        return new VaultTransitTokenMacProvider(properties, tokenSupplier);
    }
}
