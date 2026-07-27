package io.github.ajaygodbole7.piitoken.acceptance;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;

@TestConfiguration(proxyBeanMethods = false)
class AcceptanceProviderConfiguration {

    @Bean
    AcceptanceTokenMacProvider acceptanceTokenMacProvider() {
        return new AcceptanceTokenMacProvider();
    }
}
