package io.github.ajaygodbole7.piitoken.kms;

import io.github.ajaygodbole7.piitoken.provider.TokenMacProvider;
import io.github.ajaygodbole7.piitoken.runtime.PiiTokenAutoConfiguration;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import software.amazon.awssdk.services.kms.KmsClient;

import java.util.List;

@AutoConfiguration(before = PiiTokenAutoConfiguration.class)
@ConditionalOnProperty(
        prefix = "pii.kms",
        name = "enabled",
        havingValue = "true")
@EnableConfigurationProperties(KmsHmacProperties.class)
public class KmsTokenMacAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(TokenMacProvider.class)
    TokenMacProvider kmsTokenMacProvider(
            KmsHmacProperties properties,
            ObjectProvider<KmsClient> clients) {
        List<KmsClient> supplied = clients.orderedStream().toList();
        if (supplied.size() > 1) {
            throw new IllegalArgumentException("KMS_CONFIGURATION_INVALID");
        }
        return supplied.isEmpty()
                ? new KmsTokenMacProvider(properties)
                : new KmsTokenMacProvider(properties, supplied.getFirst());
    }
}
