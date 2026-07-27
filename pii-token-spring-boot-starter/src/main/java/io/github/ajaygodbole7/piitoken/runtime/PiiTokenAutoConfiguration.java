package io.github.ajaygodbole7.piitoken.runtime;

import io.github.ajaygodbole7.piitoken.protocol.GeneratedPiiJpaOperations;
import io.github.ajaygodbole7.piitoken.protocol.PiiWriteInterceptor;
import io.github.ajaygodbole7.piitoken.provider.TokenMacProvider;
import jakarta.persistence.EntityManagerFactory;
import org.hibernate.cfg.AvailableSettings;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.hibernate.autoconfigure.HibernatePropertiesCustomizer;
import org.springframework.boot.logging.LoggingSystem;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.ResourceLoader;

import javax.sql.DataSource;
import java.util.List;
import java.util.Map;

@AutoConfiguration
@EnableConfigurationProperties(PiiTokenProperties.class)
public final class PiiTokenAutoConfiguration {

    @Bean
    GeneratedPiiModel generatedPiiModel(ResourceLoader resourceLoader) {
        return GeneratedPiiModel.load(resourceLoader.getClassLoader());
    }

    @Bean
    PiiRuntimeGate piiRuntimeGate() {
        return new PiiRuntimeGate();
    }

    @Bean
    PiiWriteInterceptor piiWriteInterceptor(
            GeneratedPiiModel generatedPiiModel,
            PiiRuntimeGate runtimeGate,
            TokenMacProvider tokenMacProvider) {
        return new PiiWriteInterceptor(
                generatedPiiModel,
                runtimeGate,
                tokenMacProvider);
    }

    @Bean
    @Order(Ordered.LOWEST_PRECEDENCE)
    HibernatePropertiesCustomizer piiHibernatePropertiesCustomizer(
            PiiWriteInterceptor interceptor) {
        return properties -> installInterceptor(properties, interceptor);
    }

    @Bean
    GeneratedPiiJpaOperations generatedPiiJpaOperations(
            PiiRuntimeGate runtimeGate,
            TokenMacProvider tokenMacProvider) {
        return new GeneratedPiiJpaOperations(runtimeGate, tokenMacProvider);
    }

    @Bean
    PiiStartupValidator piiStartupValidator(
            List<EntityManagerFactory> entityManagerFactories,
            GeneratedPiiModel generatedPiiModel,
            DataSource dataSource,
            TokenMacProvider tokenMacProvider,
            PiiRuntimeGate runtimeGate,
            PiiWriteInterceptor interceptor,
            PiiTokenProperties properties,
            ResourceLoader resourceLoader) {
        return new PiiStartupValidator(
                requireSingleEntityManagerFactory(entityManagerFactories),
                generatedPiiModel,
                dataSource,
                tokenMacProvider,
                runtimeGate,
                interceptor,
                properties,
                LoggingSystem.get(resourceLoader.getClassLoader()));
    }

    static EntityManagerFactory requireSingleEntityManagerFactory(
            List<EntityManagerFactory> entityManagerFactories) {
        if (entityManagerFactories == null || entityManagerFactories.size() != 1) {
            throw new StartupValidationException(
                    StartupReason.PERSISTENCE_UNIT_COUNT_INVALID);
        }
        return entityManagerFactories.getFirst();
    }

    private static void installInterceptor(
            Map<String, Object> hibernateProperties,
            PiiWriteInterceptor interceptor) {
        Object existing = hibernateProperties.putIfAbsent(
                AvailableSettings.INTERCEPTOR,
                interceptor);
        if (existing != null && existing != interceptor) {
            throw new StartupValidationException(
                    StartupReason.HIBERNATE_INTERCEPTOR_CONFLICT);
        }
    }
}
