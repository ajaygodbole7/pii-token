package io.github.ajaygodbole7.piitoken.runtime;

import io.github.ajaygodbole7.piitoken.annotation.Mask;
import io.github.ajaygodbole7.piitoken.annotation.PII;
import io.github.ajaygodbole7.piitoken.descriptor.PiiFieldDescriptor;
import io.github.ajaygodbole7.piitoken.protocol.PiiWriteInterceptor;
import io.github.ajaygodbole7.piitoken.provider.TokenMacProvider;
import jakarta.persistence.EntityManagerFactory;
import jakarta.persistence.metamodel.EntityType;
import jakarta.persistence.metamodel.Metamodel;
import org.hibernate.engine.spi.SessionFactoryImplementor;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.boot.logging.LogLevel;
import org.springframework.boot.logging.LoggerConfiguration;
import org.springframework.boot.logging.LoggingSystem;

import javax.sql.DataSource;
import java.lang.reflect.Field;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * One-time startup validation. Runtime reflection is confined to this class.
 */
public final class PiiStartupValidator implements SmartInitializingSingleton {

    static final String HIBERNATE_BIND_LOGGER = "org.hibernate.orm.jdbc.bind";

    private final EntityManagerFactory entityManagerFactory;
    private final GeneratedPiiModel generatedModel;
    private final DataSource dataSource;
    private final TokenMacProvider provider;
    private final PiiRuntimeGate runtimeGate;
    private final PiiWriteInterceptor interceptor;
    private final PiiTokenProperties properties;
    private final LoggingSystem loggingSystem;

    public PiiStartupValidator(
            EntityManagerFactory entityManagerFactory,
            GeneratedPiiModel generatedModel,
            DataSource dataSource,
            TokenMacProvider provider,
            PiiRuntimeGate runtimeGate,
            PiiWriteInterceptor interceptor,
            PiiTokenProperties properties,
            LoggingSystem loggingSystem) {
        this.entityManagerFactory = entityManagerFactory;
        this.generatedModel = generatedModel;
        this.dataSource = dataSource;
        this.provider = provider;
        this.runtimeGate = runtimeGate;
        this.interceptor = interceptor;
        this.properties = properties;
        this.loggingSystem = loggingSystem;
    }

    @Override
    public void afterSingletonsInstantiated() {
        validateHibernateInterceptor();
        validateBindLogging();
        validateJpaCompleteness();
        validateSearchableDigestPolicy();
        RegistryExpectations expectations = validateConfiguration();
        ApprovedRuntimePolicy policy =
                new ApprovedRegistryLoader(dataSource).load(expectations, provider);
        runtimeGate.open(policy);
    }

    private void validateBindLogging() {
        LoggerConfiguration configuration = nearestLoggerConfiguration(
                HIBERNATE_BIND_LOGGER);
        if (configuration == null
                || configuration.getEffectiveLevel() == LogLevel.TRACE) {
            throw new StartupValidationException(StartupReason.UNSAFE_BIND_LOGGING);
        }
    }

    private LoggerConfiguration nearestLoggerConfiguration(String loggerName) {
        String candidate = loggerName;
        while (true) {
            LoggerConfiguration configuration =
                    loggingSystem.getLoggerConfiguration(candidate);
            if (configuration != null) {
                return configuration;
            }
            int separator = candidate.lastIndexOf('.');
            if (separator < 0) {
                return loggingSystem.getLoggerConfiguration(
                        LoggingSystem.ROOT_LOGGER_NAME);
            }
            candidate = candidate.substring(0, separator);
        }
    }

    private void validateHibernateInterceptor() {
        try {
            SessionFactoryImplementor sessionFactory =
                    entityManagerFactory.unwrap(SessionFactoryImplementor.class);
            if (sessionFactory.getSessionFactoryOptions().getInterceptor() != interceptor) {
                throw new StartupValidationException(
                        StartupReason.HIBERNATE_INTERCEPTOR_CONFLICT);
            }
        }
        catch (StartupValidationException exception) {
            throw exception;
        }
        catch (RuntimeException exception) {
            throw new StartupValidationException(
                    StartupReason.HIBERNATE_INTERCEPTOR_CONFLICT);
        }
    }

    private void validateJpaCompleteness() {
        Map<String, PiiFieldDescriptor> generatedById = new LinkedHashMap<>();
        for (PiiFieldDescriptor descriptor : generatedModel.descriptors()) {
            if (generatedById.putIfAbsent(descriptor.id(), descriptor) != null) {
                throw mismatch();
            }
        }

        Set<String> annotatedIds = new LinkedHashSet<>();
        Metamodel metamodel = entityManagerFactory.getMetamodel();
        for (EntityType<?> entityType : metamodel.getEntities()) {
            Class<?> javaType = entityType.getJavaType();
            for (Field field : javaType.getDeclaredFields()) {
                PII annotation = field.getAnnotation(PII.class);
                if (annotation == null) {
                    continue;
                }
                if (!annotatedIds.add(annotation.id())) {
                    throw mismatch();
                }
                PiiFieldDescriptor expected = new PiiFieldDescriptor(
                        annotation.id(),
                        annotation.kind(),
                        annotation.searchable(),
                        annotation.mask(),
                        javaType.getName(),
                        field.getName());
                if (!expected.equals(generatedById.get(annotation.id()))
                        || !persistentString(entityType, field.getName())) {
                    throw mismatch();
                }
                if (annotation.mask() == Mask.LAST4
                        && !persistentString(entityType, field.getName() + "Last4")) {
                    throw mismatch();
                }
            }
        }
        if (!annotatedIds.equals(generatedById.keySet())) {
            throw mismatch();
        }
    }

    private void validateSearchableDigestPolicy() {
        PiiTokenProperties.SearchableDigests policy = properties.getSearchableDigests();
        if (policy == null) {
            throw new StartupValidationException(StartupReason.CONFIGURATION_INVALID);
        }
        if (policy == PiiTokenProperties.SearchableDigests.PROHIBITED
                && generatedModel.descriptors().stream()
                .anyMatch(PiiFieldDescriptor::searchable)) {
            throw new StartupValidationException(
                    StartupReason.SEARCHABLE_DIGESTS_PROHIBITED);
        }
    }

    RegistryExpectations validateConfiguration() {
        String namespace = properties.getApplicationNamespace();
        if (namespace == null
                || namespace.isBlank()) {
            throw new StartupValidationException(StartupReason.CONFIGURATION_INVALID);
        }
        Map<String, String> mappings = provider.keyMappings();
        if (mappings == null
                || mappings.isEmpty()
                || mappings.size() > 4
                || mappings.entrySet().stream().anyMatch(entry ->
                entry.getKey() == null
                        || entry.getKey().isBlank()
                        || entry.getValue() == null
                        || entry.getValue().isBlank())
                || !mappings.keySet().equals(provider.liveVersions())
                || !mappings.containsKey(provider.currentVersion())) {
            throw new StartupValidationException(StartupReason.CONFIGURATION_INVALID);
        }
        return new RegistryExpectations(
                namespace,
                generatedModel.descriptors(),
                Map.copyOf(mappings));
    }

    private static boolean persistentString(EntityType<?> entityType, String fieldName) {
        try {
            return entityType.getAttribute(fieldName).getJavaType() == String.class;
        }
        catch (IllegalArgumentException exception) {
            return false;
        }
    }

    private static StartupValidationException mismatch() {
        return new StartupValidationException(StartupReason.JPA_MODEL_MISMATCH);
    }
}
