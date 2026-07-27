package io.github.ajaygodbole7.piitoken.runtime;

import io.github.ajaygodbole7.piitoken.acceptance.Customer;
import io.github.ajaygodbole7.piitoken.protocol.PiiWriteInterceptor;
import io.github.ajaygodbole7.piitoken.provider.TokenMacProvider;
import jakarta.persistence.EntityManagerFactory;
import jakarta.persistence.metamodel.Attribute;
import jakarta.persistence.metamodel.EntityType;
import jakarta.persistence.metamodel.Metamodel;
import org.hibernate.boot.spi.SessionFactoryOptions;
import org.hibernate.engine.spi.SessionFactoryImplementor;
import org.junit.jupiter.api.Test;
import org.springframework.boot.logging.LogLevel;
import org.springframework.boot.logging.LoggerConfiguration;
import org.springframework.boot.logging.LoggingSystem;

import javax.sql.DataSource;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PiiStartupValidatorTest {

    @Test
    void searchableDescriptorsAreProhibitedByDefaultBeforeRegistryOrProviderWork() {
        Probe probe = new Probe();
        PiiStartupValidator validator = validator(
                generatedModel(),
                new PiiTokenProperties(),
                probe);

        assertThatThrownBy(validator::afterSingletonsInstantiated)
                .isInstanceOf(StartupValidationException.class)
                .hasMessage(StartupReason.SEARCHABLE_DIGESTS_PROHIBITED.name());
        assertThat(probe.dataSourceCalls.get()).isZero();
        assertThat(probe.providerCalls.get()).isZero();
    }

    @Test
    void incompleteGeneratedDescriptorsFailBeforeSearchPolicyAndRegistry() {
        GeneratedPiiModel complete = generatedModel();
        GeneratedPiiModel missingSsn = new GeneratedPiiModel(
                complete.fields().stream()
                        .filter(field -> !field.descriptor().fieldName().equals("ssn"))
                        .toList());
        PiiTokenProperties properties = validProperties();
        Probe probe = new Probe();
        PiiStartupValidator validator = validator(missingSsn, properties, probe);

        assertThatThrownBy(validator::afterSingletonsInstantiated)
                .isInstanceOf(StartupValidationException.class)
                .hasMessage(StartupReason.JPA_MODEL_MISMATCH.name());
        assertThat(probe.dataSourceCalls.get()).isZero();
        assertThat(probe.providerCalls.get()).isZero();
    }

    @Test
    void invalidDeploymentConfigurationFailsBeforeRegistryOrProviderWork() {
        PiiTokenProperties properties = new PiiTokenProperties();
        properties.setSearchableDigests(PiiTokenProperties.SearchableDigests.PERMITTED);
        Probe probe = new Probe();
        PiiStartupValidator validator = validator(generatedModel(), properties, probe);

        assertThatThrownBy(validator::afterSingletonsInstantiated)
                .isInstanceOf(StartupValidationException.class)
                .hasMessage(StartupReason.CONFIGURATION_INVALID.name());
        assertThat(probe.dataSourceCalls.get()).isZero();
        assertThat(probe.providerCalls.get()).isZero();
    }

    @Test
    void conflictingInstalledInterceptorFailsBeforeRegistryOrProviderWork() {
        Probe probe = new Probe();
        PiiTokenProperties properties = validProperties();
        GeneratedPiiModel model = generatedModel();
        TokenMacProvider provider = probe.provider();
        PiiRuntimeGate runtimeGate = new PiiRuntimeGate();
        PiiWriteInterceptor expected = new PiiWriteInterceptor(
                model,
                runtimeGate,
                provider);
        PiiWriteInterceptor installed = new PiiWriteInterceptor(
                model,
                runtimeGate,
                provider);
        PiiStartupValidator validator = new PiiStartupValidator(
                entityManagerFactory(installed),
                model,
                probe.dataSource(),
                provider,
                runtimeGate,
                expected,
                properties,
                loggingSystem(LogLevel.INFO));

        assertThatThrownBy(validator::afterSingletonsInstantiated)
                .isInstanceOf(StartupValidationException.class)
                .hasMessage(StartupReason.HIBERNATE_INTERCEPTOR_CONFLICT.name());
        assertThat(probe.dataSourceCalls.get()).isZero();
        assertThat(probe.providerCalls.get()).isZero();
    }

    @Test
    void traceBindLoggingFailsBeforeRegistryOrProviderWork() {
        Probe probe = new Probe();
        PiiTokenProperties properties = validProperties();
        GeneratedPiiModel model = generatedModel();
        TokenMacProvider provider = probe.provider();
        PiiRuntimeGate runtimeGate = new PiiRuntimeGate();
        PiiWriteInterceptor interceptor = new PiiWriteInterceptor(
                model,
                runtimeGate,
                provider);
        PiiStartupValidator validator = new PiiStartupValidator(
                entityManagerFactory(interceptor),
                model,
                probe.dataSource(),
                provider,
                runtimeGate,
                interceptor,
                properties,
                loggingSystem(LogLevel.TRACE));

        assertThatThrownBy(validator::afterSingletonsInstantiated)
                .isInstanceOf(StartupValidationException.class)
                .hasMessage(StartupReason.UNSAFE_BIND_LOGGING.name());
        assertThat(probe.dataSourceCalls.get()).isZero();
        assertThat(probe.providerCalls.get()).isZero();
    }

    @Test
    void registryExpectationsComeFromTheProvidersActualImmutableMapping() {
        TokenMacProvider provider = configuredProvider(
                Map.of("k1", "vault:key:v1", "k2", "vault:key:v2"),
                Set.of("k1", "k2"),
                "k2");
        PiiStartupValidator validator = new PiiStartupValidator(
                null,
                generatedModel(),
                null,
                provider,
                null,
                null,
                validProperties(),
                null);

        RegistryExpectations expectations = validator.validateConfiguration();

        assertThat(expectations.expectedLiveMappings()).containsExactlyInAnyOrderEntriesOf(
                Map.of("k1", "vault:key:v1", "k2", "vault:key:v2"));
    }

    @Test
    void providerMappingAndLiveVersionDriftIsInvalidConfiguration() {
        TokenMacProvider provider = configuredProvider(
                Map.of("k1", "vault:key:v1"),
                Set.of("k1", "k2"),
                "k2");
        PiiStartupValidator validator = new PiiStartupValidator(
                null,
                generatedModel(),
                null,
                provider,
                null,
                null,
                validProperties(),
                null);

        assertThatThrownBy(validator::validateConfiguration)
                .isInstanceOf(StartupValidationException.class)
                .hasMessage(StartupReason.CONFIGURATION_INVALID.name());
    }

    private static PiiStartupValidator validator(
            GeneratedPiiModel model,
            PiiTokenProperties properties,
            Probe probe) {
        TokenMacProvider provider = probe.provider();
        PiiRuntimeGate runtimeGate = new PiiRuntimeGate();
        PiiWriteInterceptor interceptor = new PiiWriteInterceptor(
                model,
                runtimeGate,
                provider);
        return new PiiStartupValidator(
                entityManagerFactory(interceptor),
                model,
                probe.dataSource(),
                provider,
                runtimeGate,
                interceptor,
                properties,
                loggingSystem(LogLevel.INFO));
    }

    private static LoggingSystem loggingSystem(LogLevel effectiveLevel) {
        return new LoggingSystem() {
            @Override
            public void beforeInitialize() {
            }

            @Override
            public void setLogLevel(String loggerName, LogLevel level) {
            }

            @Override
            public LoggerConfiguration getLoggerConfiguration(String loggerName) {
                return new LoggerConfiguration(loggerName, null, effectiveLevel);
            }
        };
    }

    private static GeneratedPiiModel generatedModel() {
        return GeneratedPiiModel.load(PiiStartupValidatorTest.class.getClassLoader());
    }

    private static TokenMacProvider configuredProvider(
            Map<String, String> mappings,
            Set<String> liveVersions,
            String currentVersion) {
        return proxy(TokenMacProvider.class, method -> switch (method.getName()) {
            case "keyMappings" -> mappings;
            case "liveVersions" -> liveVersions;
            case "currentVersion" -> currentVersion;
            default -> throw unexpected(method);
        });
    }

    private static PiiTokenProperties validProperties() {
        PiiTokenProperties properties = new PiiTokenProperties();
        properties.setApplicationNamespace("bank.acceptance");
        properties.setSearchableDigests(PiiTokenProperties.SearchableDigests.PERMITTED);
        return properties;
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private static EntityManagerFactory entityManagerFactory(
            PiiWriteInterceptor interceptor) {
        Attribute stringAttribute = proxy(Attribute.class, method -> {
            if (method.getName().equals("getJavaType")) {
                return String.class;
            }
            throw unexpected(method);
        });
        EntityType<Customer> entityType = proxy(EntityType.class, method -> {
            return switch (method.getName()) {
                case "getJavaType" -> Customer.class;
                case "getAttribute" -> stringAttribute;
                default -> throw unexpected(method);
            };
        });
        Metamodel metamodel = proxy(Metamodel.class, method -> {
            if (method.getName().equals("getEntities")) {
                return Set.of(entityType);
            }
            throw unexpected(method);
        });
        SessionFactoryOptions options = proxy(SessionFactoryOptions.class, method -> {
            if (method.getName().equals("getInterceptor")) {
                return interceptor;
            }
            throw unexpected(method);
        });
        SessionFactoryImplementor sessionFactory =
                proxy(SessionFactoryImplementor.class, method -> {
            if (method.getName().equals("getSessionFactoryOptions")) {
                return options;
            }
            throw unexpected(method);
        });
        return proxy(EntityManagerFactory.class, method -> {
            return switch (method.getName()) {
                case "getMetamodel" -> metamodel;
                case "unwrap" -> sessionFactory;
                default -> throw unexpected(method);
            };
        });
    }

    private static AssertionError unexpected(Method method) {
        return new AssertionError("Unexpected call: " + method.getName());
    }

    @FunctionalInterface
    private interface MethodResult {
        Object invoke(Method method);
    }

    private static <T> T proxy(Class<T> type, MethodResult result) {
        return type.cast(Proxy.newProxyInstance(
                type.getClassLoader(),
                new Class<?>[] {type},
                (proxy, method, arguments) -> {
                    if (method.getDeclaringClass() == Object.class) {
                        return switch (method.getName()) {
                            case "toString" -> type.getSimpleName() + "Probe";
                            case "hashCode" -> System.identityHashCode(proxy);
                            case "equals" -> proxy == arguments[0];
                            default -> throw unexpected(method);
                        };
                    }
                    return result.invoke(method);
                }));
    }

    private static final class Probe {
        private final AtomicInteger dataSourceCalls = new AtomicInteger();
        private final AtomicInteger providerCalls = new AtomicInteger();

        private DataSource dataSource() {
            return proxy(DataSource.class, method -> {
                dataSourceCalls.incrementAndGet();
                throw unexpected(method);
            });
        }

        private TokenMacProvider provider() {
            return proxy(TokenMacProvider.class, method -> {
                providerCalls.incrementAndGet();
                throw unexpected(method);
            });
        }
    }
}
