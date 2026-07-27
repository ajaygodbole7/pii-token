package io.github.ajaygodbole7.piitoken.runtime;

import jakarta.persistence.EntityManagerFactory;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PiiTokenAutoConfigurationTest {

    @Test
    void requiresExactlyOnePersistenceUnit() {
        EntityManagerFactory first = entityManagerFactory();
        EntityManagerFactory second = entityManagerFactory();

        assertThat(PiiTokenAutoConfiguration.requireSingleEntityManagerFactory(
                List.of(first))).isSameAs(first);
        assertReason(List.of());
        assertReason(List.of(first, second));
    }

    private static void assertReason(List<EntityManagerFactory> factories) {
        assertThatThrownBy(() ->
                PiiTokenAutoConfiguration.requireSingleEntityManagerFactory(factories))
                .isInstanceOf(StartupValidationException.class)
                .hasMessage(StartupReason.PERSISTENCE_UNIT_COUNT_INVALID.name());
    }

    private static EntityManagerFactory entityManagerFactory() {
        return (EntityManagerFactory) Proxy.newProxyInstance(
                PiiTokenAutoConfigurationTest.class.getClassLoader(),
                new Class<?>[] {EntityManagerFactory.class},
                (proxy, method, arguments) -> {
                    throw new UnsupportedOperationException(method.getName());
                });
    }
}
