package io.github.ajaygodbole7.piitoken.protocol;

import io.github.ajaygodbole7.piitoken.annotation.Kind;
import io.github.ajaygodbole7.piitoken.annotation.Mask;
import io.github.ajaygodbole7.piitoken.descriptor.PiiFieldDescriptor;
import io.github.ajaygodbole7.piitoken.provider.TokenMacProvider;
import io.github.ajaygodbole7.piitoken.runtime.PiiGateClosedException;
import io.github.ajaygodbole7.piitoken.runtime.PiiRuntimeGate;
import io.github.ajaygodbole7.piitoken.runtime.RuntimePolicyFixture;
import jakarta.persistence.EntityManager;
import jakarta.persistence.TypedQuery;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Expression;
import jakarta.persistence.criteria.Path;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import org.junit.jupiter.api.Test;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class GeneratedPiiJpaOperationsTest {

    @Test
    void closedGatePreventsProviderAndJpaWork() {
        JpaProbe probe = new JpaProbe();
        CountingProvider provider = new CountingProvider();
        var operations = new GeneratedPiiJpaOperations(new PiiRuntimeGate(), provider);

        assertThatThrownBy(() -> operations.existsBy(
                probe.entityManager,
                Customer.class,
                "customer.ssn",
                "ssn",
                "123-45-6789"))
                .isInstanceOf(PiiGateClosedException.class);

        assertThat(provider.calls).isZero();
        assertThat(probe.interactions).isZero();
    }

    @Test
    void searchableExistsUsesBoundedRotationSetAndMaxOne() {
        PiiFieldDescriptor descriptor = descriptor("customer.ssn", "ssn", true);
        CountingProvider provider = new CountingProvider();
        var operations = new GeneratedPiiJpaOperations(
                RuntimePolicyFixture.openGate(List.of(descriptor)),
                provider);
        JpaProbe probe = new JpaProbe();

        boolean exists = operations.existsBy(
                probe.entityManager,
                Customer.class,
                "customer.ssn",
                "ssn",
                "123-45-6789");

        assertThat(exists).isTrue();
        assertThat(provider.calls).isEqualTo(2);
        assertThat(provider.versions).containsExactly("k1", "k2");
        assertThat(probe.inValues).hasSize(2);
        assertThat(probe.maxResults).isOne();
    }

    @Test
    void semanticMatchSupportsBothTokenFamiliesAndRejectsCorruptedStoredSearchableValue() {
        PiiFieldDescriptor searchable = descriptor("customer.ssn", "ssn", true);
        PiiFieldDescriptor matchOnly = descriptor("customer.pan", "pan", false);
        CountingProvider provider = new CountingProvider();
        PiiRuntimeGate gate = RuntimePolicyFixture.openGate(List.of(searchable, matchOnly));
        var operations = new GeneratedPiiJpaOperations(gate, provider);
        var engine = new P1N1TokenEngine(provider, target -> {
            for (int index = 0; index < target.length; index++) {
                target[index] = (byte) index;
            }
        });
        Customer customer = new Customer();
        customer.ssn = engine.protect(context(searchable), "123-45-6789").token();
        customer.pan = engine.protect(context(matchOnly), "4111111111111111").token();
        JpaProbe probe = new JpaProbe(Map.of(7L, customer));

        assertThat(operations.matches(
                probe.entityManager,
                Customer.class,
                7L,
                "customer.ssn",
                "ssn",
                "123456789",
                found -> found.ssn)).isTrue();
        assertThat(operations.matches(
                probe.entityManager,
                Customer.class,
                7L,
                "customer.pan",
                "pan",
                "4111 1111 1111 1111",
                found -> found.pan)).isTrue();

        customer.ssn = "plaintext";
        int callsBeforeCorruptedValue = provider.calls;
        assertThatThrownBy(() -> operations.matches(
                probe.entityManager,
                Customer.class,
                7L,
                "customer.ssn",
                "ssn",
                "123456789",
                found -> found.ssn))
                .isInstanceOf(PiiProtocolException.class)
                .hasMessage(ProtocolReason.INVALID_TOKEN.name());
        assertThat(provider.calls).isEqualTo(callsBeforeCorruptedValue);
    }

    @Test
    void replaceOnlyMutatesManagedEntityAndDoesNoProviderWork() {
        PiiFieldDescriptor descriptor = descriptor("customer.pan", "pan", false);
        CountingProvider provider = new CountingProvider();
        var operations = new GeneratedPiiJpaOperations(
                RuntimePolicyFixture.openGate(List.of(descriptor)),
                provider);
        Customer customer = new Customer();
        JpaProbe probe = new JpaProbe(Map.of(7L, customer));

        assertThat(operations.replace(
                probe.entityManager,
                Customer.class,
                7L,
                "customer.pan",
                "pan",
                "4111111111111111",
                (found, value) -> found.pan = value)).isTrue();
        assertThat(customer.pan).isEqualTo("4111111111111111");
        assertThat(provider.calls).isZero();

        assertThat(operations.replace(
                probe.entityManager,
                Customer.class,
                8L,
                "customer.pan",
                "pan",
                "5555555555554444",
                (found, value) -> found.pan = value)).isFalse();
        assertThat(probe.flushes).isZero();
    }

    private static PiiFieldDescriptor descriptor(
            String id,
            String field,
            boolean searchable) {
        return new PiiFieldDescriptor(
                id,
                field.equals("ssn") ? Kind.SSN : Kind.PAN,
                searchable,
                Mask.NONE,
                Customer.class.getName(),
                field);
    }

    private static TokenContext context(PiiFieldDescriptor descriptor) {
        return new TokenContext(
                "bank.cards",
                descriptor,
                "k2",
                List.of("k1", "k2"));
    }

    private static final class Customer {
        private String ssn;
        private String pan;
    }

    private static final class JpaProbe {
        private final Map<?, ?> entities;
        private final EntityManager entityManager;
        private int interactions;
        private int flushes;
        private int maxResults;
        private Collection<?> inValues = List.of();

        private JpaProbe() {
            this(Map.of());
        }

        @SuppressWarnings({"unchecked", "rawtypes"})
        private JpaProbe(Map<?, ?> entities) {
            this.entities = entities;
            Predicate predicate = proxy(Predicate.class, unsupported("Predicate"));
            Expression<Integer> selection =
                    proxy(Expression.class, unsupported("Expression"));
            Path<String> path = proxy(Path.class, (ignored, method, arguments) -> {
                if (method.getName().equals("in")) {
                    inValues = (Collection<?>) arguments[0];
                    return predicate;
                }
                throw unexpected(method);
            });
            Root<Customer> root = proxy(Root.class, (ignored, method, arguments) -> {
                if (method.getName().equals("get")) {
                    return path;
                }
                throw unexpected(method);
            });
            CriteriaQuery criteria = proxy(CriteriaQuery.class, (proxy, method, arguments) -> {
                return switch (method.getName()) {
                    case "from" -> root;
                    case "select", "where" -> proxy;
                    default -> throw unexpected(method);
                };
            });
            CriteriaBuilder builder = proxy(CriteriaBuilder.class, (ignored, method, arguments) -> {
                return switch (method.getName()) {
                    case "createQuery" -> criteria;
                    case "literal" -> selection;
                    default -> throw unexpected(method);
                };
            });
            TypedQuery query = proxy(TypedQuery.class, (proxy, method, arguments) -> {
                return switch (method.getName()) {
                    case "setMaxResults" -> {
                        maxResults = (int) arguments[0];
                        yield proxy;
                    }
                    case "getResultList" -> List.of(1);
                    default -> throw unexpected(method);
                };
            });
            entityManager = proxy(EntityManager.class, (ignored, method, arguments) -> {
                interactions++;
                return switch (method.getName()) {
                    case "getCriteriaBuilder" -> builder;
                    case "createQuery" -> query;
                    case "find" -> this.entities.get(arguments[1]);
                    case "flush" -> {
                        flushes++;
                        yield null;
                    }
                    default -> throw unexpected(method);
                };
            });
        }
    }

    private static InvocationHandler unsupported(String type) {
        return (proxy, method, arguments) -> {
            throw new AssertionError("Unexpected " + type + " call: " + method.getName());
        };
    }

    private static AssertionError unexpected(Method method) {
        return new AssertionError("Unexpected call: " + method.getName());
    }

    private static <T> T proxy(Class<T> type, InvocationHandler handler) {
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
                    return handler.invoke(proxy, method, arguments);
                }));
    }

    private static final class CountingProvider implements TokenMacProvider {
        private int calls;
        private final java.util.ArrayList<String> versions = new java.util.ArrayList<>();

        @Override
        public String providerId() {
            return "provider";
        }

        @Override
        public String keySetId() {
            return "key-set";
        }

        @Override
        public String currentVersion() {
            return "k2";
        }

        @Override
        public Set<String> liveVersions() {
            return Set.of("k1", "k2");
        }

        @Override
        public java.util.Map<String, String> keyMappings() {
            return java.util.Map.of("k1", "opaque-k1", "k2", "opaque-k2");
        }

        @Override
        public byte[] macDigest(String logicalVersion, byte[] sha256Digest) {
            calls++;
            versions.add(logicalVersion);
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                digest.update(logicalVersion.getBytes(StandardCharsets.US_ASCII));
                return digest.digest(sha256Digest);
            }
            catch (java.security.NoSuchAlgorithmException exception) {
                throw new AssertionError(exception);
            }
        }

        @Override
        public void close() {
        }
    }
}
