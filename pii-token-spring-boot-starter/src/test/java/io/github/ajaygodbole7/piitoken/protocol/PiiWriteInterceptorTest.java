package io.github.ajaygodbole7.piitoken.protocol;

import io.github.ajaygodbole7.piitoken.annotation.Kind;
import io.github.ajaygodbole7.piitoken.annotation.Mask;
import io.github.ajaygodbole7.piitoken.descriptor.PiiFieldAccess;
import io.github.ajaygodbole7.piitoken.descriptor.PiiFieldDescriptor;
import io.github.ajaygodbole7.piitoken.provider.ProviderFailureReason;
import io.github.ajaygodbole7.piitoken.provider.TokenMacException;
import io.github.ajaygodbole7.piitoken.runtime.GeneratedPiiModel;
import io.github.ajaygodbole7.piitoken.runtime.PiiRuntimeGate;
import io.github.ajaygodbole7.piitoken.runtime.RuntimePolicyFixture;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PiiWriteInterceptorTest {

    private static final String[] PROPERTIES = {"pan", "ssn", "ssnLast4"};

    @Test
    void persistReplacesEveryPlaintextOnlyAfterAllOutputsAreStaged() {
        CountingProvider provider = new CountingProvider();
        Customer customer = customer("123-45-6789", "4111111111111111", "caller");
        Object[] state = {customer.pan, customer.ssn, customer.ssnLast4};
        PiiWriteInterceptor interceptor = interceptor(openGate(), provider);

        assertThat(interceptor.onPersist(
                customer,
                7L,
                state,
                PROPERTIES,
                null)).isTrue();

        assertThat(customer.pan).startsWith("v2.k2.n1.");
        assertThat(customer.ssn).startsWith("b2.k2.n1.");
        assertThat(customer.ssnLast4).isEqualTo("6789");
        assertThat(state).containsExactly(customer.pan, customer.ssn, "6789");
        assertThat(provider.calls).isEqualTo(2);
    }

    @Test
    void loadValidatesStoredStructureAndSuffixWithoutProviderWork() {
        CountingProvider provider = new CountingProvider();
        PiiWriteInterceptor interceptor = interceptor(openGate(), provider);
        Customer customer = customer(searchableToken(), matchOnlyToken(), "6789");
        Object[] valid = {customer.pan, customer.ssn, customer.ssnLast4};

        assertThat(interceptor.onLoad(customer, 7L, valid, PROPERTIES, null)).isFalse();

        assertLoadReason(
                interceptor,
                new Object[] {matchOnlyToken(), "plaintext", "6789"},
                ProtocolReason.INVALID_TOKEN);
        assertLoadReason(
                interceptor,
                new Object[] {matchOnlyToken(), matchOnlyToken(), "6789"},
                ProtocolReason.WRONG_TOKEN_FAMILY);
        assertLoadReason(
                interceptor,
                new Object[] {matchOnlyToken(), "b2.k9.n1." + "00".repeat(32), "6789"},
                ProtocolReason.UNKNOWN_KEY_VERSION);
        assertLoadReason(
                interceptor,
                new Object[] {matchOnlyToken(), searchableToken(), "caller"},
                ProtocolReason.INVALID_STORED_SUFFIX);
        assertLoadReason(
                interceptor,
                new Object[] {matchOnlyToken(), null, "6789"},
                ProtocolReason.INVALID_STORED_SUFFIX);

        assertThat(provider.calls).isZero();
    }

    @Test
    void providerFailureLeavesEntityAndHibernateStateEntirelyUnmodified() {
        CountingProvider provider = new CountingProvider();
        provider.failOnCall = 2;
        Customer customer = customer("123-45-6789", "4111111111111111", "caller");
        Object[] state = {customer.pan, customer.ssn, customer.ssnLast4};
        Object[] before = state.clone();
        PiiWriteInterceptor interceptor = interceptor(openGate(), provider);

        assertThatThrownBy(() -> interceptor.onPersist(
                customer,
                7L,
                state,
                PROPERTIES,
                null))
                .isInstanceOf(TokenMacException.class)
                .hasMessage(ProviderFailureReason.UNAVAILABLE.name());

        assertThat(state).containsExactly(before);
        assertThat(customer.pan).isEqualTo("4111111111111111");
        assertThat(customer.ssn).isEqualTo("123-45-6789");
        assertThat(customer.ssnLast4).isEqualTo("caller");
    }

    @Test
    void unchangedFlushDoesNoProviderWorkAndPreservesStoredBytes() {
        CountingProvider provider = new CountingProvider();
        String panToken = matchOnlyToken();
        String ssnToken = searchableToken();
        Customer customer = customer(ssnToken, panToken, "6789");
        Object[] current = {panToken, ssnToken, "6789"};
        Object[] previous = current.clone();
        PiiWriteInterceptor interceptor = interceptor(openGate(), provider);

        assertThat(interceptor.onFlushDirty(
                customer,
                7L,
                current,
                previous,
                PROPERTIES,
                null)).isFalse();

        assertThat(provider.calls).isZero();
        assertThat(current).containsExactly(previous);
    }

    @Test
    void dirtyProtectedFieldTransformsOnlyThatField() {
        CountingProvider provider = new CountingProvider();
        String oldSsn = searchableToken();
        String oldPan = matchOnlyToken();
        Customer customer = customer(oldSsn, "5555555555554444", "6789");
        Object[] previous = {oldPan, oldSsn, "6789"};
        Object[] current = {"5555555555554444", oldSsn, "6789"};
        PiiWriteInterceptor interceptor = interceptor(openGate(), provider);

        assertThat(interceptor.onFlushDirty(
                customer,
                7L,
                current,
                previous,
                PROPERTIES,
                null)).isTrue();

        assertThat(customer.pan).startsWith("v2.k2.n1.");
        assertThat(customer.ssn).isEqualTo(oldSsn);
        assertThat(customer.ssnLast4).isEqualTo("6789");
        assertThat(provider.calls).isOne();
    }

    @Test
    void independentlyDirtySuffixFailsBeforeProviderWork() {
        CountingProvider provider = new CountingProvider();
        String panToken = matchOnlyToken();
        String ssnToken = searchableToken();
        Customer customer = customer(ssnToken, panToken, "9999");
        Object[] previous = {panToken, ssnToken, "6789"};
        Object[] current = {panToken, ssnToken, "9999"};
        PiiWriteInterceptor interceptor = interceptor(openGate(), provider);

        assertThatThrownBy(() -> interceptor.onFlushDirty(
                customer,
                7L,
                current,
                previous,
                PROPERTIES,
                null))
                .isInstanceOf(PiiProtocolException.class)
                .hasMessage(ProtocolReason.INDEPENDENT_SUFFIX_MUTATION.name());

        assertThat(provider.calls).isZero();
        assertThat(current).containsExactly(panToken, ssnToken, "9999");
    }

    @Test
    void closedGateAndMissingPreviousStateFailBeforeMutationOrProviderWork() {
        CountingProvider provider = new CountingProvider();
        Customer customer = customer("123-45-6789", "4111111111111111", null);
        Object[] state = {customer.pan, customer.ssn, null};
        PiiWriteInterceptor closed = interceptor(new PiiRuntimeGate(), provider);

        assertThatThrownBy(() -> closed.onPersist(
                customer,
                7L,
                state,
                PROPERTIES,
                null))
                .isInstanceOf(io.github.ajaygodbole7.piitoken.runtime.PiiGateClosedException.class);

        PiiWriteInterceptor open = interceptor(openGate(), provider);
        assertThatThrownBy(() -> open.onFlushDirty(
                customer,
                7L,
                state,
                null,
                PROPERTIES,
                null))
                .isInstanceOf(PiiProtocolException.class)
                .hasMessage(ProtocolReason.PERSISTENCE_STATE_INVALID.name());
        assertThat(provider.calls).isZero();
        assertThat(state).containsExactly("4111111111111111", "123-45-6789", null);
    }

    private static PiiWriteInterceptor interceptor(
            PiiRuntimeGate gate,
            CountingProvider provider) {
        return new PiiWriteInterceptor(model(), gate, provider);
    }

    private static void assertLoadReason(
            PiiWriteInterceptor interceptor,
            Object[] state,
            ProtocolReason reason) {
        Customer customer = customer(
                (String) state[1],
                (String) state[0],
                (String) state[2]);
        assertThatThrownBy(() ->
                interceptor.onLoad(customer, 7L, state, PROPERTIES, null))
                .isInstanceOf(PiiProtocolException.class)
                .hasMessage(reason.name());
    }

    private static PiiRuntimeGate openGate() {
        return RuntimePolicyFixture.openGate(List.of(PanAccess.DESCRIPTOR, SsnAccess.DESCRIPTOR));
    }

    private static GeneratedPiiModel model() {
        return RuntimePolicyFixture.generatedModel(List.of(new SsnAccess(), new PanAccess()));
    }

    private static Customer customer(String ssn, String pan, String last4) {
        Customer customer = new Customer();
        customer.ssn = ssn;
        customer.pan = pan;
        customer.ssnLast4 = last4;
        return customer;
    }

    private static String searchableToken() {
        return "b2.k1.n1." + "00".repeat(32);
    }

    private static String matchOnlyToken() {
        return "v2.k1.n1." + "00".repeat(16) + "." + "00".repeat(32);
    }

    private static final class Customer {
        private String ssn;
        private String ssnLast4;
        private String pan;
    }

    private static final class SsnAccess implements PiiFieldAccess<Customer> {
        private static final PiiFieldDescriptor DESCRIPTOR = new PiiFieldDescriptor(
                "customer.ssn",
                Kind.SSN,
                true,
                Mask.LAST4,
                Customer.class.getName(),
                "ssn");

        @Override
        public Class<Customer> entityType() {
            return Customer.class;
        }

        @Override
        public PiiFieldDescriptor descriptor() {
            return DESCRIPTOR;
        }

        @Override
        public String readValue(Customer entity) {
            return entity.ssn;
        }

        @Override
        public void writeValue(Customer entity, String value) {
            entity.ssn = value;
        }

        @Override
        public String readLast4(Customer entity) {
            return entity.ssnLast4;
        }

        @Override
        public void writeLast4(Customer entity, String last4) {
            entity.ssnLast4 = last4;
        }
    }

    private static final class PanAccess implements PiiFieldAccess<Customer> {
        private static final PiiFieldDescriptor DESCRIPTOR = new PiiFieldDescriptor(
                "customer.pan",
                Kind.PAN,
                false,
                Mask.NONE,
                Customer.class.getName(),
                "pan");

        @Override
        public Class<Customer> entityType() {
            return Customer.class;
        }

        @Override
        public PiiFieldDescriptor descriptor() {
            return DESCRIPTOR;
        }

        @Override
        public String readValue(Customer entity) {
            return entity.pan;
        }

        @Override
        public void writeValue(Customer entity, String value) {
            entity.pan = value;
        }
    }

    private static final class CountingProvider implements TestMacProvider {
        private int calls;
        private int failOnCall = -1;

        @Override
        public String currentVersion() {
            return "k2";
        }

        @Override
        public Set<String> liveVersions() {
            return Set.of("k1", "k2");
        }

        @Override
        public byte[] macDigest(String logicalVersion, byte[] sha256Digest) {
            calls++;
            if (calls == failOnCall) {
                throw new TokenMacException(ProviderFailureReason.UNAVAILABLE);
            }
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                digest.update(logicalVersion.getBytes(StandardCharsets.US_ASCII));
                return digest.digest(sha256Digest);
            }
            catch (java.security.NoSuchAlgorithmException exception) {
                throw new AssertionError(exception);
            }
        }
    }
}
