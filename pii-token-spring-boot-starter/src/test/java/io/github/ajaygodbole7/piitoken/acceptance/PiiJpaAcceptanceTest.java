package io.github.ajaygodbole7.piitoken.acceptance;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.core.read.ListAppender;
import io.github.ajaygodbole7.piitoken.annotation.Kind;
import io.github.ajaygodbole7.piitoken.annotation.Mask;
import io.github.ajaygodbole7.piitoken.descriptor.PiiFieldDescriptor;
import io.github.ajaygodbole7.piitoken.protocol.PiiProtocolException;
import io.github.ajaygodbole7.piitoken.protocol.ProtocolReason;
import io.github.ajaygodbole7.piitoken.protocol.ProtocolTestFixture;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.json.JsonMapper;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@Testcontainers
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
@SpringBootTest(
        classes = {AcceptanceApplication.class, AcceptanceProviderConfiguration.class},
        properties = {
            "spring.jpa.hibernate.ddl-auto=create-drop",
            "spring.jpa.open-in-view=false",
            "spring.jpa.show-sql=false",
            "pii.application-namespace=bank.acceptance",
            "pii.jackson-suppression-enabled=true",
            "pii.searchable-digests=permitted"
        })
class PiiJpaAcceptanceTest {

    @Container
    static final PostgreSQLContainer POSTGRESQL =
            new PostgreSQLContainer("postgres:18.4")
                    .withInitScript("acceptance-registry.sql");

    @DynamicPropertySource
    static void postgresProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRESQL::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRESQL::getUsername);
        registry.add("spring.datasource.password", POSTGRESQL::getPassword);
    }

    @Autowired
    private CustomerRepository repository;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private AcceptanceTokenMacProvider provider;

    @Autowired
    private JsonMapper jsonMapper;

    @BeforeEach
    void reset() {
        jdbcTemplate.update("delete from p3_customer");
        provider.resetCalls();
    }

    @Test
    void saveReplacesPlaintextInEntityAndDatabaseAndMaintainsLast4() {
        Customer saved = save(
                "save",
                "123-45-6789",
                "4111111111111111");

        assertThat(saved.getSsn()).startsWith("b2.k2.n1.");
        assertThat(saved.getPan()).startsWith("v2.k2.n1.");
        assertThat(saved.getSsnLast4()).isEqualTo("6789");
        Map<String, Object> row = jdbcTemplate.queryForMap(
                "select ssn, ssn_last4, pan from p3_customer where id = ?",
                saved.getId());
        assertThat(row.get("ssn")).isEqualTo(saved.getSsn());
        assertThat(row.get("ssn_last4")).isEqualTo("6789");
        assertThat(row.get("pan")).isEqualTo(saved.getPan());
        assertThat(provider.calls()).isEqualTo(2);
    }

    @Test
    void generatedSearchReturnsAllRowsAcrossBothLiveKeyVersions() {
        Customer current = save(
                "current",
                "234-56-7890",
                null);
        String oldToken = ProtocolTestFixture.searchableToken(
                "bank.acceptance",
                ssnDescriptor(),
                "k1",
                "234-56-7890",
                provider);
        UUID oldId = UUID.randomUUID();
        jdbcTemplate.update(
                """
                insert into p3_customer
                    (id, version, name, ssn, ssn_last4, pan)
                values (?, 0, ?, ?, ?, null)
                """,
                oldId,
                "old",
                oldToken,
                "7890");
        provider.resetCalls();

        List<Customer> found = repository.findAllBySsn("234567890");

        assertThat(found).extracting(Customer::getId)
                .containsExactlyInAnyOrder(current.getId(), oldId);
        assertThat(repository.existsBySsn("234-56-7890")).isTrue();
        assertThat(provider.calls()).isEqualTo(4);
    }

    @Test
    void generatedMatchAndReplaceMethodsStaySemantic() {
        Customer saved = save(
                "semantic",
                "345-67-8901",
                "4111111111111111");
        provider.resetCalls();

        assertThat(repository.ssnMatches(saved.getId(), "345678901")).isTrue();
        assertThat(repository.panMatches(
                saved.getId(),
                "4111 1111 1111 1111")).isTrue();
        assertThat(repository.replaceSsn(
                saved.getId(),
                "456-78-9012")).isTrue();

        Customer replaced = repository.findById(saved.getId()).orElseThrow();
        assertThat(replaced.getSsn()).startsWith("b2.k2.n1.");
        assertThat(replaced.getSsnLast4()).isEqualTo("9012");
        assertThat(repository.existsBySsn("456789012")).isTrue();
        assertThat(repository.existsBySsn("345678901")).isFalse();
    }

    @Test
    void corruptedStoredSearchableValueFailsBeforeProviderWork() {
        Customer saved = save(
                "corrupt",
                "567-89-0123",
                null);
        jdbcTemplate.update(
                "update p3_customer set ssn = ? where id = ?",
                "plaintext",
                saved.getId());
        provider.resetCalls();

        assertThatThrownBy(() -> repository.ssnMatches(
                saved.getId(),
                "567890123"))
                .isInstanceOf(PiiProtocolException.class)
                .hasMessage(ProtocolReason.INVALID_TOKEN.name());
        assertThat(provider.calls()).isZero();
    }

    @Test
    void ordinaryEntityLoadRejectsPlantedPlaintextAndMalformedSuffixWithoutProviderWork() {
        Customer planted = save(
                "planted",
                "568-90-1234",
                null);
        jdbcTemplate.update(
                "update p3_customer set ssn = ? where id = ?",
                "planted-plaintext",
                planted.getId());
        provider.resetCalls();

        assertThatThrownBy(() -> repository.findById(planted.getId()))
                .satisfies(throwable -> assertThat(hasCause(
                        throwable,
                        ProtocolReason.INVALID_TOKEN)).isTrue());
        assertThat(provider.calls()).isZero();

        Customer malformedSuffix = save(
                "malformed-suffix",
                "569-01-2345",
                null);
        jdbcTemplate.update(
                "update p3_customer set ssn_last4 = ? where id = ?",
                "12x4",
                malformedSuffix.getId());
        provider.resetCalls();

        assertThatThrownBy(() -> repository.findById(malformedSuffix.getId()))
                .satisfies(throwable -> assertThat(hasCause(
                        throwable,
                        ProtocolReason.INVALID_STORED_SUFFIX)).isTrue());
        assertThat(provider.calls()).isZero();
    }

    @Test
    void optInJacksonModuleSuppressesTokensAndPlaintextButKeepsApprovedLast4()
            throws Exception {
        Customer saved = save(
                "serialize",
                "570-12-3456",
                "4111111111111111");

        String json = jsonMapper.writeValueAsString(saved);

        assertThat(json)
                .contains("\"ssnLast4\":\"3456\"")
                .doesNotContain(
                        "\"ssn\"",
                        "\"pan\"",
                        saved.getSsn(),
                        saved.getPan(),
                        "570123456",
                        "4111111111111111");

        Customer proxyShape = new Customer() { };
        proxyShape.setName("proxy-shape");
        proxyShape.setSsn(saved.getSsn());
        proxyShape.setSsnLast4(saved.getSsnLast4());
        proxyShape.setPan(saved.getPan());

        assertThat(jsonMapper.writeValueAsString(proxyShape))
                .contains("\"ssnLast4\":\"3456\"")
                .doesNotContain(
                        "\"ssn\"",
                        "\"pan\"",
                        saved.getSsn(),
                        saved.getPan());
    }

    @Test
    @Transactional
    void managedDirtyAndUnrelatedUpdatesHonorDirtyState() {
        Customer managed = save(
                "managed",
                "678-90-1234",
                "4111111111111111");
        String ssnBefore = managed.getSsn();
        String panBefore = managed.getPan();
        provider.resetCalls();

        managed.setPan("5555555555554444");
        repository.flush();

        assertThat(managed.getPan())
                .startsWith("v2.k2.n1.")
                .isNotEqualTo(panBefore);
        assertThat(managed.getSsn()).isEqualTo(ssnBefore);
        assertThat(provider.calls()).isOne();

        provider.resetCalls();
        managed.setName("renamed");
        repository.flush();
        assertThat(provider.calls()).isZero();
        assertThat(managed.getSsn()).isEqualTo(ssnBefore);
    }

    @Test
    @Transactional
    void independentlyModifiedLast4FailsClosed() {
        Customer managed = save(
                "suffix",
                "789-01-2345",
                "4111111111111111");
        provider.resetCalls();
        managed.setSsnLast4("0000");

        assertThatThrownBy(repository::flush)
                .satisfies(throwable -> assertThat(hasCause(
                        throwable,
                        ProtocolReason.INDEPENDENT_SUFFIX_MUTATION)).isTrue());
        assertThat(provider.calls()).isZero();
    }

    @Test
    void dirtyDetachedTokenFailsClosedWithoutChangingStoredBytes() {
        Customer detached = save(
                "detached",
                "890-12-3456",
                "4111111111111111");
        String storedToken = detached.getSsn();
        String staleToken = ProtocolTestFixture.searchableToken(
                "bank.acceptance",
                ssnDescriptor(),
                "k1",
                "890-12-3456",
                provider);
        detached.setSsn(staleToken);
        provider.resetCalls();

        assertThatThrownBy(() -> repository.saveAndFlush(detached))
                .satisfies(throwable -> assertThat(hasCause(
                        throwable,
                        ProtocolReason.INVALID_VALUE)).isTrue());
        assertThat(provider.calls()).isZero();
        assertThat(jdbcTemplate.queryForObject(
                "select ssn from p3_customer where id = ?",
                String.class,
                detached.getId())).isEqualTo(storedToken);
    }

    @Test
    void unsafeRuntimeBindLoggingNegativeControlExposesProtectedStoredForms() {
        Logger bindLogger = (Logger) LoggerFactory.getLogger(
                "org.hibernate.orm.jdbc.bind");
        Level previousLevel = bindLogger.getLevel();
        ListAppender<ch.qos.logback.classic.spi.ILoggingEvent> capture =
                new ListAppender<>();
        capture.start();
        bindLogger.addAppender(capture);
        bindLogger.setLevel(Level.TRACE);
        try {
            Customer saved = save(
                    "bind-negative-control",
                    "901-23-4567",
                    "4111111111111111");

            List<String> messages = capture.list.stream()
                    .map(event -> event.getFormattedMessage())
                    .toList();
            assertThat(messages.stream().anyMatch(message ->
                    message.contains(saved.getSsn())
                            || message.contains(saved.getSsnLast4())))
                    .as("TRACE bind logging must demonstrate the unsupported "
                            + "token/LAST4 leak")
                    .isTrue();
        }
        finally {
            bindLogger.setLevel(previousLevel);
            bindLogger.detachAppender(capture);
            capture.stop();
        }
    }

    private Customer save(String name, String ssn, String pan) {
        Customer customer = new Customer();
        customer.setName(name);
        customer.setSsn(ssn);
        customer.setPan(pan);
        return repository.saveAndFlush(customer);
    }

    private static PiiFieldDescriptor ssnDescriptor() {
        return new PiiFieldDescriptor(
                "acceptance.customer.ssn",
                Kind.SSN,
                true,
                Mask.LAST4,
                Customer.class.getName(),
                "ssn");
    }

    private static boolean hasCause(Throwable failure, ProtocolReason reason) {
        for (Throwable current = failure;
             current != null && current.getCause() != current;
             current = current.getCause()) {
            if (current instanceof PiiProtocolException protocol
                    && protocol.reason() == reason) {
                return true;
            }
        }
        return false;
    }
}
