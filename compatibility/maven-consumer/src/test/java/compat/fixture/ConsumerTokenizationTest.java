package compat.fixture;

import io.github.ajaygodbole7.piitoken.test.RegistryTestFixture;
import io.github.ajaygodbole7.piitoken.test.VaultTransitTestFixture;
import io.github.ajaygodbole7.piitoken.vault.VaultTransitTokenMacProvider;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.postgresql.ds.PGSimpleDataSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;

@Testcontainers
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
@SpringBootTest(
        classes = ConsumerApplication.class,
        properties = {
            "spring.jpa.hibernate.ddl-auto=create-drop",
            "spring.jpa.open-in-view=false",
            "spring.jpa.show-sql=false",
            "pii.application-namespace=consumer.app",
            "pii.searchable-digests=permitted"
        })
class ConsumerTokenizationTest {

    private static final VaultTransitTestFixture VAULT = startVault();

    @Container
    private static final PostgreSQLContainer POSTGRESQL =
            new PostgreSQLContainer("postgres:18.4");

    private static final AtomicBoolean REGISTRY_PROVISIONED =
            new AtomicBoolean();

    @DynamicPropertySource
    static void postgresProperties(DynamicPropertyRegistry registry) {
        provisionRegistry();
        registry.add("spring.datasource.url", POSTGRESQL::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRESQL::getUsername);
        registry.add("spring.datasource.password", POSTGRESQL::getPassword);
        registry.add("sample.vault-token", VAULT::runtimeToken);
        VAULT.springProperties().forEach(
                (name, value) -> registry.add(name, () -> value));
    }

    @AfterAll
    static void stopVault() {
        VAULT.close();
    }

    @Autowired
    private CustomerRepository repository;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private EntityManager entityManager;

    @Test
    void annotationTokenizesAndQueriesAcrossPinnedVaultRotation() {
        Customer customer = new Customer();
        customer.setId(UUID.randomUUID());
        customer.setSsn("123-45-6789");
        customer.setPan("4111 1111 1111 1111");

        Customer saved = repository.saveAndFlush(customer);

        assertThat(saved.getSsn()).startsWith("b2.k2.n1.");
        assertThat(saved.getPan()).startsWith("v2.k2.n1.");
        assertThat(saved.getSsnLast4()).isEqualTo("6789");
        Map<String, Object> stored = jdbcTemplate.queryForMap(
                "select ssn, ssn_last4, pan from customer where id = ?",
                saved.getId());
        assertThat(stored.get("ssn")).isEqualTo(saved.getSsn());
        assertThat(stored.get("pan")).isEqualTo(saved.getPan());
        assertThat(stored.values())
                .doesNotContain("123456789", "4111111111111111");
        assertThat(repository.existsBySsn("123456789")).isTrue();
        assertThat(repository.ssnMatches(saved.getId(), "123-45-6789")).isTrue();
        assertThat(repository.panMatches(
                saved.getId(),
                "4111111111111111")).isTrue();

        String oldSsnToken = searchableSsnToken("123456789");
        assertThat(oldSsnToken).startsWith("b2.k1.n1.");
        jdbcTemplate.update(
                "update customer set ssn = ? where id = ?",
                oldSsnToken,
                saved.getId());
        entityManager.clear();

        assertThat(repository.existsBySsn("123-45-6789")).isTrue();
        assertThat(repository.ssnMatches(saved.getId(), "123456789")).isTrue();
        assertThat(jdbcTemplate.queryForObject(
                "select ssn from customer where id = ?",
                String.class,
                saved.getId())).isEqualTo(oldSsnToken);
    }

    private static String searchableSsnToken(String normalizedSsn) {
        byte[] domain = bytes(
                "pii-tok|1|".getBytes(StandardCharsets.US_ASCII),
                new byte[] {1},
                lp("consumer.app"),
                lp("fixture.customer.ssn"),
                lp("SSN"),
                new byte[] {0, 1});
        byte[] message = bytes(lp(domain), normalizedSsn.getBytes(StandardCharsets.US_ASCII));
        try (var provider = new VaultTransitTokenMacProvider(
                VAULT.providerProperties(),
                VAULT::runtimeToken)) {
            byte[] mac = provider.macDigest(
                    "k1",
                    sha256(message));
            return "b2.k1.n1." + HexFormat.of().formatHex(mac);
        }
    }

    private static VaultTransitTestFixture startVault() {
        VaultTransitTestFixture fixture = VaultTransitTestFixture.start(
                "pii-token",
                "consumer-vault-key-set",
                "k1");
        fixture.rotate("k2");
        return fixture;
    }

    private static void provisionRegistry() {
        if (!REGISTRY_PROVISIONED.compareAndSet(false, true)) {
            return;
        }
        try {
            PGSimpleDataSource dataSource = new PGSimpleDataSource();
            dataSource.setURL(POSTGRESQL.getJdbcUrl());
            dataSource.setUser(POSTGRESQL.getUsername());
            dataSource.setPassword(POSTGRESQL.getPassword());
            RegistryTestFixture.fromManifest(
                    "consumer.app",
                    VaultTransitTokenMacProvider.PROVIDER_ID,
                    VAULT.keySetId(),
                    generatedManifest(),
                    List.of(
                            new RegistryTestFixture.KeyVersion(
                                    "k1",
                                    VAULT.opaqueReference("k1"),
                                    RegistryTestFixture.KeyState.READ_ONLY),
                            new RegistryTestFixture.KeyVersion(
                                    "k2",
                                    VAULT.opaqueReference("k2"),
                                    RegistryTestFixture.KeyState.CURRENT)))
                    .provision(dataSource);
        }
        catch (RuntimeException exception) {
            REGISTRY_PROVISIONED.set(false);
            throw exception;
        }
    }

    private static String generatedManifest() {
        try {
            Path classes = Path.of(Customer.class
                    .getProtectionDomain()
                    .getCodeSource()
                    .getLocation()
                    .toURI());
            return Files.readString(classes.resolve(
                    "META-INF/pii/descriptor-manifest.txt"));
        }
        catch (Exception exception) {
            throw new IllegalStateException(
                    "GENERATED_MANIFEST_UNAVAILABLE",
                    exception);
        }
    }

    private static byte[] lp(String value) {
        return lp(value.getBytes(StandardCharsets.US_ASCII));
    }

    private static byte[] lp(byte[] value) {
        byte[] framed = new byte[value.length + 2];
        framed[0] = (byte) ((value.length >>> 8) & 0xff);
        framed[1] = (byte) (value.length & 0xff);
        System.arraycopy(value, 0, framed, 2, value.length);
        return framed;
    }

    private static byte[] bytes(byte[]... values) {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        for (byte[] value : values) {
            output.writeBytes(value);
        }
        return output.toByteArray();
    }

    private static byte[] sha256(byte[] value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value);
        }
        catch (Exception exception) {
            throw new AssertionError(exception);
        }
    }
}
