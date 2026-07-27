package io.github.ajaygodbole7.piitoken.test;

import io.github.ajaygodbole7.piitoken.annotation.Kind;
import io.github.ajaygodbole7.piitoken.annotation.Mask;
import io.github.ajaygodbole7.piitoken.descriptor.DescriptorManifestCodec;
import io.github.ajaygodbole7.piitoken.descriptor.PiiFieldDescriptor;
import org.junit.jupiter.api.Test;
import org.postgresql.ds.PGSimpleDataSource;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.sql.DriverManager;
import java.util.List;

import static io.github.ajaygodbole7.piitoken.test.RegistryTestFixture.KeyState.CURRENT;
import static org.assertj.core.api.Assertions.assertThat;

class RegistryTestFixtureTest {

    @Test
    void provisionsCanonicalPolicyAndKeyRowsIntoConsumerDatabase()
            throws Exception {
        try (var postgres = new PostgreSQLContainer("postgres:18.4")) {
            postgres.start();
            PGSimpleDataSource dataSource = new PGSimpleDataSource();
            dataSource.setURL(postgres.getJdbcUrl());
            dataSource.setUser(postgres.getUsername());
            dataSource.setPassword(postgres.getPassword());

            PiiFieldDescriptor descriptor = new PiiFieldDescriptor(
                    "test.customer.ssn",
                    Kind.SSN,
                    true,
                    Mask.LAST4,
                    "test.Customer",
                    "ssn");
            RegistryTestFixture fixture =
                    RegistryTestFixture.fromDescriptors(
                            "test.app",
                            "hashicorp-vault-transit",
                            "test-key-set",
                            List.of(descriptor),
                            List.of(new RegistryTestFixture.KeyVersion(
                                    "k1",
                                    "vault-transit:transit:pii-token:v1",
                                    CURRENT)));

            fixture.provision(dataSource);

            try (var connection = DriverManager.getConnection(
                    postgres.getJdbcUrl(),
                    postgres.getUsername(),
                    postgres.getPassword());
                 var policy = connection.createStatement().executeQuery("""
                         select descriptor_manifest, descriptor_fingerprint
                         from pii_security.pii_policy_registry
                         where id = 1
                         """)) {
                assertThat(policy.next()).isTrue();
                assertThat(policy.getString("descriptor_manifest"))
                        .isEqualTo(DescriptorManifestCodec.encode(
                                List.of(descriptor)));
                assertThat(policy.getString("descriptor_fingerprint"))
                        .isEqualTo(fixture.fingerprint());
            }

            try (var connection = DriverManager.getConnection(
                    postgres.getJdbcUrl(),
                    postgres.getUsername(),
                    postgres.getPassword());
                 var keys = connection.createStatement().executeQuery("""
                         select logical_version, opaque_ref, state
                         from pii_security.pii_key_version_registry
                         """)) {
                assertThat(keys.next()).isTrue();
                assertThat(keys.getString("logical_version")).isEqualTo("k1");
                assertThat(keys.getString("opaque_ref"))
                        .isEqualTo("vault-transit:transit:pii-token:v1");
                assertThat(keys.getString("state")).isEqualTo("CURRENT");
                assertThat(keys.next()).isFalse();
            }
        }
    }
}
