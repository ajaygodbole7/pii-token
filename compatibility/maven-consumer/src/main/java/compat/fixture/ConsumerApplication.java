package compat.fixture;

import io.github.ajaygodbole7.piitoken.vault.VaultTokenSupplier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.Map;
import java.util.UUID;

@SpringBootApplication
public class ConsumerApplication {

    public static void main(String[] args) {
        try (var ignored = SpringApplication.run(
                ConsumerApplication.class,
                args)) {
            // The quickstart is a one-shot executable, not a service.
        }
    }

    @Bean
    VaultTokenSupplier vaultTokenSupplier(
            @Value("${sample.vault-token}") String token) {
        return () -> token;
    }

    @Bean
    @ConditionalOnProperty(
            name = "sample.quickstart",
            havingValue = "true")
    ApplicationRunner quickstart(
            CustomerRepository repository,
            JdbcTemplate jdbcTemplate) {
        return ignored -> {
            Customer customer = new Customer();
            customer.setId(UUID.randomUUID());
            customer.setSsn("123-45-6789");
            customer.setPan("4111 1111 1111 1111");

            Customer saved = repository.saveAndFlush(customer);
            Map<String, Object> stored = jdbcTemplate.queryForMap(
                    "select ssn, ssn_last4, pan from customer where id = ?",
                    saved.getId());

            System.out.println("saved.id=" + saved.getId());
            System.out.println("saved.ssnLast4=" + saved.getSsnLast4());
            System.out.println(
                    "search.ssn.exists="
                            + repository.existsBySsn("123456789"));
            System.out.println(
                    "match.ssn="
                            + repository.ssnMatches(
                            saved.getId(),
                            "123-45-6789"));
            System.out.println(
                    "match.pan="
                            + repository.panMatches(
                            saved.getId(),
                            "4111111111111111"));
            System.out.println("stored.ssn=" + stored.get("ssn"));
            System.out.println("stored.pan=" + stored.get("pan"));
        };
    }
}
