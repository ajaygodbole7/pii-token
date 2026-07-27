package compat.fixture;

import io.github.ajaygodbole7.piitoken.annotation.Kind;
import io.github.ajaygodbole7.piitoken.annotation.Mask;
import io.github.ajaygodbole7.piitoken.annotation.PII;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import lombok.Getter;
import lombok.Setter;

import java.util.UUID;

@Entity
@Getter
@Setter
public class Customer {

    @Id
    private UUID id;

    @PII(
            id = "fixture.customer.ssn",
            kind = Kind.SSN,
            searchable = true,
            mask = Mask.LAST4)
    private String ssn;

    private String ssnLast4;

    @PII(id = "fixture.customer.pan", kind = Kind.PAN)
    private String pan;
}
