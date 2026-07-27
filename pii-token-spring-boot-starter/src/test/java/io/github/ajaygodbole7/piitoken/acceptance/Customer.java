package io.github.ajaygodbole7.piitoken.acceptance;

import io.github.ajaygodbole7.piitoken.annotation.Kind;
import io.github.ajaygodbole7.piitoken.annotation.Mask;
import io.github.ajaygodbole7.piitoken.annotation.PII;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Version;

import java.util.UUID;

@Entity
@Table(name = "p3_customer")
public class Customer {

    @Id
    @GeneratedValue
    private UUID id;

    @Version
    private long version;

    @Column(nullable = false)
    private String name;

    @PII(
            id = "acceptance.customer.ssn",
            kind = Kind.SSN,
            searchable = true,
            mask = Mask.LAST4)
    @Column(length = 160)
    private String ssn;

    @Column(name = "ssn_last4", length = 4)
    private String ssnLast4;

    @PII(id = "acceptance.customer.pan", kind = Kind.PAN)
    @Column(length = 160)
    private String pan;

    public UUID getId() {
        return id;
    }

    public long getVersion() {
        return version;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getSsn() {
        return ssn;
    }

    public void setSsn(String ssn) {
        this.ssn = ssn;
    }

    public String getSsnLast4() {
        return ssnLast4;
    }

    public void setSsnLast4(String ssnLast4) {
        this.ssnLast4 = ssnLast4;
    }

    public String getPan() {
        return pan;
    }

    public void setPan(String pan) {
        this.pan = pan;
    }
}
