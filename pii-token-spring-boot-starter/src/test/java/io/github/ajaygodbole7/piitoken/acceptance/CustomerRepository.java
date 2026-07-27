package io.github.ajaygodbole7.piitoken.acceptance;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface CustomerRepository
        extends JpaRepository<Customer, UUID>, CustomerPiiRepositoryFragment {
}
