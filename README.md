# PII Tokenization Library

This library performs irreversible keyed tokenization. If losing the original
value would create a business, legal, or operational incident, that field must
not use this library. It supports match, verify, deduplicate, equality search,
and optional LAST4 display. It has no API to decrypt, display, or recover the
original value.

## What using it looks like

An application declares the protection decision on its entity:

```java
@PII(
        id = "customer.ssn",
        kind = Kind.SSN,
        searchable = true,
        mask = Mask.LAST4)
private String ssn;

private String ssnLast4;
```

Compilation generates the persistence transformer and typed repository
operations:

```java
boolean existsBySsn(String candidate);
List<Customer> findAllBySsn(String candidate);
boolean ssnMatches(UUID id, String candidate);
boolean replaceSsn(UUID id, String replacement);
```

There is no crypto implementation, provider call, token transformation, or
protected-column query code in the application. The application wires provider
credentials once, then field behavior stays annotation-driven. Adding a field
still requires deployment-reviewed schema and registry changes; see
[Adding protected fields](docs/adding-protected-fields.md).

## Local evaluation

Prerequisites are Docker with Compose, JDK 25, and a shell. The Maven wrapper is
included.

The root Compose file uses pinned `hashicorp/vault:2.0.3` and `postgres:18.4`
images. It creates the Transit HMAC key, rotates it to version 2, issues an
HMAC-only runtime token, and provisions the approved registry for the sample.

> The Compose stack is for evaluation only. Vault runs in dev mode with a known
> root token, no TLS, and in-memory storage. PostgreSQL also uses known local
> credentials. Never use this configuration in production.

Start the stack and wait for all three services:

```shell
docker compose up -d --wait
```

Build the library artifacts from source:

```shell
./mvnw -DskipTests install
```

Run the existing Maven consumer with its evaluation profile:

```shell
./mvnw -f compatibility/maven-consumer/pom.xml \
  -Dspring-boot.run.profiles=quickstart \
  spring-boot:run
```

The one-shot app saves an entity, searches by SSN, verifies the SSN and PAN, and
prints only LAST4 plus stored token text. The relevant output has this shape:

```text
saved.ssnLast4=6789
search.ssn.exists=true
match.ssn=true
match.pan=true
stored.ssn=b2.k2.n1.<64 lowercase hexadecimal characters>
stored.pan=v2.k2.n1.<32 hexadecimal salt characters>.<64 hexadecimal MAC characters>
```

Inspect the database directly:

```shell
docker compose exec postgres \
  psql -U pii_demo -d pii_demo \
  -c 'select ssn, ssn_last4, pan from customer;'
```

Remove the evaluation data and containers when finished:

```shell
docker compose down -v
```

## Runnable sample

[`compatibility/maven-consumer`](compatibility/maven-consumer) is both the
runnable sample and the independent Maven compatibility gate. It contains a
real JPA entity, generated repository API, PostgreSQL persistence, Vault
Transit provider wiring, equality search, match-only verification, and pinned
version rollover.

## Build and verification

Docker must be available for the complete gate:

```shell
./mvnw clean verify
./tools/verify-compatibility.sh
```

The reactor runs unit, annotation-processor, PostgreSQL 18.4, Vault 2.0.3, and
LocalStack 4.14.0 tests. The compatibility gate builds the sample as an
independent Maven/Lombok consumer and scans the production runtime API and
dependencies.

## Test support

Consumer integration tests can use the test-only module after building this
repository with `./mvnw install`:

```xml
<dependency>
    <groupId>io.github.ajaygodbole7</groupId>
    <artifactId>pii-token-test</artifactId>
    <version>0.1.0-SNAPSHOT</version>
    <scope>test</scope>
</dependency>
```

`VaultTransitTestFixture` starts the pinned Vault dev container, provisions a
non-exportable HMAC key and least-privilege token, exposes `pii.vault.*` test
properties, and supports in-place rotation. `RegistryTestFixture` provisions
the fixed security schema and a manifest-derived approved registry into a
consumer-supplied PostgreSQL `DataSource`. Testcontainers is intentionally a
normal dependency of this test-support artifact; the artifact itself must
always be declared with Maven test scope.

## Documentation

- [Field suitability](docs/field-suitability.md) defines which one-way fields
  fit and why many sensitive fields do not.
- [Adding protected fields](docs/adding-protected-fields.md) covers application
  changes, generated migrations, and new kinds.
- [Architecture and scope](docs/DESIGN.md) describes the supported persistence,
  registry, and provider boundaries.
- [Security contract](SECURITY.md) states the application, database, provider,
  and operational boundaries.
- [Operations](docs/OPERATIONS.md) covers deployment, registry updates, key
  rollover, retirement, and incidents.
- [Protocol p1/n1](docs/PROTOCOL.md) freezes token bytes, normalization, and
  registry semantics.

## Current limitations

The supported path is intentionally narrow: Java 25, Spring Boot 4.1.0,
Spring Data JPA, Hibernate, and PostgreSQL. Version 1 implements only SSN and
PAN kinds. Tokenization is one-way forever; compromise remediation can require
deletion or recollection because no decrypt path exists. Vault Transit remains
the quickstart provider; the optional
[`pii-token-provider-kms`](pii-token-provider-kms/README.md) module supports
AWS KMS HMAC keys. Artifacts are currently built from source; no public Maven
repository is configured.

## License

Apache-2.0. See [LICENSE](LICENSE).
