# PII Tokenization Library

This library performs irreversible keyed tokenization. If losing the original
value would create a business, legal, or operational incident, that field must
not use this library.

What it supports:

- exact match and equality search
- verification: check a value someone gives you against a tokenized sensitive field
- deduplication
- optional last-four display

What it will never do: decrypt, display, or recover the original value. No such
API exists.

## What using it looks like

Add `@PII` to the entity field you want protected:

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

What this means for application code:

- no crypto implementation, provider calls, token transformation, or
  protected-column query code in the application
- provider credentials are wired once; field behavior stays annotation-driven
- adding a field still requires deployment-reviewed schema and registry
  changes; see [Adding protected fields](docs/adding-protected-fields.md)

## Using it in your application

One-time setup, in order:

1. **Build the artifacts** into your local Maven repository (no public Maven
   repository is configured yet):

   ```shell
   ./mvnw -DskipTests install
   ```

2. **Add the dependencies**: the starter, exactly one provider module, and the
   annotation processor on the compiler path.

   ```xml
   <dependency>
       <groupId>io.github.ajaygodbole7</groupId>
       <artifactId>pii-token-spring-boot-starter</artifactId>
       <version>0.1.0-SNAPSHOT</version>
   </dependency>
   <dependency>
       <groupId>io.github.ajaygodbole7</groupId>
       <artifactId>pii-token-provider-vault</artifactId>
       <version>0.1.0-SNAPSHOT</version>
   </dependency>
   ```

   ```xml
   <plugin>
       <groupId>org.apache.maven.plugins</groupId>
       <artifactId>maven-compiler-plugin</artifactId>
       <configuration>
           <annotationProcessorPaths>
               <path>
                   <groupId>io.github.ajaygodbole7</groupId>
                   <artifactId>pii-token-processor</artifactId>
                   <version>0.1.0-SNAPSHOT</version>
               </path>
           </annotationProcessorPaths>
       </configuration>
   </plugin>
   ```

   For AWS KMS instead of Vault, replace the provider dependency with
   `pii-token-provider-kms`; see its
   [README](pii-token-provider-kms/README.md). Activate exactly one provider.

3. **Configure the application**:

   ```properties
   pii.application-namespace=your.app
   # Required only if any field uses searchable = true:
   pii.searchable-digests=permitted

   pii.vault.address=https://vault.example.com
   pii.vault.mount=transit
   pii.vault.key-name=pii-token
   pii.vault.key-set-id=your-key-set
   pii.vault.current-version=k1
   pii.vault.versions.k1=1
   ```

4. **Provide the Vault credential**: define a `VaultTokenSupplier` bean that
   returns the runtime token. The token needs the HMAC path only; see
   [Operations](docs/OPERATIONS.md) for the least-privilege policy.

5. **Provision the registry**: a privileged migration identity creates the
   `pii_security` schema and the approved policy and key rows; the application
   role gets `SELECT` only. The application refuses to start until its
   compiled descriptors match the approved registry. See
   [Adding protected fields](docs/adding-protected-fields.md) and
   [Operations](docs/OPERATIONS.md).

After setup, each protected field is the annotation plus a reviewed schema and
registry change, as described in
[Adding protected fields](docs/adding-protected-fields.md). The
[runnable sample](compatibility/maven-consumer) shows a complete working
configuration.

## Local evaluation

Prerequisites are Docker with Compose, JDK 25, and a shell. The Maven wrapper is
included.

The root Compose file uses pinned `hashicorp/vault:2.0.3` and `postgres:18.4`
images. On startup it:

- creates the Transit HMAC key and rotates it to version 2
- issues an HMAC-only runtime token
- provisions the approved registry for the sample

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
runnable sample and the independent Maven compatibility gate. It demonstrates:

- a real JPA entity with the generated repository API
- PostgreSQL persistence and Vault Transit provider wiring
- equality search and match-only verification
- pinned key-version rollover

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

The module provides two fixtures:

- `VaultTransitTestFixture` starts the pinned Vault dev container, provisions
  a non-exportable HMAC key and least-privilege token, exposes `pii.vault.*`
  test properties, and supports in-place rotation.
- `RegistryTestFixture` provisions the fixed security schema and a
  manifest-derived approved registry into a consumer-supplied PostgreSQL
  `DataSource`.

Testcontainers is a normal dependency of this test-support artifact; the
artifact itself must always be declared with Maven test scope.

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
  registry semantics. `p1/n1` names the current version pair: protocol
  version 1 (the byte construction) and normalizer version 1 (the SSN/PAN
  validation and canonicalization rules). Every stored token records this
  pair.

## Current limitations

- The supported path is narrow by design: Java 25, Spring Boot 4.1.0,
  Spring Data JPA, Hibernate, and PostgreSQL.
- Version 1 implements only SSN and PAN kinds.
- Tokenization is one-way forever. Compromise remediation can require deletion
  or recollection because no decrypt path exists.
- Vault Transit is the quickstart provider; the optional
  [`pii-token-provider-kms`](pii-token-provider-kms/README.md) module supports
  AWS KMS HMAC keys.
- Artifacts are built from source; no public Maven repository is configured.

## License

Apache-2.0. See [LICENSE](LICENSE).
