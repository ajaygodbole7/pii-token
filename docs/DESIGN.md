# Architecture and Scope

This document describes the implemented `p1/n1` architecture on `main`.

## Security goals and non-goals

The supported deployment is one Spring application, one application
namespace, one key set, and one active provider. The implementation is designed
to:

- fail closed before any protected operation;
- never persist plaintext on the supported path after protection;
- expose no decrypt, recover, raw-key, or generic tokenization API;
- keep key material non-exportable;
- use typed, content-free errors;
- keep plaintext, request digests, tokens, and suffixes out of diagnostic
  sinks;
- detect descriptor, registry, key, and protocol drift before runtime use; and
- exercise the supported path with unit and real-provider integration tests.

The library does not provide regulatory certification, payment authorization,
recoverable storage, cross-provider routing, or protection for persistence
paths outside the documented Hibernate integration.

## Product

Irreversible, annotation-driven tokenization of SSN and PAN fields for Spring
Data JPA applications.

Supported business operations are:

- replace a protected value;
- exact match;
- equality search when explicitly enabled;
- optional last-four display; and
- delete.

Recovery is impossible by design. If losing the original value would create a
business, legal, or operational incident, that field must not use this
library.

## Fixed v1 scope

- Java 25.
- Spring Boot, Spring Data JPA, Hibernate, and PostgreSQL.
- `String` SSN and PAN fields only.
- `@PII` plus generated metadata/repository fragments.
- Hibernate `Interceptor` write transformation.
- One application namespace, one provider, and one logical key set per
  deployment.
- Bounded new-write key rollover only; one live normalizer version.
- Manual schema and data migration.

No v1 API exists for decryption, recovery, GENERIC values, manual
`protect()`, records, Mongo, R2DBC, batch tokenization, policy hot reload,
transparent derived-query rewriting, multiple simultaneous providers, or
provider certification.

## Consumer experience

```java
@PII(
        id = "customer.ssn",
        kind = Kind.SSN,
        searchable = true,
        mask = Mask.LAST4)
private String ssn;

private String ssnLast4;
```

The annotation processor:

- validates the field structure and SSN/PAN option combinations;
- emits readable direct-access metadata;
- emits the descriptor manifest;
- emits individually applicable PostgreSQL field DDL blocks plus a
  CAS-guarded policy-update plan;
- emits the same-package Spring Data repository fragment and implementation;
  and
- fails compilation with field-local diagnostics when the model is invalid.

Protected entities use default field access, exactly one field-level `@Id`,
and no entity inheritance, embedded/composite id, protected-field converter,
or generated/immutable protected state. Multiple persistence units fail
startup; v1 requires exactly one.

The application supplies exactly one `TokenMacProvider`. The repository ships
Vault Transit and AWS KMS implementations; an application may instead provide
its own implementation. Provider configuration is accompanied by the
deployment-maintained runtime baseline:

```yaml
pii:
  application-namespace: bank.cards
  searchable-digests: prohibited
```

`searchable-digests` defaults to `prohibited`. Startup fails closed if any
descriptor is searchable until the deployment explicitly changes it to
`permitted`.

Jackson 3 suppression is opt-in with
`pii.jackson-suppression-enabled=true`. When enabled, generated descriptors
remove protected token properties from serialization while retaining approved
`Last4` properties. Other serializers remain deployment-owned.

## Annotation semantics

`@PII` itself is the code-reviewed authorization for irreversible
tokenization. There is no one-value handling enum.

Required:

- `id`: stable logical field identity;
- `kind`: `SSN` or `PAN`.

Optional safe-absence defaults:

- `searchable = false`;
- `mask = NONE`.

`LAST4` is valid only with the required companion suffix field. A mask change
affects only future writes unless the deployment still has plaintext elsewhere;
tokens cannot backfill suffixes.

## Storage contract

One protected field uses:

- one token column; and
- one nullable cleartext suffix column only when `mask = LAST4`.

There is no ciphertext envelope and no decryptable companion column.

After a managed write the entity field itself contains the token. Reloading
returns that token. Applications must use DTO/serializer boundaries so tokens
are not exposed as API values.

Token columns use `VARCHAR(160)`. Exact `b2` and `v2` grammar and tighter
family limits are defined in [`PROTOCOL.md`](PROTOCOL.md).

## Validation

Normalization happens only during an operation that has plaintext:

- SSN: ASCII digits with optional canonical separators, normalized to exactly
  9 digits;
- PAN: ASCII digits with optional spaces or hyphens, normalized to 12–19
  digits and validated with Luhn.

Blank, malformed, or invalid values fail before any provider call. There is no
normalization guess for arbitrary identifiers.

## Managed write path

The mechanism of record is a Hibernate `Interceptor` registered through
`HibernatePropertiesCustomizer`.

- `onPersist` protects new plaintext before SQL binding.
- `onLoad` structurally rejects plaintext, malformed tokens, unknown live
  versions, and malformed/null-inconsistent LAST4 state without a provider
  call.
- `onFlushDirty` uses Hibernate state and the loaded previous state to detect
  a protected-field replacement.
- Token and suffix are fully staged before either entity field is mutated.
- Provider or validation failure aborts the operation without a
  plaintext/token or token/suffix mixture.
- Independent suffix edits fail closed.
- The runtime gate must be open before the interceptor, query layer, or token
  engine can execute.

JPA entity listeners are not supported because they do not provide the loaded
old state needed to distinguish a replacement from an already-tokenized
value.

Detached merge is not the recommended update path. Generated `replace*`
methods are the supported explicit mutation path.

## Persistence boundary

The library guarantees the managed JPA/Hibernate path only.

| Path | v1 status |
|---|---|
| managed `persist` / dirty flush | supported and tokenized |
| generated repository-fragment operations | supported |
| detached merge | structurally fail-closed, not the recommended path |
| native SQL, raw JDBC, bulk DML, alternate writer | outside the boundary |

Database permissions and writer inventory remain deployment responsibilities.
The application runtime role must not have a second path that writes plaintext
to protected columns. The processor emits a migration plan plus one
individually applicable DDL block per descriptor under
`META-INF/pii/migrations/fields/`. The operator applies only blocks named by the
descriptor-aware diagnostic, then applies the CAS-guarded manifest/fingerprint
update through the migration identity. The library never executes this SQL.

Load validation is structural, not cryptographic authentication. It catches
plaintext and malformed stored values, but a forged value that already has
canonical token shape can pass it.

## Search and bounded new-write key rollover

Searchable fields use deterministic `b2` tokens. Match-only fields use salted
`v2` tokens.

- Search generates one candidate token per live key version and queries with a
  bounded `IN` list.
- Match-only verification parses the stored salt and logical version and
  recomputes one MAC.
- Searchable verification validates the stored token before provider work and
  compares it with the generated live-version token set.
- Comparisons use constant-time byte comparison.
- Malformed, wrong-family, or unknown-version stored values are errors, not
  `NO_MATCH`.

One deployment has exactly one `CURRENT` key version and zero through three
`READ_ONLY` versions. A bounded new-write key rollover is:

1. add a new immutable version as `READ_ONLY`;
2. deploy readers that recognize it;
3. promote it to `CURRENT`;
4. deploy writers using it;
5. retire an old version only after every writer is drained and an offline
   inventory proves no stored token references it.

Constraints of bounded rollover:

- It does not rewrite existing rows and provides no unlimited key-version
  history.
- An old version remains live until every row that names it is deleted or
  replaced from newly presented plaintext.
- Each deployment with searchable fields must declare its maximum token
  lifetime and rollover cadence.
- The deployment must demonstrate, with safety margin, that the oldest version
  reaches zero rows before a fifth live version would be required.
- If that proof is unavailable, bounded rollover is not an operable
  key-lifecycle strategy for that deployment.

A normalizer change, provider change, or token-key compromise requires a new
namespace plus deletion or recollection/re-tokenization from an authorized
external source. Existing irreversible tokens cannot be
migrated in place, and key rollover does not remediate a compromised token key.

## Runtime integrity baseline

The PostgreSQL registry is a runtime integrity mechanism, not a human approval
workflow.

`pii_security.pii_policy_registry` contains:

- application namespace;
- protocol version;
- provider-operation version;
- key-set id;
- canonical descriptor manifest; and
- descriptor fingerprint.

`pii_security.pii_key_version_registry` contains the immutable mapping from
logical key versions to opaque provider references and their `CURRENT |
READ_ONLY | RETIRED` state.

The migration identity writes the baseline. The application runtime identity
gets `SELECT` only and cannot rewrite it.

The registry lives in the fixed `pii_security` schema. At startup
`ApprovedRegistryLoader` reads the complete baseline in one
read-only PostgreSQL `REPEATABLE READ` transaction. Startup validates:

- the compiled `p1/n1` protocol version;
- `HMAC_SHA256_PREHASH_V1` provider-operation version;
- namespace and key-set identity;
- stored manifest integrity;
- exact live descriptor fingerprint;
- exactly one current key and no more than three read-only keys;
- exact logical-to-opaque mappings; and
- equality between registry and provider live/current versions.

Only a successful immutable snapshot opens `PiiRuntimeGate`. There is no
runtime policy mutation, lease, hot reload, or report-only mode. Local
iteration uses the offline read-only `PiiRegistryDiagnosticCommand`, which
never starts the application, never writes the registry, and exits nonzero
while drift exists.

## Token protocol

[`PROTOCOL.md`](PROTOCOL.md) is the current byte-level specification for this
implementation.

```text
searchable:  b2.<keyVersion>.n1.<hex64>
match-only:  v2.<keyVersion>.n1.<hexSalt32>.<hex64>
```

The library:

1. validates and normalizes;
2. builds the length-prefixed domain and message;
3. computes `SHA-256(message)` locally;
4. sends exactly that 32-byte digest to `TokenMacProvider`; and
5. stores the returned 32-byte HMAC in the canonical token form.

The provider must not hash the digest again.

## Provider boundary

`TokenMacProvider` is the only cryptographic provider interface:

```java
public interface TokenMacProvider extends AutoCloseable {
    String providerId();
    String keySetId();
    String currentVersion();
    Set<String> liveVersions();
    Map<String, String> keyMappings();
    byte[] macDigest(String logicalVersion, byte[] sha256Digest);
}
```

The provider owns the immutable logical-to-opaque mapping returned by
`keyMappings()`. Startup compares that exact mapping with the approved
registry; there is no second generic mapping in application configuration.

The repository ships two implementations:

- HashiCorp Vault Transit pins every logical version to an explicit numeric
  Transit key version and invokes only
  `POST /v1/<mount>/hmac/<key>/sha2-256`. It never uses Vault's implicit latest
  version.
- AWS KMS maps each logical version to one immutable HMAC key ARN and invokes
  `GenerateMac` with `HMAC_SHA_256`. Aliases are rejected because they are
  mutable.

An application may supply a different implementation of the provider-neutral
interface.

Every production implementation must:

- keep at least 256-bit HMAC-SHA-256 keys non-exportable;
- resolve logical versions only through its immutable allowlist;
- accept exactly 32 bytes and return exactly 32 bytes;
- reject invalid input and unknown versions before transport;
- expose typed, content-free failures;
- retry only throttling and unavailable failures;
- enforce one total deadline, one bounded retry layer, and one concurrency
  cap;
- suppress request bodies and sensitive values from logs, traces, metrics,
  exceptions, and SDK diagnostics.

`INVALID_INPUT`, `AUTH_FAILED`, `THROTTLED`, `UNAVAILABLE`, `DEADLINE`,
`INTERRUPTED`, `UNKNOWN_VERSION`, and `INVALID_RESPONSE` remain distinct
reasons.
`AUTH_FAILED` deliberately combines invalid, expired, or revoked credentials
with insufficient policy because Vault returns HTTP 403 for both and error
bodies are not a safe classification surface.

For searchable low-entropy values the unsalted request digest is
candidate-testable and must be treated as plaintext-equivalent at the provider
boundary. Match-only digests include a fresh random salt but still remain
sensitive.

## Compile-time architecture

The processor uses standard JSR-269 APIs only. It does not modify compiler ASTs
and does not write into build-tool-owned generated-source directories outside
`Filer`.

Runtime reflection is allowed only once during startup to compare runtime
annotations with generated descriptors. No per-operation path discovers
fields, annotations, or accessors reflectively.

## Product modules

```text
pii-token-annotations/
pii-token-processor/
pii-token-spring-boot-starter/
pii-token-provider-vault/
pii-token-provider-kms/
pii-token-test/
```

Provider dependencies are isolated from the annotation processor and starter.
The Vault module uses the raw Transit HTTP API; the KMS module confines the AWS
SDK to that adapter. `pii-token-test` is test-support only and must not be added
to an application runtime classpath.

## Test strategy

The retained tests exist to protect this implementation:

- unit/property tests for normalization, framing, codecs, strict parsing,
  constant-time comparisons, call counts, staging, and failure atomicity;
- Java regression against `docs/golden-vectors/p1-n1.json`;
- annotation-processor compile/error tests;
- one clean independent Maven/Lombok consumer compilation and real
  Spring/Hibernate/PostgreSQL/HashiCorp Vault tokenization test, including
  explicit Transit numeric-version pinning across a provider key-version
  addition;
- LocalStack KMS request/response, key pinning, key-state, and golden-vector
  integration tests;
- real Spring Boot/Hibernate/PostgreSQL registry and JPA acceptance tests;
- concurrent Vault-adapter deadline/semaphore behavior under contention;
- leak canaries with positive controls;
- public-API and production-dependency scans.

## Version discipline

`p1/n1` is the current stored-data version for this implementation.

Any change to normalization, framing, hash/MAC construction, token grammar, or
accepted values must:

1. use a new protocol/normalizer or token-family version;
2. never reinterpret an existing stored token under new rules;
3. define an explicit operator-run migration or recollection plan; and
4. keep the old reader only for as long as stored data requires it.

Changes to tests, provider SDK wiring, or internal code that preserve all
specified bytes do not require a new token version.

The provider-independent security contract and operator procedures are
published in [`SECURITY.md`](../SECURITY.md) and
[`OPERATIONS.md`](OPERATIONS.md).
