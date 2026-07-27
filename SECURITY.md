# Security Contract

This library irreversibly tokenizes SSN and PAN fields on the supported
Spring Data JPA/Hibernate/PostgreSQL path. It has no decrypt, recover, raw-key,
or generic `protect()` API.

This document defines the security boundary of the current implementation. It
does not claim that using the library makes an application or deployment
compliant with any law, regulation, or payment-card standard.

## Reporting a vulnerability

Do not include real PII, PANs, tokens, credentials, or key references in a
report. Use GitHub private vulnerability reporting for the published
repository. If that channel is unavailable, open a minimal issue requesting a
private contact channel without including vulnerability details.

## Appropriate use

Use this library only when all of the following are true:

- the original value is not needed after the write;
- replacement, equality search, match, LAST4 display, and deletion are
  sufficient business operations;
- the protected column is written only through managed Hibernate operations
  or generated repository methods;
- one application deployment owns one namespace, one provider, and one
  logical key set;
- the application can fail closed when the provider or registry is
  unavailable; and
- the deployment can recollect values after a token-key compromise if continued
  use is required.

Do not use it for:

- payment authorization or any workflow that must recover a PAN;
- card verification values or other sensitive authentication data;
- fields whose loss would prevent a legal, customer-service, or operational
  obligation;
- native SQL, raw JDBC, bulk DML, R2DBC, ETL, stored-procedure, or other
  alternate write paths;
- multi-provider or multi-tenant routing; or
- data that needs range, prefix, substring, fuzzy, or analytical queries.

## Security properties

On a successfully validated managed write:

- plaintext is validated and normalized before provider work;
- token and optional LAST4 are fully staged before entity mutation;
- plaintext is replaced in the managed entity before SQL binding;
- provider failure leaves no partial token/suffix mutation;
- the runtime gate stays closed until the generated model, deployment
  configuration, registry snapshot, provider identity, and key states agree;
- the application database identity reads but cannot modify the registry; and
- malformed stored tokens fail before provider work on generated match/search
  operations.

The token column is not ciphertext. It cannot be decrypted. A match-only token
is randomized; a searchable token deliberately reveals equality within one
field domain and key version.

## Sensitive values

Treat every item below as sensitive:

| Value | Required handling |
|---|---|
| Presented or normalized SSN/PAN | Plaintext PII/PAN |
| Searchable request digest | Plaintext-equivalent for low-entropy SSN/PAN |
| Match-only request digest | Sensitive even though it contains a random salt |
| Stored `b2`/`v2` token | Sensitive pseudonymous data |
| Salt or MAC segment | Sensitive token material |
| LAST4 suffix | Sensitive display data |
| Provider opaque key reference | Sensitive configuration, never key material |

Tokens are candidate-testable by an identity that can invoke the HMAC key.
Tokenization reduces plaintext exposure; it does not make the database,
backups, caches, exports, or logs public data.

## Boundaries the library cannot enforce

- A native or alternate writer can place plaintext directly in the token
  column. Managed entity loading rejects plaintext and malformed token
  structure without a provider call, but it cannot authenticate a
  forged-but-canonical token.
- An entity contains its stored token after save/reload. The library does not
  prevent JSON serialization, DTO copying, debugger display, heap dumps, or
  application logging of that field.
- Parsed protocol holders remain package-private, have redacted `toString()`
  implementations, and are never handed to a generic mapper by library code.
  This is an internal containment measure, not a substitute for the supported
  entity serializer boundary.
- The library checks Hibernate bind logging at startup only. A privileged
  runtime log-level change can enable leaking diagnostics afterward.
- The library cannot inspect provider SDK, HTTP client, service-mesh, proxy,
  APM, packet-capture, or cloud-side request logging.
- The registry is an immutable startup snapshot, not continuous authorization
  or revocation.
- Database encryption, backups, retention, access control, and deletion
  propagation remain deployment responsibilities.

## Required deployment controls

### Application

- Enable `pii.jackson-suppression-enabled=true` when using the supported
  Jackson 3 mapper. For every other serializer, exclude protected entity
  fields from API serialization and logs. Return only explicitly approved
  suffix fields.
- Do not include candidate values, normalized values, tokens, suffixes, or
  provider digests in exceptions, metrics, traces, audit events, or message
  attributes.
- Keep `org.hibernate.orm.jdbc.bind` below `TRACE`. Prevent dynamic log-level
  changes from raising it after startup.
- Disable SQL/bind inspection in JDBC proxies and APM agents.
- Disable heap dumps and automatic request capture on processes handling
  plaintext unless access and retention are explicitly controlled.
- Set `pii.searchable-digests=permitted` only when equality search is required
  and provider-boundary digest exposure has been accepted.

### Database

- Use a migration identity to own and modify registry and business tables.
- Give the runtime identity `USAGE` on `pii_security` and `SELECT` only on
  `pii_security.pii_policy_registry` and
  `pii_security.pii_key_version_registry`.
- Ensure the runtime identity cannot gain registry writes through table
  ownership, schema ownership, `PUBLIC`, inherited roles, or stored
  procedures.
- Inventory every physical protected and suffix column. Prevent alternate
  writer identities from writing those columns.
- Apply only descriptor blocks named by the drift diagnostic from
  `META-INF/pii/migrations/fields/`, then apply the CAS-guarded policy update
  from `META-INF/pii/owner-migration-template.sql` through the migration
  identity. The library never executes this SQL.
- Treat tokens and suffixes as sensitive in backups, replicas, CDC, support
  exports, and query tooling.

### Provider

- Generate HMAC-SHA-256 keys from at least 256 bits of cryptographic entropy.
- Keep keys non-exportable and restrict the application identity to the
  required MAC operation and exact key versions.
- Map logical versions through an immutable allowlist. Never accept a provider
  key reference from token text or candidate input.
- Reject null/invalid digests and unknown logical versions before transport.
- MAC exactly the supplied 32-byte digest; do not hash it again.
- Return exactly 32 bytes.
- Use one bounded retry layer, one total deadline, and one concurrency cap.
  Retry only throttling and unavailability.
- Disable request/response bodies, headers containing sensitive context, and
  SDK wire logging.
- Emit only safe operation count, latency, throttle, availability, and access
  failure signals.

For the HashiCorp Vault Transit adapter:

- pin every logical version to an explicit numeric Transit `key_version`;
  implicit latest-version operation is forbidden;
- create an HMAC-only key with `exportable=false` and
  `allow_plaintext_backup=false`;
- grant the runtime identity `update` only on the exact
  `transit/hmac/<key>/sha2-256` path;
- use TLS in production; insecure HTTP is test-only; and
- keep root/admin tokens out of the application. They may be used only by
  operator-controlled bootstrap and bounded-rollover procedures.

For the AWS KMS adapter:

- use one `HMAC_256` key per logical version and configure its full immutable
  key ARN; aliases are forbidden;
- grant the runtime identity `kms:GenerateMac` only on the configured key ARNs;
- keep key creation, policy changes, disablement, and deletion outside the
  application identity; and
- keep SDK wire logging disabled. LocalStack is an integration-test emulator,
  not evidence of AWS IAM enforcement.

## Failure behavior

Provider, registry, validation, protocol, or startup failure must never fall
back to plaintext persistence, a local exportable key, a different key
version, or an unprotected query. The supported response is to fail the
operation or keep the application unavailable.

Descriptor-drift diagnostics may expose only canonical descriptor metadata,
fingerprints, generated artifact paths, and guarded migration SQL. They never
contain presented values, tokens, salts, MACs, credentials, provider content,
or database error text. Registry manifest integrity/decoding failures emit a
reason only and never repair SQL.

Provider errors expose only the typed reasons `INVALID_INPUT`, `AUTH_FAILED`,
`THROTTLED`, `UNAVAILABLE`, `DEADLINE`, `INTERRUPTED`, `UNKNOWN_VERSION`, and
`INVALID_RESPONSE`.

- `INTERRUPTED` is distinct from deadline expiry; the adapter re-asserts the
  caller thread's interrupt flag.
- `AUTH_FAILED` combines invalid, expired, or revoked credentials with
  insufficient policy when the provider does not distinguish them on the wire.
- Adapters never parse provider error bodies to guess a finer classification.

## Incident assumptions

A compromised HMAC key or provider identity permits candidate testing of
tokens. Because this product stores no recoverable envelope, existing tokens
cannot be transformed safely into a new namespace or key without an
authorized plaintext source. The response is containment followed by
recollection or deletion, not token-to-token migration.

Use the procedures in
[`docs/OPERATIONS.md`](docs/OPERATIONS.md) for baseline updates, bounded
new-write key rollover, retirement, writer inventory, and incidents.
