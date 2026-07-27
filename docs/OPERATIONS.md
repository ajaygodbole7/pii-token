# Operations Runbook

This runbook applies to the supported `p1/n1` deployment described in
[`DESIGN.md`](DESIGN.md). Commands and SQL use placeholders; bind values or
review quoted identifiers instead of concatenating untrusted text.

## Release checklist

Before deploying:

1. With Docker available, run `./mvnw clean verify`. Testcontainers starts the
   pinned PostgreSQL, Vault, and LocalStack images; Failsafe fails `verify` if
   a live-provider contract breaks.
2. Run `./tools/verify-compatibility.sh`.
3. Confirm the application artifact contains:
   - `META-INF/pii/processor-marker.txt`;
   - `META-INF/pii/descriptor-manifest.txt`;
   - `META-INF/pii/descriptor-fingerprint.txt`;
   - `META-INF/pii/owner-migration-template.sql`; and
   - one `META-INF/pii/migrations/fields/<descriptor-id>.sql` resource per
     protected field.
4. Compare the artifact manifest and fingerprint with the proposed registry
   migration.
5. Confirm the application namespace and the provider's reported
   logical-to-opaque key mappings are identical to the registry.
6. Confirm exactly one key is `CURRENT` and no more than three are
   `READ_ONLY`.
7. Confirm `pii.searchable-digests` is `prohibited` unless the artifact has an
   intentionally searchable field and the deployment permits its
   plaintext-equivalent provider digest.
8. Confirm Hibernate bind logging, JDBC inspection, provider wire logging,
   proxy body logging, and APM request capture are disabled.
9. Confirm only managed Hibernate and generated repository paths can write
   protected columns.
10. For every searchable field, record the maximum token lifetime and rollover
    cadence and prove the oldest version reaches zero rows before a fifth live
    version would be required.
11. Start one instance and require a successful runtime-gate opening before
    rolling the rest of the deployment.

Never weaken the registry, change an annotation, or enable a fallback merely
to make startup pass.

## HashiCorp Vault Transit

The Vault adapter lives in `pii-token-provider-vault`. It uses the raw
Transit HTTP API and does not create keys, policies, tokens, or mounts at
runtime.

Create an HMAC-only key as an operator. Keep key export and plaintext backup
disabled:

```text
vault secrets enable transit
vault write transit/keys/pii-token \
  type=hmac key_size=32 exportable=false allow_plaintext_backup=false
```

The application identity needs only:

```hcl
path "transit/hmac/pii-token/sha2-256" {
  capabilities = ["update"]
}
```

Do not grant the runtime identity access to `transit/keys`, key rollover,
backup, restore, export, or policy administration. Root tokens are permitted
only in the disposable dev-mode E2E bootstrap and must never be supplied to
the application.

Example deployment configuration:

```yaml
pii:
  application-namespace: bank.cards
  searchable-digests: permitted
  vault:
    address: https://vault.example.internal:8200
    mount: transit
    key-name: pii-token
    key-set-id: bank-cards-2026
    current-version: k2
    versions:
      k1: 1
      k2: 2
    total-deadline: 3s
    retry-delay: 25ms
    max-attempts: 2
    max-concurrency: 32
```

Supply a `VaultTokenSupplier` bean backed by the deployment's workload
identity or token-renewal mechanism. It must be non-blocking and must not log
the token. The default client uses the JVM TLS trust configuration. If the
deployment needs a private CA, mTLS, or an HTTP proxy, construct
`VaultTransitTokenMacProvider` with an application-owned `HttpClient`; the
auto-configuration backs off when the application supplies its own
`TokenMacProvider`.

`pii.vault.allow-insecure-http=true` exists only for disposable local/dev
tests. Production configuration must use HTTPS.

Each entry under `versions` is a permanent logical-to-numeric mapping. Vault
supports an explicit `key_version` on Transit HMAC requests, and the adapter
sends it on every call. Never renumber or repoint an existing logical version.
Do not raise Vault's `min_encryption_version` above a `READ_ONLY` version while
any stored row still uses that version.

## AWS KMS HMAC

The optional `pii-token-provider-kms` module uses AWS KMS `GenerateMac`. Create
one `HMAC_256` key with `GENERATE_VERIFY_MAC` usage per logical version and
grant the runtime identity `kms:GenerateMac` only on the exact live key ARNs.
Do not grant key administration or alias mutation.

Map every logical version directly to a full key ARN. KMS aliases are mutable
and are rejected by the adapter. Adding a key creates a new logical version;
never repoint an existing logical version. Configuration and LocalStack
fidelity limits are documented in
[`pii-token-provider-kms/README.md`](../pii-token-provider-kms/README.md).

## Registry roles

Create and populate the registry as the migration identity. Then remove
runtime write authority:

```sql
REVOKE ALL ON TABLE pii_security.pii_policy_registry FROM <runtime_role>;
REVOKE ALL ON TABLE pii_security.pii_key_version_registry FROM <runtime_role>;
GRANT USAGE ON SCHEMA pii_security TO <runtime_role>;
GRANT SELECT ON TABLE pii_security.pii_policy_registry TO <runtime_role>;
GRANT SELECT ON TABLE pii_security.pii_key_version_registry TO <runtime_role>;
```

Also verify that `<runtime_role>`:

- does not own either table or their schema;
- has no write privilege through `PUBLIC` or inherited roles;
- cannot execute a security-definer routine that changes the registry; and
- cannot change role to the migration identity.

The application startup test must use the runtime identity, not the migration
identity.

## Baseline update

The annotation processor writes the canonical manifest and its fingerprint
into the application artifact. Use those bytes directly; do not reconstruct
the manifest by hand.

For a Spring Boot executable JAR they normally reside under:

```text
BOOT-INF/classes/META-INF/pii/descriptor-manifest.txt
BOOT-INF/classes/META-INF/pii/descriptor-fingerprint.txt
```

For an ordinary classes directory or library JAR they reside under:

```text
META-INF/pii/descriptor-manifest.txt
META-INF/pii/descriptor-fingerprint.txt
META-INF/pii/owner-migration-template.sql
META-INF/pii/migrations/fields/<descriptor-id>.sql
```

Procedure:

1. Build and test the exact deployment artifact.
2. Run the offline diagnostic command against the compiled artifact and the
   approved registry. It exits nonzero while drift exists, prints only
   descriptor metadata, and never starts the application or writes the
   registry:

   ```text
   PII_REGISTRY_PASSWORD=<password> java -cp <application-runtime-classpath> \
     io.github.ajaygodbole7.piitoken.runtime.PiiRegistryDiagnosticCommand \
     <compiled-classes-or-jar> <jdbc-url> <select-only-registry-user>
   ```

3. Review the descriptor diff:
   - an `id`, kind, or `searchable` change alters the token domain and requires
     a new namespace plus recollection;
   - adding `LAST4` affects future replacements only; old irreversible rows
     cannot be backfilled without plaintext;
   - an entity/field mapping change requires a coordinated application and
     database migration.
4. For each block named by the diagnostic, replace its physical-name
   placeholders, review its token-family, suffix-coupling, length, and index
   DDL, and apply it through the migration identity. Do not rerun blocks for
   existing fields.
5. In the same migration transaction, apply the exact CAS-guarded policy
   update printed by the diagnostic. Require exactly one affected row.
6. Rerun the diagnostic and require exit code zero (`DESCRIPTOR_MATCH`).
7. Deploy all instances that use the new descriptor snapshot as one
   coordinated change. There is no mixed-descriptor compatibility epoch.
8. Require startup success, then verify token grammar and leak canaries.

Do not change the stored fingerprint without changing the manifest to the
exact artifact bytes. Do not use a baseline update to authorize a protocol,
provider-operation, namespace, or key mapping the binary does not implement.
`MANIFEST_INTEGRITY` and `MANIFEST_INVALID` never produce repair SQL; restore a
known-good registry migration instead.

## Writer inventory

Maintain a deployment-controlled inventory with, for every protected field:

- application and entity;
- physical schema, table, token column, and optional suffix column;
- expected token family (`b2` or `v2`);
- every database role, service, batch job, import, CDC consumer, and procedure
  capable of writing the table; and
- the generated replacement/search/match methods used by the application.

Before release and key retirement, scan every physical token column with a
cache-bypassing database query. For a searchable column, non-null values must
match:

```regex
^b2\.[a-z0-9][a-z0-9_-]{0,31}\.n1\.[0-9a-f]{64}$
```

For a match-only column:

```regex
^v2\.[a-z0-9][a-z0-9_-]{0,31}\.n1\.[0-9a-f]{32}\.[0-9a-f]{64}$
```

Example PostgreSQL check:

```sql
SELECT <primary_key>, <token_column>
  FROM <schema>.<table>
 WHERE <token_column> IS NOT NULL
   AND <token_column> !~ <expected_family_regex>;
```

Any row returned is an incident. Managed entity loading now fails closed on
plaintext and malformed token structure without a provider call. It does not
authenticate a forged-but-canonical token, so quarantine and investigate every
row found by the inventory.

## Bounded new-write key rollover

Rollover changes the key used for new writes while keeping old rows queryable.
It does not rewrite existing rows and cannot be repeated indefinitely.

Before starting a rollover, the deployment record must state:

- the maximum token lifetime for every searchable field;
- the planned rollover cadence and safety margin;
- the current per-version row counts across the complete writer inventory; and
- why the oldest version will reach zero rows before adding a fifth live
  version would be necessary.

If the proof cannot be produced, do not begin the rollover. Do not raise the
four-version cap.

### Stage 1: expand readers

1. Create a new non-exportable provider key version.
2. Add a new immutable registry mapping as `READ_ONLY`.
3. Add the new immutable provider mapping: a numeric Vault key version or a
   KMS key ARN. Its derived opaque mapping must match the registry.
4. Keep the old version `CURRENT`.
5. Deploy every instance.
6. Prove every serving instance started with the expanded live set.

No instance writes under the new key during this stage.

### Stage 2: promote writers

1. In one migration, change the old version to `READ_ONLY` and the new version
   to `CURRENT`.
2. Change the provider implementation's reported current version to the new
   logical version.
3. Roll the deployment.
4. During the rollout, keep both versions live. Old instances can still write
   the old version and all instances can search both.
5. Verify new writes use the new version and searches find rows under both.

If promotion fails, restore the registry and deployment current version
together. Never repoint an existing logical version to a different provider
key.

## Key-version retirement

Do not retire a logical version based on age or rollout completion.

1. Drain every instance whose immutable startup snapshot includes the old
   version.
2. Run the writer inventory against every protected column.
3. For each canonical token column, count the exact logical version:

```sql
SELECT count(*)
  FROM <schema>.<table>
 WHERE <token_column> IS NOT NULL
   AND split_part(<token_column>, '.', 2) = :logical_version;
```

4. Bypass application and second-level caches.
5. Require zero rows across the complete inventory.
6. Mark the registry version `RETIRED`, remove it from the provider
   configuration, deploy, and only then disable or destroy the provider key
   according to the provider retention policy.

If the inventory is incomplete or any count is non-zero, keep the version
`READ_ONLY`.

## Incident response

### Plaintext or malformed value in a token column

1. Stop the alternate writer and quarantine the affected rows.
2. Confirm managed entity loading fails closed, and prevent all other readers
   from loading the affected rows.
3. Search logs, traces, CDC, backups, exports, and caches for the planted
   value.
4. Delete the row or replace it through the generated API using a trusted
   plaintext source.
5. Re-run the complete writer inventory before restoring service.

Never feed a stored malformed value back through a replacement API as though
it were plaintext.

### Provider unavailable, throttled, or over deadline

1. Keep writes and protected queries failed closed.
2. Check provider availability and the configured bounded concurrency, total
   deadline, and retry behavior.
3. Retry only `THROTTLED` and `UNAVAILABLE` within the provider adapter's one
   retry layer.
4. Do not use a local key, a different key version, plaintext persistence, or
   an unprotected query as a fallback.

### Provider access failure

1. Keep the runtime failed closed.
2. Verify identity, key-version permissions, and logical-to-opaque mappings
   without logging digests or key references.
3. Treat unexpected identity or policy changes as a possible security
   incident. `AUTH_FAILED` does not distinguish the two because the provider's
   wire status may not distinguish them.
4. Restore least privilege; do not broaden access to all provider keys.

### Registry drift or integrity failure

1. Keep the application unavailable.
2. Compare the deployed artifact manifest/fingerprint, application
   configuration, provider metadata, and registry snapshot.
3. Restore the last known correct migration or deploy the artifact intended
   for the new baseline.
4. Never edit one field merely to satisfy the startup error.

### HMAC key or provider identity compromise

1. Disable the compromised identity and contain provider access.
2. Assume an attacker can candidate-test stored tokens, especially searchable
   SSN/PAN tokens.
3. Preserve evidence without recording plaintext, digests, tokens, or key
   material in the incident system.
4. Create a new application namespace and new non-exportable key set.
5. Recollect from an authorized plaintext source into the new namespace,
   or delete the affected data.
6. Do not attempt token-to-token migration. Existing irreversible tokens
   contain no source value.

### Diagnostic leak

1. Disable the leaking logger, agent, proxy, SDK diagnostic, or trace export.
2. Restrict and purge retained diagnostic data under the deployment's incident
   and retention policy.
3. Rotate credentials used to access the provider or database when their
   exposure cannot be excluded.
4. A token-key rollover does not remediate exposed plaintext or searchable
   digests.

## Recollection

Recollection is a business process, not a cryptographic transform:

1. Define a new namespace and key set.
2. Create a separate baseline for the new namespace.
3. Obtain the original value again from an authorized source.
4. Validate and write it through the generated managed path.
5. Verify the new stored token and optional suffix.
6. Delete the old token only after the replacement is durable and business
   reconciliation succeeds.

If no authorized plaintext source exists, the old token cannot be migrated.
