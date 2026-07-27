# PII Token Protocol p1/n1 — Current Versioned Specification

**Status:** current `p1/n1` byte and registry specification for this
implementation. Existing stored tokens must never be silently reinterpreted.
A byte-incompatible change requires a new version plus an explicit
recollection or operator-run migration plan.

This document specifies the bytes used for irreversible searchable and match-only tokens and the canonical policy-registry schema, descriptor manifest, and fingerprint. It does not specify JPA integration, provider SDK wiring, or deployment-specific role names and physical business-column mappings.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**, and **MAY** are normative.

## 1. Profiles and fixed identifiers

| Name | Exact value | Meaning |
|---|---|---|
| Protocol profile id | ASCII `p1` | This byte construction |
| Normalizer version | integer `1` | The SSN/PAN normalizers in section 5 |
| Normalizer token segment | ASCII `n1` | Canonical text encoding of normalizer version 1 |
| Registry protocol profile | ASCII `p1/n1` | Exact profile implemented by this binary |
| Provider-operation version | ASCII `HMAC_SHA256_PREHASH_V1` | Provider accepts a 32-byte digest and returns HMAC-SHA-256 |
| Searchable token family | ASCII `b2` | Deterministic equality-search token |
| Match-only token family | ASCII `v2` | Random-salted verification token |
| Domain tag | ASCII `pii-tok\|1\|` | Protocol/domain-separation tag |

The token-family numbers are identifiers, not arithmetic values. Implementations MUST emit the exact lowercase strings shown.

A p1/n1 binary MUST compare the approved registry protocol profile with the exact compiled value `p1/n1` before opening its runtime gate. Application configuration MUST NOT select a different normalizer or protocol profile. An approved profile the running binary does not implement MUST fail startup closed.

## 2. Primitive encodings

All lengths count **bytes**, not Unicode code points or Java characters.

### 2.1 `u8`

`u8(x)` is one unsigned byte containing `x`. The permitted range is 0 through 255.

The searchability flag has exactly two encodings:

- match-only: `u8(0)` = `00`
- searchable: `u8(1)` = `01`

Every other value is invalid.

### 2.2 `u16`

`u16(x)` is exactly two bytes containing unsigned integer `x` in network byte order (big-endian), most significant byte first. The permitted range is 0 through 65535.

Examples:

| Value | Bytes |
|---:|---|
| 0 | `00 00` |
| 1 | `00 01` |
| 255 | `00 ff` |
| 256 | `01 00` |
| 65535 | `ff ff` |

The p1/n1 normalizer version is encoded in the domain as `u16(1)` = `00 01`.

### 2.3 `lp`

For a byte string `x`:

```text
lp(x) = u16(length_in_bytes(x)) || x
```

`x` MUST contain at most 65535 bytes. There is no terminator, padding, or alignment. The length prefix itself is not included in the encoded length.

### 2.4 Text

Unless a section says ASCII explicitly, text is encoded as strict UTF-8 without a byte-order mark. Invalid UTF-8, malformed surrogate input, Unicode replacement, Unicode normalization, case folding, trimming, and locale-sensitive conversion are prohibited.

All p1/n1 identifiers and normalized protected values are restricted to ASCII by their grammars, so their UTF-8 bytes are the corresponding single-byte ASCII values.

## 3. Identifier grammars and limits

Grammars are anchored: the entire value MUST match.

### 3.1 Application namespace

```regex
[a-z0-9.-]{3,64}
```

It is encoded as UTF-8 and supplied to the domain as `lp(appNamespace)`.

### 3.2 PII field id

```regex
[a-z0-9.-]{3,64}
```

It is the required `@PII.id`, unique within one deployment, encoded as UTF-8, and supplied as `lp(piiId)`.

Renaming either the application namespace or the PII field id changes every derived token. V1 does not migrate such a change in place.

### 3.3 Kind id

The only p1/n1 kind identifiers are:

```text
SSN
PAN
```

They are encoded as ASCII and supplied as `lp(kindId)`. Case variants and all other identifiers are invalid.

### 3.4 Logical key version

```regex
[a-z0-9][a-z0-9_-]{0,31}
```

The length is 1 through 32 ASCII bytes. The logical key version identifies an immutable, allowlisted provider key-version reference. It is stored in the token but is never used directly as a provider key reference.

A deployment MUST have exactly one `CURRENT` logical key version and MAY have up to three `READ_ONLY` logical key versions. Therefore the approved live set contains 1 through 4 versions. Zero live versions, more than four live versions, duplicate logical versions, multiple `CURRENT` versions, or a `CURRENT` version absent from the live set MUST fail startup closed.

This is a hard rollover ceiling; it provides no unlimited key-version history.
Irreversible rows cannot be re-keyed from stored token bytes. A deployment with
searchable fields MUST declare a maximum token lifetime and rollover cadence
and MUST demonstrate that its oldest version reaches zero stored rows before a
fifth live version would be required. The version cap MUST NOT be raised to
substitute for that lifecycle proof.

### 3.5 Normalizer segment

The general canonical grammar is:

```regex
n([1-9][0-9]{0,4})
```

The captured decimal integer MUST be between 1 and 65535 inclusive. Leading zeroes, `n0`, signs, whitespace, and values above 65535 are invalid. P1 accepts exactly `n1`.

## 4. Domain construction

The domain byte string is:

```text
domain =
    ASCII("pii-tok|1|")
    || u8(searchable)
    || lp(UTF8(appNamespace))
    || lp(UTF8(piiId))
    || lp(ASCII(kindId))
    || u16(normalizerVersion)
```

For p1/n1:

- `searchable` is 0 for match-only and 1 for searchable.
- `normalizerVersion` is integer 1.
- `appNamespace`, `piiId`, and `kindId` MUST already satisfy section 3.

The minimum domain length is 28 bytes and the maximum is 150 bytes. The library
MUST construct it as bytes; concatenating unframed text and then encoding the
result is invalid.

The field id, namespace, kind, searchability, and normalizer version are intentionally absent from the stored token. They are cryptographically bound through this domain instead.

## 5. Normalizer n1

Normalization is a pure deterministic function. It performs no network, database, locale, or clock access.

Common requirements:

- Input MUST be non-null when the normalizer is invoked.
- Leading or trailing whitespace is invalid.
- Only ASCII digits `0` through `9` and the explicitly permitted separators below are accepted.
- Unicode digits are invalid.
- Normalization removes only the permitted separators. It performs no other transformation.
- Validation and normalization MUST complete before salt generation or a provider call.
- Error messages MUST NOT contain the input, a substring, its normalized value, or its length.

Database-null semantics are outside the byte transform: a permitted Java/database `null` produces no token and no suffix and does not invoke the provider.

### 5.1 SSN n1

Accepted input is exactly one of:

```regex
[0-9]{9}
[0-9]{3}-[0-9]{2}-[0-9]{4}
```

The normalized output is the nine ASCII digits, with the two hyphens removed from the formatted form.

No spaces, other punctuation, alternate hyphen characters, or other hyphen placement is accepted. N1 validates structure only; it does not claim that an SSN was issued or belongs to a person.

The normalized SSN is exactly 9 bytes.

### 5.2 PAN n1

PAN input MUST pass both the textual grammar and Luhn validation.

An unformatted PAN is:

```regex
[0-9]{12,19}
```

A formatted PAN obeys all of these rules:

1. It contains exactly one separator type: ASCII space (`0x20`) or ASCII hyphen (`0x2d`), never both.
2. It has no leading, trailing, or adjacent separator.
3. Splitting on the separator produces 3 through 5 groups.
4. Every group except the last contains exactly four ASCII digits.
5. The last group contains one through four ASCII digits.
6. Concatenating the groups produces 12 through 19 digits.

After Luhn validation, this permits left-to-right four-digit display grouping such as:

```text
4111 1111 1111 1111
4111-1111-1111-1111
4222 2222 2222 2
4000-0000-0000-0000-006
```

It intentionally does not accept issuer-specific groupings such as 4-6-5; callers can supply the digits-only form for those PANs.

The normalized output is the concatenated ASCII digits.

Luhn validation is performed over the normalized digits:

1. Starting with the rightmost digit as position 0, traverse right to left.
2. Add digits at even positions unchanged.
3. Double digits at odd positions; if the result exceeds 9, subtract 9.
4. The total MUST be divisible by 10.

The normalized PAN is 12 through 19 bytes.

### 5.3 LAST4

`LAST4` is not an input to the token construction. When enabled, it is the final four digits of the normalized value and is stored separately as cleartext. It MUST be computed from the same normalized bytes used for the token in the same staged write.

## 6. Message and digest construction

### 6.1 Searchable

For a searchable field:

```text
message = lp(domain) || normalizedValue
digest  = SHA-256(message)
mac     = HMAC-SHA-256(K_keyVersion, digest)
```

There is no salt. For the same domain, normalized value, and key version, the token is deterministic.

The searchable message length is 39 through 171 bytes:

- `lp(domain)`: 30 through 152 bytes
- normalized SSN/PAN: 9 through 19 bytes

### 6.2 Match-only

After input validation succeeds, generate exactly 16 uniformly random bytes using a cryptographically secure random generator:

```text
salt128 = 16 random bytes
message = lp(domain) || salt128 || normalizedValue
digest  = SHA-256(message)
mac     = HMAC-SHA-256(K_keyVersion, digest)
```

A fresh salt MUST be generated for every new or replacement token. Salt reuse is prohibited. Retry logic MUST NOT persist a partial token; whether a retried logical write reuses a staged salt or restages the complete transform is an implementation concern, but exactly one complete token may commit.

The match-only message length is 55 through 187 bytes.

### 6.3 SHA-256

`SHA-256` is the function defined by [NIST FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final). Its output is exactly 32 bytes. `p1/n1` incorporates no future revision by reference. Any standards revision that changes these bytes requires a new protocol version under section 10.

The library computes SHA-256 locally over the exact message bytes. It sends only those 32 digest bytes to `TokenMacProvider.macDigest`.

For searchable low-entropy values, this unsalted digest is candidate-testable and MUST be treated as plaintext-equivalent sensitive data at the provider request boundary. It MUST NOT appear in logs, traces, metrics, proxies, or exception messages.

### 6.4 HMAC-SHA-256

`HMAC-SHA-256` is HMAC as defined by [RFC 2104](https://www.rfc-editor.org/rfc/rfc2104) and [NIST FIPS 198-1](https://csrc.nist.gov/pubs/fips/198-1/final) using SHA-256. NIST has proposed withdrawing FIPS 198-1 after publishing the final SP 800-224 successor; p1/n1 incorporates neither the draft nor an unknown future publication by reference. A successor that changes p1/n1 bytes requires a new protocol profile under section 10.

The provider receives exactly the 32 SHA-256 digest bytes as the HMAC message. The adapter MUST NOT call an SDK operation that hashes those bytes again before HMAC. The returned MAC MUST be exactly 32 bytes and MUST NOT be truncated.

The logical key version is resolved through the approved immutable mapping to one provider key version before the call. Caller-controlled token text MUST NOT become a provider key reference.

A provider call with a null logical version, null digest, or digest length other
than 32 bytes MUST fail locally with `INVALID_INPUT`. A syntactically valid but
unmapped logical version MUST fail locally with `UNKNOWN_VERSION`. Neither case
may reach the provider transport. A null, truncated, oversized, or otherwise
malformed provider result MUST fail with `INVALID_RESPONSE`; it MUST NOT be
retried or returned to the token engine.

The provider implementation owns exactly one bounded retry layer, one total
deadline, and one remote concurrency cap. `AUTH_FAILED`, `UNKNOWN_VERSION`,
`INVALID_INPUT`, `INVALID_RESPONSE`, `DEADLINE`, and `INTERRUPTED` are not
retryable. `INTERRUPTED` re-asserts the caller thread's interrupt flag.
`THROTTLED` and `UNAVAILABLE` are the only retry-eligible reasons, and retries
MUST stop at the configured maximum-attempt count or total deadline, whichever
occurs first. All failures and throwable chains remain content-free.

A production HMAC key MUST be generated from at least 256 bits of cryptographic entropy, MUST be non-exportable, and MUST be restricted to the provider operation required for HMAC-SHA-256. Literal or exportable keys are permitted only in published test-vector fixtures and MUST never be present in the production starter.

## 7. Stored token encoding

All token text is strict ASCII without whitespace or a terminator. Hexadecimal is lowercase.

```text
lowerhex32 = 32 lowercase hexadecimal characters  # 16 bytes
lowerhex64 = 64 lowercase hexadecimal characters  # 32 bytes

searchable = "b2." keyVersion "." normVersion "." lowerhex64
matchOnly  = "v2." keyVersion "." normVersion "." lowerhex32 "." lowerhex64
```

Where:

- `keyVersion` satisfies section 3.4.
- `normVersion` is exactly `n1` for p1/n1.
- searchable `lowerhex64` is the MAC.
- match-only `lowerhex32` is `salt128`.
- match-only final `lowerhex64` is the MAC.

Because p1/n1 accepts exactly the two-character normalizer segment `n1`, the
exact family lengths are:

| Family | Minimum length | Maximum length |
|---|---:|---:|
| `b2` | 72 | 103 |
| `v2` | 105 | 136 |

The maxima are derived as
`3 + 32 + 1 + 2 + 1 + 64 = 103` for `b2` and
`3 + 32 + 1 + 2 + 1 + 32 + 1 + 64 = 136` for `v2`, where `3` is the
family plus its following dot and `32` is the maximum key-version length.
A future profile that permits a longer normalizer segment must publish its own
family limits; p1/n1 parsers MUST NOT reserve or accept that future syntax.

The v1 database token column is `VARCHAR(160)`. A parser MUST reject input longer than 160 characters before splitting, regex matching, hex decoding, provider resolution, or other allocation proportional to attacker-controlled content. It MUST then enforce the tighter family-specific maximum.

An accepted token has exactly one textual encoding. Uppercase hex, leading/trailing whitespace, empty segments, extra segments, alternate family casing, padded normalizer numbers, or non-ASCII input are invalid.

## 8. Write, search, and match operations

### 8.1 Write

For a non-null value:

1. Resolve the generated descriptor and kind.
2. Validate and normalize under n1.
3. Construct the domain.
4. For match-only, generate the salt.
5. Construct the message and SHA-256 digest.
6. Resolve the one `CURRENT` logical key version through the approved immutable mapping.
7. Request HMAC-SHA-256 over the digest.
8. Encode the token canonically.
9. Stage token and optional LAST4 before mutating entity or persistence state.
10. Commit all protected-field outputs atomically with the business write.

Any failure aborts the entire write. Plaintext MUST NOT be stored as fallback.

### 8.2 Searchable equality

For one valid candidate:

1. Normalize once and construct the searchable domain and digest once.
2. Enumerate exactly the approved `CURRENT` plus `READ_ONLY` logical key versions.
3. Sort logical versions by ascending ASCII byte order.
4. Compute one searchable token per logical version.
5. Reject duplicate logical versions or duplicate output tokens.
6. Query with bounded `IN (:tokens)` semantics.

The token set contains 1 through 4 entries, so one search performs at most four provider MAC calls. V1 has one normalizer, so there is no key-by-normalizer cross-product. A normalizer change requires recollection into a new namespace.

### 8.3 Searchable verification

To verify a candidate against one stored searchable token:

1. Enforce the total-length and exact `b2` family bounds before splitting.
2. Parse and validate the exact canonical `b2` grammar.
3. Reject a key version outside the approved `CURRENT` plus `READ_ONLY` set
   before a provider call.
4. Reject a normalizer segment other than `n1` before a provider call.
5. Validate the candidate, compute the section 8.2 token set, and perform
   constant-time membership comparison against the stored token bytes.

The match-only `v2` parser is not reused, but searchable verification still
validates its own stored-token family. A malformed, wrong-family, or
unknown-version stored value is an error, not `NO_MATCH`. Equality search by
candidate (section 8.2) does not scan or parse unrelated stored rows; this
validation applies when one stored token is explicitly loaded for verification.
A malformed candidate raises the content-free `INVALID_VALUE` reason rather
than returning `NO_MATCH`.

### 8.4 Match-only verification

For a candidate and stored match-only token:

1. Enforce the total-length bound.
2. Parse and validate the exact `v2` grammar.
3. Reject a key version outside the approved `CURRENT` plus `READ_ONLY` set before a provider call.
4. Reject a normalizer segment other than `n1` before a provider call.
5. Validate and normalize the candidate.
6. Decode the 16-byte salt.
7. Reconstruct the domain, message, and digest.
8. Compute HMAC using the stored token's approved logical key version.
9. Compare the 32 MAC bytes in constant time.

The result is `MATCH` or `NO_MATCH` only for a candidate that passes frozen
kind validation. A malformed candidate raises the content-free `INVALID_VALUE`
reason. Malformed tokens, wrong token families, and unknown versions are
errors, not `NO_MATCH`.

### 8.5 Bounded new-write key rollover

Startup installs an immutable approved policy; p1/n1 does not poll or hot-reload
the registry. A running instance therefore continues using the policy snapshot
under which its runtime gate opened. A deployment MUST NOT introduce writes
under a new key until every serving instance can search both the old and new
key versions.

V1 bounded rollover uses two deployment stages:

1. **Expand.** Create the new immutable provider key version, add its logical
   mapping as `READ_ONLY`, and deploy the live set `{old CURRENT, new
   READ_ONLY}` without changing the write version. Wait until deployment
   evidence proves every serving instance uses that expanded live set.
2. **Promote.** In one registry migration, change the old version to
   `READ_ONLY` and the new version to `CURRENT`; then roll the deployment's
   current write version to the new key. During the bounded rollout, stage-one
   instances may still write the old key, but every old and new instance can
   search both versions. The old key MUST remain live until all such instances
   are drained and the section 11.1 retirement proof succeeds.

Skipping the expand-stage fleet convergence creates a search correctness gap
and is unsupported. A failed promotion rolls the registry and deployment write
version back together; immutable logical-to-provider mappings are never
rewritten. Descriptor, namespace, normalizer, provider, or key-set changes do
not use this key-only procedure.

Rollover changes the key for new writes only; it does not rewrite or
cryptographically remediate existing tokens. Token-key compromise requires a
new namespace and key set plus deletion or recollection from an
authorized external plaintext source. In-place token-to-token remediation
is impossible.

## 9. Fail-closed and leakage rules

Before any provider call, an implementation MUST reject:

- invalid candidate grammar;
- overlong or malformed token text;
- wrong token family;
- invalid or non-canonical hex;
- unknown or retired key version;
- normalizer other than n1;
- unapproved namespace, field id, kind, or searchability metadata;
- an approved registry protocol profile other than the binary's compiled `p1/n1`.

Exceptions, logs, metrics, and traces MUST NOT include:

- plaintext or normalized protected values;
- stored or generated tokens;
- salt or MAC segments;
- searchable request digests;
- LAST4 suffixes.

Errors use content-free typed reason codes. They MAY include documented non-sensitive descriptor ids or compiled profile identifiers, but MUST NOT interpolate attacker-controlled stored token segments or candidate content.

Provider access failure, throttling, unavailability, deadline, and
unknown-version failures remain distinct typed errors. `AUTH_FAILED`
intentionally does not distinguish invalid or expired credentials from
insufficient policy because supported providers may expose the same wire status
for both. Adapters MUST NOT inspect or retain provider error bodies to infer a
finer reason. There is no plaintext fallback and no local exportable-key
fallback.

## 10. Change control

The following changes alter protocol bytes or accepted values and require a new protocol/normalizer profile plus explicit migration or recollection:

- any primitive encoding;
- identifier encoding or grammar;
- domain tag, field order, or length prefix;
- kind identifier;
- SSN/PAN accepted grammar or normalized output;
- salt length or placement;
- hash or MAC algorithm;
- token family, segment order, or canonical text rules.

V1 does not run multiple normalizer versions concurrently. A normalizer change is recollection into a new application namespace, not a live cross-product and not a registry `RETIRED` transition.

A future profile MUST NOT reinterpret an existing `b2` or `v2` token under different byte rules. A byte-incompatible profile must use new token-family identifiers, or must operate only in a new namespace after complete recollection. Silent reinterpretation of stored tokens is prohibited.

Changing the provider implementation while preserving
`HMAC_SHA256_PREHASH_V1` does not change protocol bytes. The Java golden-vector
regression must continue to reproduce the same digest-to-HMAC results.

## 11. Policy registry

### 11.1 Normative DDL and authority boundary

The exact p1/n1 schema and table definitions are published in
[`docs/registry-schema.sql`](registry-schema.sql). The fixed `pii_security`
schema, two `CREATE TABLE` statements, constraints, and partial unique index
are normative. A deployment MUST NOT rename or reinterpret their columns while
claiming p1/n1 registry compatibility.

An approved migration identity creates and writes the registry. The application
runtime identity MUST have `SELECT` and MUST NOT have `INSERT`, `UPDATE`,
`DELETE`, `TRUNCATE`, ownership, or schema privileges that permit it to alter
either registry table. Role names, role creation, schema ownership, and exact
`GRANT` statements are deployment-owned because they differ across platforms;
the read-only runtime boundary is not optional.

`pii_security.pii_policy_registry` contains exactly one approved deployment
row, enforced by `id = 1`.
`pii_security.pii_key_version_registry` contains the immutable mapping from
logical versions to opaque provider references. The database partial unique
index and startup validation both enforce one `CURRENT` row per provider/key
set. Startup additionally enforces zero through three `READ_ONLY` rows, no
duplicate logical versions, and agreement with the configured approved
provider and key set.

The registry is comparison-only at application startup. All policy-row,
manifest, fingerprint, key-mapping, and key-state reads MUST occur in one
read-only PostgreSQL `REPEATABLE READ` transaction. A torn multi-statement
`READ COMMITTED` view is invalid. Missing rows, non-canonical manifests,
fingerprint mismatch, descriptor drift, profile drift, key mapping drift, or
transaction setup/commit failure fails startup closed before the runtime gate
opens.

Registry validation is a startup snapshot, not a lease or continuous
authorization check. Except for the two-stage key-only rollout in section 8.5,
a policy-registry change requires a coordinated deployment that prevents old
and new policy snapshots from concurrently writing protected fields. P1/n1
defines no mixed-descriptor epoch, hot reload, or automatic revocation of an
already-open runtime gate.

A logical key version MUST NOT move to `RETIRED` until every instance whose
approved snapshot can write or query that version is drained and an offline,
cache-bypassing inventory of every deployment-mapped protected column proves
that no stored `b2` or `v2` token references it. The logical manifest does not
contain physical column names, so the deployment migration supplies and reviews
that complete column list. If the proof cannot be produced, the version remains
`READ_ONLY`; retirement is not inferred from age or deployment completion.

### 11.2 Canonical descriptor manifest

The descriptor manifest is canonical UTF-8 without a byte-order mark. Every
allowed character is ASCII, so its UTF-8 bytes equal its ASCII bytes.

Each descriptor is exactly six fields:

```text
id "|" kind "|" searchable "|" mask "|" entityClassName "|" fieldName
```

The field grammars are:

| Field | Canonical grammar |
|---|---|
| `id` | `[a-z0-9.-]{3,64}` |
| `kind` | exactly `SSN` or `PAN` |
| `searchable` | exactly lowercase `true` or `false` |
| `mask` | exactly `NONE` or `LAST4` |
| `entityClassName` | `[A-Za-z_$][A-Za-z0-9_$]*(\.[A-Za-z_$][A-Za-z0-9_$]*)*` |
| `fieldName` | `[A-Za-z_$][A-Za-z0-9_$]*` |

The vertical bar (`0x7c`), carriage return (`0x0d`), and line feed (`0x0a`)
cannot occur inside any field because they are outside every field grammar.
There is no escaping mechanism. An encoder or decoder that encounters a value
outside these grammars MUST reject it rather than escape, replace, trim, or
normalize it.

Records are sorted by `id` in ascending unsigned ASCII-byte order and joined by
one line feed (`0x0a`). IDs MUST be unique. There is no leading or trailing line
feed and no blank line. The empty descriptor set has exactly one representation:
the zero-byte string.

`entityClassName` and `fieldName` are the logical Java mapping. Physical schema,
table, protected-column, and suffix-column names are deliberately absent and
remain deployment-migration inputs.

### 11.3 Descriptor fingerprint

The descriptor fingerprint is:

```text
descriptor_fingerprint =
    lowercase_hex(SHA-256(UTF8(descriptor_manifest)))
```

It is exactly 64 lowercase hexadecimal ASCII characters. SHA-256 is the
section 6.3 function, without HMAC, salt, prefix, terminator, or JSON
serialization.

Startup MUST first recompute the fingerprint of the stored manifest and compare
it with the stored `descriptor_fingerprint`. It MUST then encode the compiled
live descriptor set under section 11.2, fingerprint those exact bytes, and
compare the result with the approved stored fingerprint. This second comparison
covers all six logical fields, including the entity/field mapping.

Only after stored-manifest integrity and canonical decoding succeed may a
descriptor mismatch report added, removed, and attribute-level altered
descriptor metadata or emit a CAS-guarded proposed policy update. Manifest
integrity or canonical-decoding failures MUST NOT emit repair SQL. Production
startup remains fail-closed; there is no report-only runtime mode.

For the canonical two-record fixture:

```text
customer.pan|PAN|false|NONE|pii.slice.Customer|pan
customer.ssn|SSN|true|LAST4|pii.slice.Customer|ssn
```

the fingerprint is:

```text
8602d6bbac41b47b4ae93816ac876f126e15a41ac932dc09fec88b8538d76d51
```

The final record above has no trailing line feed.

## 12. Golden vectors

The retained fixture is
[`docs/golden-vectors/p1-n1.json`](golden-vectors/p1-n1.json). It records literal
inputs, test-only keys and salt, normalized values, domain bytes,
length-prefixed-domain bytes, full messages, SHA-256 digests, MACs, and final
tokens for searchable SSN and match-only PAN.

`GoldenVectorTest` in `pii-token-spring-boot-starter` loads that JSON and
requires `P1N1TokenEngine` to reproduce every intermediate byte and final
token. The vectors lock the implementation against accidental byte drift.
