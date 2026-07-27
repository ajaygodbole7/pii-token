# AWS KMS HMAC provider

`pii-token-provider-kms` is an optional `TokenMacProvider` backed by AWS KMS
HMAC keys. It receives only the library's 32-byte SHA-256 digest and invokes
`GenerateMac` with `HMAC_SHA_256`. It never receives the normalized SSN or PAN,
does not pre-process or hash the digest again, and requires the full 32-byte MAC
response.

## Version model

Use one KMS key per logical token version. The mapping is an immutable
allowlist from logical version to full key ARN:

```yaml
pii:
  kms:
    enabled: true
    region: us-east-1
    key-set-id: customer-identifiers
    current-version: k2
    key-arns:
      k1: arn:aws:kms:us-east-1:123456789012:key/11111111-1111-1111-1111-111111111111
      k2: arn:aws:kms:us-east-1:123456789012:key/22222222-2222-2222-2222-222222222222
```

Aliases are rejected because their targets are mutable. The current version
must be in the live map, ARNs must be unique, and at most four live versions
are accepted. A new-write rollover adds a new KMS key and makes its logical
version current; it never changes the key behind an existing logical version.

Create production keys with key spec `HMAC_256`, key usage
`GENERATE_VERIFY_MAC`, and origin `AWS_KMS`. Grant the runtime identity only
`kms:GenerateMac` on the exact live key ARNs. Do not grant alias mutation, key
administration, scheduling deletion, or imported-key-material operations.

## Runtime behavior

The auto-configuration is active only when `pii.kms.enabled=true` and no other
`TokenMacProvider` bean exists. Exactly one provider module may be active in a
deployment. Do not activate the Vault and KMS providers together.

The owned AWS SDK v2 client uses the configured region, the SDK default
credential chain, one total API timeout, and exactly one SDK attempt (zero SDK
retries). The adapter itself owns the fair concurrency semaphore and at most
one bounded retry by default. An application-supplied `KmsClient` is accepted
only when its observable retry strategy also has exactly one attempt; the
adapter does not close that client. The adapter closes a client it created.

Provider failures expose only shared content-free reason codes. KMS
`NotFoundException`, disabled keys, pending-deletion/invalid key state, and
unavailable keys map to `UNAVAILABLE` and are non-retryable inside this
adapter. The shared starter contract intentionally has no separate
`KEY_STATE` reason, and this module does not change that contract.

## LocalStack fidelity

Failsafe runs the module integration tests against the exact
`localstack/localstack:4.14.0` image. The emulator is test-only and must never
be deployed as a production KMS substitute.

The integration suite proves real request/response framing, deterministic
HMACs, distinct keys, key-per-version rollover, full 32-byte MACs, response
key-ARN matching, disabled-key failure, and byte-exact reproduction of the
published `docs/golden-vectors/p1-n1.json` MAC using imported test key
material.

LocalStack does not enforce AWS IAM. `AUTH_FAILED` mapping is covered by unit
tests against real AWS SDK exception types, not by a fabricated LocalStack
authentication test. The emulator also does not prove AWS HSM custody, quotas,
latency, availability, policy evaluation, or incident behavior. Production
acceptance still requires a narrowly scoped AWS identity and real AWS KMS.
