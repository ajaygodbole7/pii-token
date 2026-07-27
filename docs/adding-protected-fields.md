# Adding Protected Fields

Two different tasks share this document. **Part 1** is for the application
developer: putting `@PII` on an entity field whose kind already exists (SSN,
PAN). **Part 2** is for the library maintainer: adding a new kind (for example
IBAN), which is a protocol change, not an application change.

**Product promise:** Add `@PII`; the library owns protection behavior and
generated persistence artifacts. The deployment still explicitly approves schema
and protection-policy changes.

## Part 1 — Annotating a field (existing kind)

### Once per application

These exist before the first `@PII` field and are not repeated per field:

1. Dependencies: the starter, the annotation processor on the compiler path,
   and exactly one provider module (Vault Transit or AWS KMS).
2. Provider wiring: Vault requires a `VaultTokenSupplier` plus `pii.vault.*`
   properties; KMS uses `pii.kms.*` properties and the AWS credential chain.
3. Registry provisioning (migration-owned): the `pii_security` schema, the
   policy row, and the key-version rows, created by a privileged migration
   identity. The application role receives SELECT only.
4. `pii.application-namespace`, and `pii.searchable-digests=permitted` if any
   field will be searchable.

### Per field

1. Add the annotation to a `String` field of a top-level `@Entity`:

   ```java
   @PII(id = "customer.ssn", kind = Kind.SSN, searchable = false, mask = Mask.LAST4)
   private String ssn;
   ```

2. If `mask = LAST4`, declare the companion column yourself
   (`private String ssnLast4;` with its `@Column`). The library maintains it;
   it does not create it.
3. Once per protected entity (not per field): extend the generated fragment in
   the repository interface
   (`interface CustomerRepository extends JpaRepository<...>, CustomerPiiRepositoryFragment`).
   Adding further protected fields to the same entity requires no new extension.
4. Size the column: `VARCHAR(160)` for the token and 4 characters for the
   suffix. Review and apply the changed field's generated DDL block under
   `META-INF/pii/migrations/fields/<descriptor-id>.sql`; do not rerun blocks
   for existing fields.
5. Review and apply the generated guarded policy update using the migration
   identity. The startup diagnostic and offline diagnostic command show the
   added/removed/altered descriptors, name the required field blocks, and emit
   the exact compare-and-set update. Approval is per deployment change set —
   several fields added together need one registry update, not one each.
   **The application will refuse to start until this is done.** This is
   deliberate: adding a protected field is a governed change, and the
   fail-closed startup gate is what makes the registry mean something.
6. If the column is already populated with plaintext, adding `@PII` does not
   migrate it — and ordinary "load and re-save" is **not possible**: the load
   hook rejects a non-token value before the entity can be loaded. Migrating a
   populated column requires an explicit strategy executed **before** the
   original column becomes protected. The supported approach is a side-by-side
   migration: add a new protected column while the old plaintext column remains
   unannotated, copy each value through managed entity writes, verify the new
   tokens, then delete and drop the plaintext column. The library has no public
   manual tokenization API for an in-place SQL batch. Plan this before changing
   the existing field annotation.

### What the developer never does

No crypto code, no service injection, no token handling, no provider calls, no
query construction against token columns. Compile-time errors (`PII001`–…)
reject unsupported shapes rather than degrading silently.

## Part 2 — Adding a new kind (protocol change)

Adding a kind is additive: existing tokens are unaffected (the kind id is bound
into the domain, so new-kind tokens can never collide with old ones). It is
still a protocol event and follows change control.

Prerequisite: the field passes both criteria in
[`field-suitability.md`](field-suitability.md) and has a **closed, public
grammar**, ideally with a checksum
(IBAN mod-97, SIN Luhn, ABA checksum). A kind without a strong grammar
(free-form account numbers, per-issuer licence formats) needs a design
decision first; do not add it by loosening validation.

Required changes:

1. **Grammar first.** Write the PROTOCOL.md section before any code: accepted
   textual forms, the exact normalization (what is stripped, what is rejected),
   checksum algorithm, normalized byte length, and the kind identifier string.
   If the grammar cannot be written down exactly, the kind is not ready.
2. **`Kind` enum constant** in `pii-token-annotations`.
3. **Normalizer arm** in `N1Normalizer` — the exhaustive switch will not
   compile until every kind is handled; implement validate-then-normalize,
   rejecting before any salt generation or provider call. Error messages carry
   reason codes only, never input content.
4. **Golden vectors.** Extend `docs/golden-vectors/p1-n1.json` with at least
   one searchable and one match-only vector for the new kind (inputs, domain,
   message, digest, MAC, final token), and extend `GoldenVectorTest`.
5. **Tests**: accepted forms including both boundary lengths, rejected forms
   (bad checksum, wrong length, wrong separators, embedded whitespace), and a
   LAST4 derivation check if the kind supports masking.
6. **Docs**: document the kind as supported in `field-suitability.md`.

The processor and codegen are kind-agnostic; they need no changes. The token
grammar, registry, and provider are untouched.

What adding a kind must never do (change control, PROTOCOL.md §10): alter an
existing kind's grammar or normalization, reinterpret existing tokens, or relax
validation to accommodate the new kind.
