# Field Suitability

This library applies **irreversible keyed tokenization**: a protected value can be
matched, deduplicated, verified, and optionally displayed as a last-four suffix,
but never recovered. Suitability is therefore not "is the field sensitive?" —
many sensitive fields (names, postal addresses) must be read back and cannot use
this library. A field is suitable only when it passes both criteria below.

## Suitability criteria

1. **One-way is acceptable.** The value is used for matching, deduplication, or
   verification, and never needs to be recovered or displayed in full (last-four
   display is the only supported partial view).
2. **The leakage is acceptable.** Searchable (`b2`) fields leak equality and
   frequency through the stored deterministic token. Their unsalted provider
   request digest is also candidate-testable without the HMAC key and must be
   treated as plaintext-equivalent. Match-only (`v2`) fields use a random salt,
   do not support equality search, and avoid deterministic stored tokens.

A field failing either criterion is out of scope. This restates the design's
boundary rule: if losing the original value would create a business, legal, or
operational incident, the field must not use this library.

## Supported kinds

Version 1 accepts exactly two kinds:

| Kind | Modes | Conditions |
|---|---|---|
| SSN | searchable or match-only; optional LAST4 | Searchable mode requires explicit acceptance of provider-boundary digest exposure and equality/frequency leakage. |
| PAN | searchable or match-only; optional LAST4 | Not for payment authorization or any workflow that must recover or display the PAN. Using this library does not by itself establish PCI DSS compliance. |

Every other field is rejected. Supporting another identifier requires a new
`Kind`, a closed grammar, a normalizer, validation rules, protocol
documentation, and golden vectors. There is no generic identifier mode.

## Common exclusions

| Category | Reason |
|---|---|
| Names, addresses, email addresses, phone numbers | Applications normally need to read or use the original value. |
| Dates of birth, postcodes, demographic categories | Small domains make searchable digests easy to enumerate; these values also commonly require display. |
| Passwords | Require a memory-hard password hash such as Argon2id or bcrypt. |
| Biometric templates | Require fuzzy matching. This library performs exact-equality only. |
| CVV/CVC and other sensitive authentication data | Storage is prohibited after authorization; do not tokenize it here. |
| Values needing range, prefix, substring, analytics, or fuzzy queries | The library supports exact match and equality only. |

Default to match-only. Enable search only for a documented equality-search
requirement after accepting both leakage channels.
