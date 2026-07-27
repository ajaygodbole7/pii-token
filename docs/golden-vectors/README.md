# p1/n1 golden vectors

`p1-n1.json` is the byte-exact regression fixture for the current
[`p1/n1` protocol](../PROTOCOL.md) (protocol version 1, normalizer version 1).
Literal HMAC keys and salts are test-only inputs; using them in any deployed
system is prohibited.

`GoldenVectorTest` in `pii-token-spring-boot-starter` loads this file and
requires the production `P1N1TokenEngine` to reproduce normalization, domain
framing, message bytes, SHA-256 digests, HMAC-SHA-256 outputs, and final token
text for both records.

Run the focused regression with:

```bash
./mvnw -pl pii-token-spring-boot-starter -Dtest=GoldenVectorTest test
```

This fixture protects the stored-data format from silent refactor drift.
