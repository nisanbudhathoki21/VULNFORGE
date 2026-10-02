# Evidence model

## Current records

- HTTP exchanges persist prepared request/parsed response metadata and bodies under one `exchange_id`; values are redacted by default, while the loopback-only dashboard offers an explicit plaintext-cookie/auth opt-in per scan.
- Tests link to hypotheses and reference baseline/cross-identity exchange IDs.
- Findings carry evidence items with a test ID, summaries, security boundary, and response hashes for the implemented authorization verifier.
- Asset/application relationships identify observed source or researcher configuration.
- SQLite `evidence` rows link finding and test IDs; report data is redacted before persistence.

## Verified-state rule

Only findings with status `VERIFIED` and a matching `VERIFIED` test whose `finding_id` matches can enter `verified_findings`. A weak signal, scanner alert, response change, reflection, or legacy `confirmed` label does not satisfy this rule.

## Limitations

This is not yet the complete request → response → mutation → differential → identity/session → security property → impact evidence graph. The HTTP store uses paired exchange records, does not preserve exact wire bytes, has no general mutation/payload tables, and has no tamper-evident hash chain. Current response hashes support one narrow verifier and must not be represented as full evidence integrity.

## Extension requirements

Add stable IDs and foreign-key relationships before extending plugins. Preserve researcher-provided versus observed versus inferred provenance. Redact credentials and personal data by default. Require evidence validation before verified-state admission. Historical data must be adapted transparently, never silently promoted.
