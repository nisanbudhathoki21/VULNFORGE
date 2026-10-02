# Architecture state

Repository date: 2026-10-01  
Primary runtime: `vulnforge/`  
Public CLI: `vulnforge`  
Web dashboard: `vulnforge.dashboard:app`  
Store: `vulnforge.core.store.Store`

## Consolidated architecture

- One Python package namespace, scanner engine, SQLite store, CLI entry point, and package-owned web dashboard.
- The dashboard imports the canonical store and scanner orchestrator only. Persisted scan events are the source of truth; in-memory queues only wake SSE clients.
- One CLI provides scan, read-only stored scan views, report export, `lab`, and `dashboard` commands.
- Three organized synthetic training apps bind exclusively to loopback ports 9001, 9002, and 9003. No hidden vulnerability manifest is provided to the scanner.
- Historical source paths have been reviewed and retired. Existing database files are preserved in place and are not automatically reset or migrated.

## Implemented

- Staged scan orchestrator with persisted phase rows and JSON/HTML/Markdown/PDF reports.
- Central request path for authorization/scope checks, rate limit, budget, timeout, cancellation, bounded responses, and manually validated redirects.
- Static crawl, robots/sitemap intake, endpoint and parameter inventory, JavaScript static analysis, passive fingerprints, scan intelligence, and response-backed live-state classification.
- Configured read-only BOLA verification and paired open-redirect verification with independent evidence contracts and negative controls.
- CORS reflection and bounded SQL/parser-error behavior are observation-only. They cannot create confirmed findings.
- Versioned scan store with scan lifecycle, events, request/response exchange records, redaction, findings, evidence, and research objects.
- Package-owned dashboard for stored scans, scope, endpoint/parameter inventories, findings, verification state, evidence, test plan/results, controls, differentials, reports, HTTP details, filters, guarded Repeater, and persisted/live scan events.
- One `vulnforge` CLI for scanning and stored-data operations; a loopback-only local dashboard subcommand; three loopback-only training lab subcommands.

## Partial or unsupported

- Scope remains primarily host/scheme/port/path based; there is no general project/target scope-rule CRUD or generalized third-party boundary workflow.
- Discovery is limited to target DNS/system resolver, same-origin web observations, robots/sitemap, crawl-derived assets, and explicitly linked OpenAPI/Swagger documents. There is no general subdomain or port discovery.
- API/frontend/application models are evidence-backed inventories. HAR import and bounded navigation observations do not execute browser JavaScript or infer server-side authorization state.
- History stores prepared HTTP requests and parsed bounded responses, not raw packet/TLS capture. Sensitive history requires an explicit local opt-in.
- Differential views compare stored response status, headers, and bounded JSON/text bodies. They are observations, not vulnerability verdicts.
- BOLA confirmation requires user-supplied identities, assertions, resource/owner fields, and a sensitive field. Redirect confirmation is limited to a reserved marker and same-origin control with redirects not followed.
- CORS and SQL coverage is observation-only. Most vulnerability classes remain unsupported or not tested. No exploit template runtime or external scanner integration is shipped.
- No general multi-user organization mode, session vault, broad state-changing workflow runner, retest/resume checkpoint recovery, SARIF/JUnit/CI policy, or full legacy database migration.

## Evidence and safety limits

- Only checks with independent, repeatable security-property assertions may produce `VERIFIED` findings.
- Generic errors, reflected input, status/timing/size changes, technology matches, missing headers, or one SQL parser message are not enough to confirm exploitation or impact.
- Authorized scope, bounded requests, conservative methods, loopback-only labs, no arbitrary production data extraction, and no destructive testing remain enforced constraints.
- `resume` starts a new scan with a new ID; it is not checkpoint recovery. This limitation is disclosed by the CLI.

## Verification record

See `QUALITY_REPORT.md` for the final suite, CLI, packaged-wheel, lab vulnerable/patched, report, Store, and dashboard integration outcomes.
