# Testing model

## Current regression coverage

The pytest suite covers target normalization, centralized request/scope/budget behavior, crawler cancellation/error outcomes, emergency stop, passive intelligence/report persistence, loopback BOLA, CORS, and open-redirect verification, CORS allowlist and fixed-redirect negative controls, methodology cards, no-follow redirect behavior, redaction, canonical phases, schema versioning, guarded Repeater scope/consent/host-change checks, history/view/JSON-and-text diff, JSON OpenAPI/Swagger parsing, scope refusal for linked external schemas, unsupported YAML skip behavior, response-backed live-state classification, severity-profile registry selection, unsupported-class truthfulness, and legacy-status demotion.

Run:

```bash
python -m compileall -q vulnforge
python -m pytest -q
```

## Not yet covered

There is no per-class vulnerable/secure/adversarial fixture suite for XSS, SQLi, SSRF, traversal, file upload, CSRF, JWT/OAuth, WebSocket, business logic, or race conditions. CORS and open-redirect suites are intentionally narrow and do not validate downstream browser/user impact. There is no detection benchmark reporting true/false positives/negatives, precision, recall, or evidence completeness. Browser, dashboard, API, external adapter, real resume, retest, and performance suites do not exist yet.

## Gate for a new detector

Before enabling a vulnerability class, add a harmless loopback positive fixture, secure negative fixture, scanner-adversarial fixture, scope/budget/stop cases, redaction case, test/evidence linkage, independent verifier, and coverage label. Do not infer detector quality from one positive fixture or from alert count.
