# VULNFORGE quality and consolidation report

**Validation date:** 2026-10-01  
**Source version:** 0.4.0  
**Test environment:** Python 3.13, clean `.venv-final`, installed `.[dashboard,dev]` dependencies  
**Scope:** repository consolidation, scanner behavior, training labs, reports/store, dashboard API/UI, package build, and final source-archive hygiene.

## Executive outcome

The repository now has one canonical application package (`vulnforge/`), one active engine, one Store/data layer, one public command (`vulnforge`), one dashboard (`vulnforge.dashboard` with package-owned assets), and three organized loopback-only training apps under `labs/`. Duplicate root scanner/database code and the separate historical `VulnForge_Ultimate/` runtime have been audited and retired after their reusable dashboard/Reapter/report behavior and safe test intent were reviewed. The existing workspace database files were preserved; no destructive migration or reset was performed.

## Validation results

| Check | Result |
|---|---|
| Full suite: `python -m pytest -q` | **185 passed in 49.73s; zero failures, zero warnings** |
| `git diff --check` | Passed |
| `python -m compileall -q vulnforge labs server.py` | Passed |
| `node --check vulnforge/dashboard_static/app.js` | Passed |
| `node --check vulnforge/dashboard_static/traffic_inspector.js` | Passed |
| Example JSON and versioned report schema parsing | Passed |
| Source import/reference scan for root `engine`, root `database`, `VulnForge_Ultimate`, and `vulnforge2` | No active Python imports found |
| Installed wheel entry points | Exactly one: `vulnforge = vulnforge.cli:main` |
| Installed wheel contents | Canonical package, dashboard assets, and lab runtime present; duplicate app trees and test package excluded |

## Vulnerable and patched lab outcomes

End-to-end CLI smoke scans were run against all three vulnerable apps and their paired patched controls, using the normal scanner flow and only the explicit sample identity configuration. No expected-vulnerability manifest was passed to the scanner.

| Lab | Vulnerable variant | Patched variant | Interpretation |
|---|---:|---:|---|
| Critical, port 9001 | 1 verified finding | 0 verified findings | Configured two-identity, read-only BOLA boundary comparison. |
| High, port 9002 | 1 verified finding | 0 verified findings | Configured tenant/object BOLA comparison; SQL parser behavior remains candidate/observation-only. |
| Medium, port 9003 | 1 verified finding | 0 verified findings | Paired open-redirect marker/control check. |

The high-lab JSON API paths and query parameters were observed in inventory. SQL fixture output is a bounded synthetic parser diagnostic. It does not confirm SQL injection, query semantic alteration, data access, or impact. CORS behavior is likewise observation-only. No status/error/reflection/timing/size/technology signal alone becomes a verified finding.

## Database, CLI, and report checks

- The installed wheel's `vulnforge`, `vulnforge lab --help`, and `vulnforge dashboard --help` entry paths were exercised.
- The CLI listed the six stored lab acceptance scans, including three vulnerable and three patched runs.
- A stored scan-ID command exported a versioned JSON report (schema `1.0`) with endpoints and controlled-test details; it did not start a new scan.
- The local workspace `vulnforge.db` contains those QA records and is intentionally retained. Existing `.preview-*` database files and journals were also left unchanged.
- The PDF renderer is dependency-free; its portability test checks the generated PDF signature. The user-facing data store remains a single `vulnforge.core.store.Store` implementation.

## Dashboard integration checks

The package-owned dashboard was exercised against real stored scans, not mock chart data. The UI shell and JS assets loaded, and the live API returned actual persisted records:

- 6 stored scans across 3 local lab targets
- 132 stored endpoints and 202 recorded requests/exchanges across those scans
- High-lab detail: 23 endpoints, 7 controlled tests, 17 negative controls, and 46 stored exchanges
- 145 persisted high-lab scan events, including a terminal completion event
- JSON export schema `1.0`

The checks also exercised stored findings, tests, controls, HTTP traffic, report export, and event history. The guarded Repeater remains source-exchange-linked, scope-inheriting, rate/budget bounded, one-request, redirect-disabled, response-size limited, and redacted.

## Package build

`pip wheel . --no-deps` produced `vulnforge-0.4.0-py3-none-any.whl` (216,881 bytes; SHA-256 `4884a6cda2b98d92f24699e10f1cebf92d6aecc273f6698a5427c805f0e3f187`). The wheel contains package-owned dashboard assets and the three lab packages, has exactly one console script, excludes test packages, and contains neither historical duplicate app tree.

## Remaining limitations

- Only explicitly configured read-only BOLA checks and paired open-redirect checks can create `VERIFIED` findings.
- CORS and SQL/parser-error checks are `OBSERVATION_ONLY`; most other vulnerability classes are unsupported or not tested.
- Historical databases with incompatible schemas remain preserved but are not automatically migrated or shown as modern verified scan history. A full migration needs a separate backed-up, validated plan.
- Broad project/target scope management, subdomain/port discovery, browser sessions/stateful workflow execution, most vulnerability classes, external scanner adapters, full proxy/raw capture, real checkpoint resume, retest, multi-user organizations, and CI report formats remain out of scope.
- `resume` creates a new scan ID; it is not checkpoint recovery.

## Source ZIP policy

The final source ZIP contains source, organized labs, examples, docs, tests, and packaging configuration only. It excludes `.git`, virtual environments, caches/bytecode, build/egg-info outputs, local `.db`/SQLite/WAL/SHM files, secrets, logs, generated reports, and temporary test artifacts. Database files remain in the workspace unchanged and are not part of the archive.
