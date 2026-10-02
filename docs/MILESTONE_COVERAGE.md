# Milestone coverage

Date: 2026-10-01

## Consolidation milestone

- **Complete:** One canonical `vulnforge/` application package, one scanner engine, one Store, one public CLI, one dashboard API/UI, and organized `labs/` fixtures.
- **Complete:** Hybrid root dashboard routes were separated from the old engine/database. The structured routes and frontend now live under `vulnforge/`; `server.py` is a thin compatibility launcher only.
- **Complete:** Root `cli.py`, `database.py`, `engine/`, `seed.py`, old static dashboard copy, `vulnforge_dashboard.html`, and the separate `VulnForge_Ultimate/` runtime were retired after the source/import/entry-point audit. The licensing notice was retained at the repository root.
- **Complete:** Existing database files were not reset, deleted, overwritten, or migrated. Old incompatible databases are not silently surfaced as verified findings.
- **Complete:** Only one `vulnforge` console script remains. `lab` and `dashboard` are subcommands, not competing CLI entry points.

## Training apps

- **Critical (9001):** explicit two-identity, read-only BOLA boundary check. Vulnerable fixture produces a verified finding when configured; patched fixture is negative.
- **High (9002):** realistic multi-page work hub with tenant-scoped objects and observed JSON API routes. Configured BOLA behavior has vulnerable/patched coverage. SQL parser diagnostics are deliberately candidate-only; no SQL finding is verified.
- **Medium (9003):** paired redirect behavior can meet the narrow external-marker/same-origin verifier; patched fixture is negative. CORS behavior remains observation-only.
- The scanner receives explicit user test configuration, not expected outcomes or hidden lab manifests. All fixture records/identities are fictional and each server binds to `127.0.0.1` only.

## Dashboard coverage

- Stored scans and target counts, scan detail, actual endpoints/parameters, technologies, finding state, evidence, test plans/results, negative controls, differentials, reports, HTTP request/response detail, guarded Repeater, and persisted event replay are backed by the canonical Store.
- Active scan events are persisted and also streamed live. There is no estimated percent-complete bar or synthesized request history.
- Dashboard tests cover scope form wiring, report export, research object filtering, response comparison, guarded replay constraints, completed-scan SSE replay, and a real local scan through the dashboard API.

## Detection verification limits

- Only configured read-only object authorization and paired open redirect can emit `VERIFIED` findings in this build.
- CORS reflection and bounded SQL/parser-error checks are `OBSERVATION_ONLY` and cannot create verified security findings.
- Other vulnerability classes are unsupported or not tested; signatures, status, reflected input, timing/size changes, and technology fingerprints are never sufficient for confirmation alone.

## Validation matrix

`docs/QUALITY_REPORT.md` records the exact final suite count, warnings, static checks, installed entry-point checks, vulnerable/patched lab outcomes, report/database contents, dashboard API checks, and archive exclusions.

## Remaining out of scope

Full legacy schema migration, generalized scope/project management, broad vulnerability coverage, browser session vault/state-changing workflows, generalized attack-graph analysis, external tool execution, full proxy/raw packet capture, checkpoint resume/retest, multi-user organizations, and CI policy formats remain unimplemented. No placeholder success behavior was added for these gaps.
