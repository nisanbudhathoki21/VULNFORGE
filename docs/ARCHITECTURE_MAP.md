# Architecture map

```text
vulnforge.cli
  ├── vulnforge.core.authorization / profiles / rate limiting
  ├── vulnforge.engine.orchestrator
  │    ├── vulnforge.http.client.Requester
  │    ├── vulnforge.engine.crawler / inventory / intelligence
  │    ├── vulnforge.engine.*_verification (narrow, registered checks)
  │    └── vulnforge.core.models / outcomes / coverage
  ├── vulnforge.core.store.Store (single SQLite data layer)
  └── vulnforge.report (versioned JSON, HTML, Markdown, dependency-free PDF)

vulnforge.dashboard:app
  ├── same vulnforge.engine.orchestrator and Store
  ├── same persisted events / exchanges / reports
  └── vulnforge.dashboard_static (single web UI)

vulnforge lab critical|high|medium
  └── labs.runtime (synthetic, in-memory, loopback-only targets)
```

## Public boundaries

- `vulnforge <scan-id> ...` reads saved scan data; it never starts another scan.
- `vulnforge dashboard` serves the canonical dashboard on loopback by default.
- `vulnforge lab <level> [--patched]` starts one local fixture and rejects non-loopback binding by design.
- `server.py` is a compatibility launcher only. It imports the exact canonical dashboard ASGI app.
- `pyproject.toml` is the source of build metadata and declares a single `vulnforge` console script.

## Data flow

1. CLI or dashboard validates authorization, target, safety mode, scope, and configured test inputs.
2. The orchestrator drives bounded requests through the shared Requester and records actual exchanges and events.
3. Inventory, hypotheses, test plans, negative controls, verifier outcomes, evidence, and reports are derived from observed records.
4. The Store persists the scan and canonical dashboard APIs expose that same data. Reopened scans and SSE event replay read persisted SQLite event rows.
5. Reports label `VERIFIED`, `CANDIDATE`, `OBSERVATION_ONLY`, `INCONCLUSIVE`, `BLOCKED`, and unsupported coverage explicitly.

## Quality and gaps

Exact checks and current limitations are documented in `ARCHITECTURE_STATE.md`, `MILESTONE_COVERAGE.md`, and `QUALITY_REPORT.md`.
