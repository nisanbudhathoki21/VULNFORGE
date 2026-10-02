# Repository audit and final disposition

Audit date: 2026-10-01. This audit follows source references, imports, CLI entry points, test discovery, package configuration, and existing database artifacts before retiring duplicate implementations. Existing SQLite files were treated as data and were not reset, migrated, overwritten, or deleted.

## Final architecture

| Concern | Canonical path | Result |
|---|---|---|
| Application package / engine | `vulnforge/` | Single installed runtime and import namespace. |
| CLI | `vulnforge/cli.py` → `vulnforge` | One public console entry point; `lab` and `dashboard` are subcommands. |
| Store / data layer | `vulnforge/core/store.py` | Single active SQLite schema and store implementation. |
| Dashboard API | `vulnforge/dashboard.py` | Structured routes only; no legacy database bootstrap or second engine imports. |
| Dashboard frontend | `vulnforge/dashboard_static/` | Package-owned UI; all tables and live events load from the canonical store/API. |
| Training apps | `labs/runtime.py` via `vulnforge lab` | Three loopback-only synthetic applications, each with vulnerable and patched behavior. |
| Test suite | `vulnforge/tests/` | One pytest discovery tree, including scanner, dashboard/API, report, and lab E2E tests. |

`server.py` is a small compatibility launcher that imports the canonical ASGI app; it contains no separate routes, database, or scanning logic. `setup.py` delegates to `pyproject.toml` only.

## Migration review and retirement rationale

- The modified structured routes and dashboard frontend were moved from root `server.py` / `static/` into `vulnforge/dashboard.py` and `vulnforge/dashboard_static/`. Data-backed scan lists/details, findings, evidence, test plans, negative controls, differentials, HTTP request/response details, report export, persisted event replay/SSE, and the guarded source-linked Repeater remain available through the canonical Store.
- The previous root Repeater endpoint was rehomed in the canonical dashboard and still uses the stored scan's authorization scope, one-request budget, redirect blocking, response-size cap, and redaction. Its tests now import `vulnforge.dashboard` directly.
- The legacy text utility was retained as a small dashboard API function; it does not touch scan state.
- The edited legacy PDF import fallback in `engine/reporter.py` was reviewed. The canonical report renderer already writes a self-contained PDF without ReportLab; the portability test now asserts that canonical behavior. The old reporter implementation is not retained.
- Root `cli.py`, `database.py`, `engine/`, and `seed.py` were retired after reference searches showed their active callers were confined to the old dashboard/CLI path. Their unsupported scanner modules were not copied: the canonical registry reports unsupported classes as such and does not infer confirmation from weak signals.
- The 170-file `VulnForge_Ultimate/` tree was inventoried in `REPOSITORY_FILE_DISPOSITION.tsv`. It carried a second scanner, database, CLI, dashboard, template runtime, and uncollected test tree. Useful safe goals were re-expressed as documented, controlled BOLA/open-redirect lab checks and paired patched E2E tests. The separate unverified template engine and its broad exploit templates were not imported into the canonical runtime. The old demo harness included arbitrary file/network/process behavior and was not retained. Its MIT license text was copied to the repository root before retirement.
- `vulnforge_dashboard.html` and duplicate root dashboard assets were retired after moving the current UI into the package.
- The prior second console entry point `vulnforge-lab` was removed; all three labs start with the single `vulnforge lab <critical|high|medium>` command.

## Database/data preservation

Existing database files in the workspace (including the sample preview databases and the canonical structured database) were left intact. No migration or reset is attempted. The application uses `VULNFORGE_SCAN_DB_PATH` or the canonical Store default. Old incompatible schemas remain on disk untouched and are not presented as modern verified scan records; a future explicit migration requires a separate backup-and-validation plan.

The source archive must exclude local database files, WAL/SHM journals, environment directories, caches, secrets, and generated reports. The quality report and final ZIP enumerate the exclusion rules.

## Reference and entry-point checks

The active source imports only `vulnforge.*` and `labs.*`. The package exposes one `vulnforge` script. No source runtime imports root `database`, root `engine`, `VulnForge_Ultimate`, or `vulnforge2`. The root launcher and the `vulnforge dashboard` command both target the same `vulnforge.dashboard:app` object.
