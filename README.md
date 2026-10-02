# VULNFORGE

VULNFORGE is a scoped, evidence-led web assessment application for authorized testing. The repository has one canonical Python runtime (`vulnforge/`), one SQLite store (`vulnforge.core.store.Store`), one public CLI (`vulnforge`), and one web dashboard (`vulnforge.dashboard`). The independent synthetic training targets live under `labs/` and bind only to loopback.

## Install on Linux

```bash
cd /path/to/VulnForge
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dashboard,dev]'
```

The dashboard extra installs FastAPI, Uvicorn, and Pydantic. The core scanner uses `httpx`. To run without installing the package, `python -m vulnforge --help` works from the repository root after dependencies are installed.

## Start the dashboard

```bash
vulnforge dashboard
```

By default the dashboard binds to `127.0.0.1:8000`. `HOST` and `PORT` can be set in the environment, or supplied to the command:

```bash
vulnforge dashboard --host 127.0.0.1 --port 8000
```

The UI is served from package-owned local assets and reads persisted scan, endpoint, finding, evidence, test, control, differential, exchange, and event records from the canonical store. Its dark, multi-pane workbench brings the target map, HTTP history, request/response inspection, finding distribution, and scan events together on one screen. Everything shown is backed by stored records; empty databases show empty states rather than fabricated traffic or findings. Active scan progress is backed by persisted engine events. The dashboard is not a general-purpose proxy.

The project includes `vulnforge.db` in the repository root (pre-populated with synthetic loopback training-lab assessments on `127.0.0.1:9001`, `127.0.0.1:9002`, and `127.0.0.1:9003` so the workbench opens with real stored lab traffic, findings, and events immediately) plus an empty schema-only template at `data/vulnforge.db` (20 tables, schema version 3, zero scan records). Do not commit databases containing private or real-world target scans to a public repository.

## Run an authorized assessment

Start with passive observation, or explicitly select both a supported priority portfolio and a safety mode:

```bash
vulnforge scan url https://authorized.example --yes --quiet
vulnforge scan url https://authorized.example --high --mode SAFE_ACTIVE --yes
```

`--critical`, `--high`, `--medium`, `--low`, and `--full` change test planning. Safety/resource mode is separate. Active testing requires explicit authorization, an in-scope supported method, and any required per-test configuration. The default scope methods are `GET`, `HEAD`, and `OPTIONS`; use only systems you own or are expressly authorized to test.

List and inspect stored data without starting a scan:

```bash
vulnforge results
vulnforge <SCAN_ID> --database
vulnforge <SCAN_ID> --report --format json --out reports
vulnforge <SCAN_ID> --dashboard       # keyboard-navigable stored-results view
```

Scan-ID commands only read the existing scan record. `--db PATH` selects a CLI database. The CLI and dashboard use `VULNFORGE_SCAN_DB_PATH` when configured; otherwise the default is `vulnforge.db` in the working directory. Existing databases are never reset or deleted as a compatibility fix. Incompatible historical schemas are not silently overwritten or promoted into verified findings; keep a backup before any manual migration. The dashboard displays only the database filename, not its physical path, by default.

## Local training labs

Each lab is a separate, synthetic, loopback-only multi-page application with controlled fake identities, tenants, and objects. Start one lab per terminal:

```bash
vulnforge lab critical     # 127.0.0.1:9001
vulnforge lab high         # 127.0.0.1:9002
vulnforge lab medium       # 127.0.0.1:9003
```

To run its paired fixed control behavior, add `--patched`:

```bash
vulnforge lab critical --patched
vulnforge lab high --patched
vulnforge lab medium --patched
```

The labs bind exclusively to `127.0.0.1`; they do not execute operating-system commands, fetch arbitrary external URLs, persist changes, or use real credentials/data. The CLI blocks LAB-mode scans of non-loopback targets. Example test identities and explicit authorization JSON are in `examples/`.

Example vulnerable High-lab scan (start the High lab first):

```bash
vulnforge scan url http://127.0.0.1:9002 \\
  --high --lab --auth examples/high-lab-auth.json \\
  --yes --rate 2 --max-requests 100
```

The verified cross-account authorization demonstration is deliberately limited to the explicitly configured test assertions. The lab's SQL parser message is an observation, not proof of injection impact.

## Detection limits and evidence contract

- Only configured, read-only two-identity object authorization comparisons and paired open-redirect checks can currently produce `VERIFIED` findings.
- CORS reflection and bounded SQL/parser-error behavior are `OBSERVATION_ONLY`; they cannot produce confirmed findings in this build. They require stronger impact/authorization evidence before any future promotion.
- Status codes, generic errors, reflected input, timing/size changes, technology fingerprints, or a single parser diagnostic are not sufficient evidence for a vulnerability.
- Other classes in the priority registry are unsupported or not tested. Reports include the selected portfolio, actual plan/execution state, negative controls, and limitations.
- Built-in checks are bounded and non-destructive. No public-target LAB mode, persistence, credential theft, arbitrary production-data extraction, or disruption is provided.

## Project layout

```text
vulnforge/               canonical scanner, store, CLI, reports, dashboard API/assets
labs/                    three independent loopback training applications
examples/                scope and fake test-identity configurations
docs/                    architecture, evidence, security, audit, and coverage records
```

There is no second scanner implementation or legacy database layer in the runtime. Retained historical database files are not modified; they are not read as active scan history. `server.py`, if used directly for backwards compatibility, is only a thin launcher for the canonical dashboard.

## HTTP workbench and normalized research workspace

The CLI and dashboard read the same SQLite database. Every captured exchange is
kept as a redacted compatibility record and projected into relational
`requests`, `request_headers`, `request_parameters`, `responses`,
`response_headers`, and `response_cookies` rows. Test materialization adds
`payloads`, `test_runs`, `controls`, `diffs`, and direct evidence links, so a
finding can be traced back to the exact request and response that produced it.

Useful traffic commands:

```bash
vulnforge requests --db vulnforge.db
vulnforge traffic --method GET --status 200 --host api.example.test --endpoint /api
vulnforge request 004 --db vulnforge.db       # request and response together
vulnforge finding FINDING_ID --db vulnforge.db
vulnforge endpoint ENDPOINT_ID --db vulnforge.db
vulnforge search "id=123" --db vulnforge.db
```

`vulnforge db status`, `db stats`, `db migrate`, and `db backup` operate on the
same store. The additive research-workspace migration is recorded in
`schema_migrations`; opening an older compatible database is non-destructive.
Sensitive headers and cookie values remain redacted in normal display and
exports. HTTP differences are observations only and are never promoted to a
confirmed finding without the configured validation contract.

The web Traffic workbench provides filterable history, request/response raw,
header, query, cookie, body, JSON, authentication, timing, history, tests,
and evidence views. Stored reports can also be exported as JSON, Markdown,
HTML, PDF, or redacted HAR through the dashboard export endpoint.

## Tests and checks

```bash
python -m pytest -q
git diff --check
python -m compileall -q vulnforge labs
node --check vulnforge/dashboard_static/app.js
```

Dashboard/API tests use local mock targets. End-to-end lab tests verify both vulnerable and patched behavior, severity-specific planning, stored reports, and conservative finding outcomes. See `docs/LINUX_INSTALL_AND_TEST.md`, `docs/MILESTONE_COVERAGE.md`, and `docs/QUALITY_REPORT.md` for exact validation results and explicit gaps.

## License

MIT. See `LICENSE`.
