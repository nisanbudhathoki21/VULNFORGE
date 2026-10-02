# Linux install, run, and test

## Install

```bash
cd /path/to/VulnForge
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dashboard,dev]'
```

## Start the dashboard

```bash
vulnforge dashboard
```

Default bind is loopback `127.0.0.1:8000`. Use `HOST` / `PORT` environment variables or `--host` / `--port` as needed. Avoid exposing local sensitive request history on a network interface.

## Start and scan each lab

Use separate terminals for the lab and scanner:

```bash
vulnforge lab critical
vulnforge lab high
vulnforge lab medium
```

Each server binds to loopback only: ports 9001, 9002, 9003 respectively. For a patched/control run append `--patched`.

Example High vulnerable lab run:

```bash
vulnforge scan url http://127.0.0.1:9002 \
  --high --lab --auth examples/high-lab-auth.json \
  --yes --rate 2 --max-requests 100
```

Example High patched run: stop the vulnerable High lab, restart it with `vulnforge lab high --patched`, then use `examples/high-lab-auth-patched.json` with the same scan command. The patched lab should yield no verified BOLA finding. SQL parser diagnostics remain candidate-only in either mode.

## Read-only scan inspection and export

```bash
vulnforge results
vulnforge <SCAN_ID> --database
vulnforge <SCAN_ID> --report --format json --out reports
vulnforge <SCAN_ID> --dashboard
```

These commands read stored data and do not start another scan.

## Validation

```bash
python -m pytest -q
git diff --check
python -m compileall -q vulnforge labs
node --check vulnforge/dashboard_static/app.js
```

Dashboard tests require the dashboard extra. Full current test outcomes and package/dashboard/lab smoke results are in `QUALITY_REPORT.md`.

## Data safety

The canonical Store is selected by `VULNFORGE_SCAN_DB_PATH`, or defaults to `vulnforge.db` in the working directory. CLI one-off overrides use `--db PATH`. Existing DB files are never reset or deleted automatically. Old incompatible schemas remain untouched and require an explicit, backed-up migration before reuse. Do not include DB/WAL files, local credentials, virtual environments, caches, or generated reports in a source ZIP.
