# CLI reference

Install the package and optional dashboard/test dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dashboard,dev]'
```

The single public command is `vulnforge`.

## Main operations

```bash
vulnforge --help
vulnforge scan url https://authorized.example --yes --quiet
vulnforge scan url https://authorized.example --high --mode SAFE_ACTIVE --yes
vulnforge results
vulnforge scans
vulnforge <SCAN_ID> --database
vulnforge <SCAN_ID> --dashboard
vulnforge <SCAN_ID> --report --format json --out reports
vulnforge dashboard --host 127.0.0.1 --port 8000
```

Stored scan-ID views are read-only and do not trigger a new scan. `--db PATH` chooses a CLI database. `VULNFORGE_SCAN_DB_PATH` selects the shared default for CLI/dashboard processes.

## Priority and safety are separate

```bash
vulnforge scan url https://authorized.example --critical --mode SAFE_ACTIVE --yes
vulnforge scan url https://authorized.example --high --mode CONTROLLED_ACTIVE --yes
vulnforge scan url https://authorized.example --medium --mode PASSIVE --yes
```

`--critical`, `--high`, `--medium`, `--low`, and `--full` change the actual registered test portfolio/planning. They do not filter the result list after a scan. A supported test also requires the correct explicit configuration and applicable safety mode. Unsupported classes remain unsupported.

## Loopback-only labs

```bash
vulnforge lab critical     # 127.0.0.1:9001
vulnforge lab high         # 127.0.0.1:9002
vulnforge lab medium       # 127.0.0.1:9003
vulnforge lab high --patched
```

Labs use fake accounts and in-memory records; the scanner's LAB mode rejects non-loopback targets. Start each lab in a separate terminal.

## Scope, identity, and outputs

- `--scope` accepts explicit host rules or one JSON/YAML policy / IP-CIDR file. It is not a target batch file.
- `--auth FILE` supplies configured headers and optional explicit identity assertions. Never put real credentials in example files or shared archives.
- Default request methods are read-only (`GET`, `HEAD`, `OPTIONS`); state-changing requests require explicit allowed methods and stronger safety configuration.
- Reports are redacted and versioned. JSON, HTML, Markdown, and PDF are supported; PDF generation does not require ReportLab.
- CORS and SQL checks are observation-only. Only configured BOLA and paired redirect checks can currently emit verified findings.

Run `vulnforge scan --help` for the complete option list.
