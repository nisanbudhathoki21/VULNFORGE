import json
import sqlite3

from vulnforge.cli import build_parser, main
from vulnforge.core.store import Store


def _store_with_exchange(tmp_path):
    path = tmp_path / "workspace.db"
    store = Store(str(path))
    store.start_scan_record("scan-workspace", "https://authorized.example", "passive", 1.0)
    store.record_exchange("scan-workspace", {
        "exchange_id": "exchange-workspace",
        "request_id": "request-workspace",
        "response_id": "response-workspace",
        "method": "GET",
        "url": "https://authorized.example/api/users?id=123",
        "request_headers": {"Authorization": "Bearer secret", "Accept": "application/json"},
        "response_headers": {"Content-Type": "application/json", "Set-Cookie": "session=secret; HttpOnly"},
        "status": 200,
        "reason_phrase": "OK",
        "request_body": "",
        "response_body": '{"id":123}',
        "duration_ms": 9.5,
        "module": "crawler",
    })
    return path, store


def test_relational_workspace_persists_normalized_http_records(tmp_path):
    path, store = _store_with_exchange(tmp_path)
    metrics = store.relational_metrics()
    assert metrics["projects"] == 1
    assert metrics["targets"] == 1
    assert metrics["requests"] == 1
    assert metrics["responses"] == 1
    exchange = store.resolve_exchange("001")
    assert exchange["request_id"] == "request-workspace"
    assert exchange["request_headers"]["Authorization"] == "[REDACTED]"
    with sqlite3.connect(path) as con:
        tables = {row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"projects", "targets", "requests", "request_headers", "responses", "response_headers", "payloads", "test_runs", "controls", "diffs", "audit_events"}.issubset(tables)
        assert con.execute("SELECT status_code FROM responses WHERE response_id='response-workspace'").fetchone()[0] == 200


def test_cli_traffic_request_and_database_commands_share_store(tmp_path, capsys):
    path, _ = _store_with_exchange(tmp_path)
    parsed = build_parser().parse_args(["traffic", "--db", str(path), "--method", "GET"])
    assert parsed.command == "traffic" and parsed.method == "GET"
    assert main(["requests", "--db", str(path)]) == 0
    traffic_output = capsys.readouterr().out
    assert "REQUESTS" in traffic_output and "authorized.example" in traffic_output
    assert main(["request", "001", "--db", str(path)]) == 0
    detail_output = capsys.readouterr().out
    assert "HTTP REQUEST" in detail_output and "HTTP RESPONSE" in detail_output
    assert main(["db", "stats", "--db", str(path)]) == 0
    assert '"requests": 1' in capsys.readouterr().out


def test_database_migration_and_backup_are_idempotent(tmp_path):
    path, store = _store_with_exchange(tmp_path)
    assert store.migrate()["applied"] is True
    backup = tmp_path / "backup.sqlite"
    assert store.backup(str(backup)) == str(backup)
    copied = Store(str(backup))
    assert copied.relational_metrics()["requests"] == 1
