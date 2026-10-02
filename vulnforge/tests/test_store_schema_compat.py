import sqlite3

import pytest

from vulnforge import cli
from vulnforge.core.store import Store


def _legacy_database(path):
    with sqlite3.connect(path) as con:
        con.execute("CREATE TABLE scans (id TEXT PRIMARY KEY, target_url TEXT NOT NULL, status TEXT)")
        con.execute("INSERT INTO scans(id,target_url,status) VALUES ('old-scan','https://example.test','completed')")


def test_store_rejects_legacy_scans_schema_without_mutating_it(tmp_path):
    database = tmp_path / "old-vulnforge.db"
    _legacy_database(database)

    with pytest.raises(ValueError, match=r"incompatible legacy 'scans' table") as exc:
        Store(str(database))
    assert "VULNFORGE_SCAN_DB_PATH" in str(exc.value)
    assert str(database) not in str(exc.value)

    with sqlite3.connect(database) as con:
        names = {row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert names == {"scans"}
        assert con.execute("SELECT id FROM scans").fetchone() == ("old-scan",)
        assert con.execute("PRAGMA user_version").fetchone() == (0,)


def test_cli_rejects_incompatible_database_before_sending_requests(tmp_path, monkeypatch, capsys):
    database = tmp_path / "legacy.db"
    _legacy_database(database)

    def must_not_scan(*args, **kwargs):
        raise AssertionError("network scan started before database compatibility check")

    monkeypatch.setattr(cli, "run_scan", must_not_scan)
    result = cli.main([
        "scan", "http://127.0.0.1:8765", "--lab", "--db", str(database),
    ])
    assert result == 2
    output = capsys.readouterr().err
    assert "incompatible legacy 'scans' table" in output
    assert "No migration or deletion was performed" in output
    assert "VULNFORGE_SCAN_DB_PATH" in output
    assert str(database) not in output
