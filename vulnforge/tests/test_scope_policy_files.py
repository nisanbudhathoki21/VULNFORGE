import json
import pytest

from vulnforge.cli import _scope_rules


def test_ip_text_scope_file_is_allowlist_not_target_batch(tmp_path):
    path = tmp_path / "authorized.ips"
    path.write_text("# only authorized addresses\n192.0.2.10/32\n2001:db8::10/128\n", encoding="utf-8")
    policy = _scope_rules([str(path)], ["192.0.2.10"])
    assert policy["allowed_hosts"] == ["192.0.2.10"]
    assert policy["allowed_ips"] == ["192.0.2.10/32", "2001:db8::10/128"]
    assert policy["allowed_methods"] == ["GET", "HEAD", "OPTIONS"]


def test_ip_text_scope_file_rejects_invalid_entry_and_empty_policy(tmp_path):
    path = tmp_path / "bad.txt"
    path.write_text("192.0.2.1\nnot-an-ip\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid IP/CIDR"):
        _scope_rules([str(path)], ["192.0.2.1"])
    path.write_text("# intentionally empty\n", encoding="utf-8")
    with pytest.raises(ValueError, match="empty"):
        _scope_rules([str(path)], ["192.0.2.1"])


def test_full_scope_policy_file_loads_and_rejects_unknown_keys(tmp_path):
    path = tmp_path / "scope.json"
    path.write_text(json.dumps({
        "allowed_ips": ["198.51.100.10/32"],
        "allowed_ports": [443],
        "excluded_hosts": ["admin.example.test"],
        "allowed_methods": ["GET", "OPTIONS"],
    }), encoding="utf-8")
    policy = _scope_rules([str(path)], ["example.test"])
    assert policy["allowed_hosts"] == ["example.test"]
    assert policy["allowed_ips"] == ["198.51.100.10/32"]
    assert policy["allowed_ports"] == [443]
    assert policy["excluded_hosts"] == ["admin.example.test"]
    assert policy["allowed_methods"] == ["GET", "OPTIONS"]

    path.write_text('{"allow_everything": true}', encoding="utf-8")
    with pytest.raises(ValueError, match="Unknown scope policy key"):
        _scope_rules([str(path)], ["example.test"])


def test_dashboard_scope_policy_control_is_wired():
    from pathlib import Path
    root=Path(__file__).resolve().parents[2]
    html=(root/"vulnforge"/"dashboard_static"/"index.html").read_text(encoding="utf-8")
    javascript=(root/"vulnforge"/"dashboard_static"/"app.js").read_text(encoding="utf-8")
    server=(root/"vulnforge"/"dashboard.py").read_text(encoding="utf-8")
    assert 'id="scan-scope-policy"' in html
    assert 'id="scan-safety-mode"' in html
    assert "byId('scan-scope-policy')" in javascript and "scope_policy" in javascript
    assert "safety_mode:" in javascript
    assert "scope_policy: Dict[str,Any]" in server


def test_multiple_scope_files_and_missing_policy_paths_reject(tmp_path):
    a = tmp_path / "a.ips"
    b = tmp_path / "b.ips"
    a.write_text("192.0.2.1\n", encoding="utf-8")
    b.write_text("192.0.2.2\n", encoding="utf-8")
    with pytest.raises(ValueError, match="at most one"):
        _scope_rules([str(a), str(b)], ["192.0.2.1"])
    with pytest.raises(ValueError, match="does not exist"):
        _scope_rules([str(tmp_path / "missing.json")], ["example.test"])
