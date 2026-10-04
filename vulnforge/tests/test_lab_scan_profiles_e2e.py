from __future__ import annotations

import threading

from labs.runtime import create_server
from vulnforge.core.authorization import AuthorizationContext
from vulnforge.core.store import Store
from vulnforge.engine.orchestrator import ScanConfig, run_scan


def scan_app(level, profile, patched, tmp_path, auth_data=None):
    server = create_server(level, "127.0.0.1", 0, patched=patched)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        target = f"http://127.0.0.1:{server.server_port}/"
        authorization = AuthorizationContext(
            allowed_hosts=["127.0.0.1"], profile_name="lab", allow_private=True, confirmed=True
        )
        config = ScanConfig(
            target=target,
            profile_name="lab",
            allowed_hosts=["127.0.0.1"],
            allowed_ports=[server.server_port],
            allow_private=True,
            authorization_confirmed=True,
            active_requested=True,
            test_profile=profile,
            test_profile_explicit=True,
            request_rate=10,
            request_budget=80,
            request_timeout=2,
            auth_data=auth_data or {},
        )
        result = run_scan(config, authorization)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
    store = Store(str(tmp_path / f"{level}-{'patched' if patched else 'vulnerable'}-{profile}.db"))
    store.save_scan(result)
    return result, store.get_report(result.context.scan_id)


def test_critical_profile_checks_declared_admin_boundary_and_patched_negative(tmp_path):
    auth_data = {
        "identities": {
            "owner": {"headers": {"X-Lab-User": "admin"}},
            "member": {"headers": {"X-Lab-User": "alice"}},
        },
        "authorization_tests": [{
            "url": "/api/admin/settings",
            "owner_identity": "owner",
            "other_identity": "member",
            "owner_field": "owner",
            "owner_value": "admin",
            "identity_assertion": {"header": "X-Lab-Principal", "owner_value": "admin", "other_value": "alice"},
            "sensitive_fields": ["feature_flags"],
        }],
    }
    vulnerable, vulnerable_report = scan_app("critical", "critical", False, tmp_path, auth_data)
    patched, patched_report = scan_app("critical", "critical", True, tmp_path, auth_data)
    assert any(f.status == "VERIFIED" and "authorization" in f.category.lower() for f in vulnerable.context.verified_findings)
    assert not any(f.status == "VERIFIED" and "authorization" in f.category.lower() for f in patched.context.verified_findings)
    assert vulnerable_report["scan"]["test_profile"] == patched_report["scan"]["test_profile"] == "critical"
    assert vulnerable_report["tests"] and patched_report["tests"]


def test_medium_profile_verifies_only_reproduced_cors_and_redirect_and_control_is_negative(tmp_path):
    vulnerable, vulnerable_report = scan_app("medium", "medium", False, tmp_path)
    patched, patched_report = scan_app("medium", "medium", True, tmp_path)
    vuln_types = {f.category.lower() for f in vulnerable.context.verified_findings}
    patched_types = {f.category.lower() for f in patched.context.verified_findings}
    assert any("redirect" in category for category in vuln_types)
    assert not any("cors" in category for category in vuln_types)
    assert not any("cors" in category or "redirect" in category for category in patched_types)
    vuln_cors = [test for test in vulnerable_report["tests"] if test.get("type") == "cors-unified"]
    patch_cors = [test for test in patched_report["tests"] if test.get("type") == "cors-unified"]
    assert any(test["status"] == "CANDIDATE" and test["reproduction_status"] == "REPRODUCED" for test in vuln_cors)
    assert patch_cors and all(test["status"] == "CANDIDATE" for test in patch_cors)
    assert vulnerable_report["scan"]["test_profile"] == patched_report["scan"]["test_profile"] == "medium"
    cors_coverage = next(row for row in vulnerable_report["vulnerability_matrix"] if row["class_id"] == "cors")
    assert cors_coverage["status"] == "OBSERVATION_ONLY"
    assert cors_coverage["can_confirm"] is False
    assert vulnerable_report["tests"] and patched_report["tests"]
