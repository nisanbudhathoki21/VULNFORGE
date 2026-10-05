from __future__ import annotations

import threading

from labs.runtime import create_server
from vulnforge.core.authorization import AuthorizationContext
from vulnforge.core.store import Store
from vulnforge.engine.orchestrator import ScanConfig, run_scan
from vulnforge.report.json_report import build_report_dict, write_json_report
from vulnforge.report.renderers import write_html_report


def _auth_data():
    return {
        "identities": {
            "owner": {"headers": {"X-Lab-User": "alice"}},
            "other": {"headers": {"X-Lab-User": "bob"}},
        },
        "authorization_tests": [{
            "url": "/api/orders?id=1001",
            "owner_identity": "owner",
            "other_identity": "other",
            "owner_field": "owner",
            "owner_value": "alice",
            "identity_assertion": {
                "header": "X-Lab-Principal",
                "owner_value": "alice",
                "other_value": "bob",
            },
            "sensitive_fields": ["email"],
        }],
        "privilege_escalation_tests": [{
            "url": "/api/admin/users",
            "authorized_identity": "owner",
            "lower_identity": "other",
            "identity_assertion": {
                "header": "X-Lab-Principal",
                "authorized_value": "alice",
                "lower_value": "bob",
            },
        }],
    }


def _scan_high(patched, tmp_path, auth_data=None):
    server = create_server("high", "127.0.0.1", 0, patched=patched)
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
            test_profile="high",
            test_profile_explicit=True,
            request_rate=12,
            request_budget=100,
            request_timeout=2,
            auth_data=_auth_data() if auth_data is None else auth_data,
        )
        result = run_scan(config, authorization)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    store = Store(str(tmp_path / ("high-patched.db" if patched else "high-vulnerable.db")))
    store.save_scan(result)
    report = store.get_report(result.context.scan_id)
    exchanges = store.list_exchanges(scan_id=result.context.scan_id, limit=500)
    findings = store.get_findings(result.context.scan_id)
    assert report is not None and report["scan"]["scan_id"] == result.context.scan_id
    assert report["endpoints"] and report["parameters"]
    observed_urls = [endpoint["url"] for endpoint in report["endpoints"]]
    assert any("/api/orders" in url for url in observed_urls)
    assert any("/api/documents/" in url for url in observed_urls)
    assert any("/api/search" in url for url in observed_urls)
    assert any(parameter["name"] == "q" for parameter in report["parameters"])
    assert exchanges and any(x["url"].endswith("/api/orders?id=1001") for x in exchanges)
    evidence = store.list_evidence(scan_id=result.context.scan_id)
    assert report["hypotheses"] and report["tests"] and evidence is not None
    sqli_tests = [
        test for test in report["tests"]
        if test.get("type") == "sql-injection-validation"
    ]

    assert sqli_tests

    sqli_findings = [
        f for f in findings
        if "sql" in f.get("category", "").lower()
    ]

    if not patched:
        # The vulnerable high lab must now satisfy the evidence-first
        # SQLi verification contract.
        assert any(
            test.get("reproduction_status") == "REPRODUCED"
            and test.get("status") == "VERIFIED"
            for test in sqli_tests
        )
        assert any(
            f.get("status") == "VERIFIED"
            for f in sqli_findings
        )
    else:
        assert not any(
            test.get("reproduction_status") == "REPRODUCED"
            and test.get("status") == "VERIFIED"
            for test in sqli_tests
        )
        assert not any(
            f.get("status") == "VERIFIED"
            for f in sqli_findings
        )

    sqli_coverage = next(
        row for row in report["vulnerability_matrix"]
        if row["class_id"] == "sqli"
    )

    # SQLi now has an evidence-backed verification contract.
    # The vulnerable lab must therefore advertise confirmation capability,
    # while the patched lab must still produce no verified finding.
    assert sqli_coverage["can_confirm"] is True
    assert sqli_coverage["verification_level"] == "CONTROLLED_SEMANTIC_VERIFICATION"
    assert report["report_manifest"]

    json_doc = build_report_dict(result)
    json_path = tmp_path / ("high-patched.json" if patched else "high-vulnerable.json")
    html_path = tmp_path / ("high-patched.html" if patched else "high-vulnerable.html")
    write_json_report(result, str(json_path))
    write_html_report(result, str(html_path))
    assert json_path.is_file() and '"schema_version": "1.0"' in json_path.read_text()
    assert html_path.is_file() and "VulnForge" in html_path.read_text()
    return result, findings


def test_high_lab_full_engine_data_path_vulnerable_and_patched_controls(tmp_path):
    vulnerable, vulnerable_findings = _scan_high(False, tmp_path)
    patched, patched_findings = _scan_high(True, tmp_path)

    assert any(f.get("status") == "VERIFIED" and "authorization" in f.get("category", "").lower() for f in vulnerable_findings)
    assert not any(f.get("status") == "VERIFIED" and "authorization" in f.get("category", "").lower() for f in patched_findings)
    assert vulnerable.context.stats.requests_sent <= 100
    assert patched.context.stats.requests_sent <= 100
    assert vulnerable.context.tests and patched.context.tests


def test_high_lab_auto_discovers_privilege_boundary(tmp_path):
    auth_data = _auth_data()
    auth_data.pop("privilege_escalation_tests", None)

    vulnerable, findings = _scan_high(
        False,
        tmp_path,
        auth_data=auth_data,
    )

    def finding_field(finding, field, default=""):
        if isinstance(finding, dict):
            return finding.get(field, default)
        return getattr(finding, field, default)

    privilege_findings = [
        finding
        for finding in findings
        if str(
            finding_field(finding, "category")
        ).lower()
        == "privilege escalation"
    ]

    assert privilege_findings, (
        "Automatic privilege-boundary discovery did not produce "
        "a privilege-escalation finding"
    )

    assert any(
        "/api/admin/users"
        in str(finding_field(finding, "endpoint"))
        for finding in privilege_findings
    ), "Expected /api/admin/users to be automatically tested"

    assert any(
        str(finding_field(finding, "status")).upper() == "VERIFIED"
        for finding in privilege_findings
    ), "Privilege escalation must be evidence-verified"
