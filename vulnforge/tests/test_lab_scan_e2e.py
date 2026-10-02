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
    }


def _scan_high(patched, tmp_path):
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
            auth_data=_auth_data(),
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
    parser_observations = [test for test in report["tests"] if test.get("type") == "sql-injection-validation"]
    if not patched:
        assert parser_observations and any(test.get("reproduction_status") == "REPRODUCED" and test.get("status") == "CANDIDATE" for test in parser_observations)
    else:
        assert parser_observations and not any(test.get("reproduction_status") == "REPRODUCED" for test in parser_observations)
    assert not any(f.get("status") == "VERIFIED" and "sql" in f.get("category", "").lower() for f in findings)
    sqli_coverage = next(row for row in report["vulnerability_matrix"] if row["class_id"] == "sqli")
    assert sqli_coverage["can_confirm"] is False and sqli_coverage["verification_level"] == "OBSERVATION_ONLY"
    if not patched:
        assert sqli_coverage["status"] == "OBSERVATION_ONLY"
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
