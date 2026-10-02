import json
import sqlite3

from vulnforge import cli
from vulnforge.cli_ui import build_stored_scan_pages
from vulnforge.core.store import Store


def test_shortcut_parser_keeps_one_scan_id_central_for_report_exports():
    args = cli._scan_id_shortcut_parser().parse_args([
        "vf-844f5fecfb2b", "--report", "--format", "pdf",
    ])
    assert args.scan_id == "vf-844f5fecfb2b"
    assert args.report and args.format == "pdf"


def test_invalid_scan_id_has_clean_error_and_no_traceback(tmp_path, capsys):
    result = cli.main([
        "vf-does-not-exist", "--dashboard", "--db", str(tmp_path / "scans.db"),
    ])
    assert result == 2
    error = capsys.readouterr().err
    assert "scan ID not found" in error
    assert "Traceback" not in error


def test_scan_id_report_shortcut_exports_json_and_dashboard_uses_stored_scan(tmp_path, capsys):
    path=tmp_path/"stored.db"
    store=Store(str(path))
    scan_id="vf-0123456789ab"
    store.start_scan_record(scan_id,"https://demo.example/","lab",1.0)
    store.finish_scan_record(scan_id,"completed",2.0)
    report={"scan":{"scan_id":scan_id,"target":"https://demo.example/","report_paths":{}},
            "findings":[],"candidates":[],"tests":[],"vulnerability_matrix":[]}
    with sqlite3.connect(path) as con:
        con.execute("INSERT INTO scan_documents(scan_id,report_json) VALUES (?,?)",(scan_id,json.dumps(report)))
    out=tmp_path/"exported"
    assert cli.main([scan_id,"--report","--format","json","--out",str(out),"--db",str(path)])==0
    assert (out/"report.json").is_file()
    assert cli.main([scan_id,"--dashboard","--db",str(path)])==2
    assert "needs a TTY" in capsys.readouterr().out


def test_results_lists_scan_ids_with_verified_counts_and_shortcut_help(tmp_path,capsys):
    store=Store(str(tmp_path/"results.db"))
    store.start_scan_record("vf-aabbccddeeff","https://demo.example/","lab",1.0)
    store.finish_scan_record("vf-aabbccddeeff","completed",2.0)
    assert cli.cmd_status(store)==0
    output=capsys.readouterr().out
    assert "SCAN ID" in output and "vf-aabbccddeeff" in output
    assert "--dashboard | --database | --report" in output


def test_scan_database_view_is_scan_scoped_and_hides_path_by_default(tmp_path, capsys):
    path = tmp_path / "private-location" / "structured.db"
    path.parent.mkdir()
    store = Store(str(path))
    scan_id = "vf-aabbccddeeff"
    store.start_scan_record(scan_id, "https://demo.example/", "lab", 1.0)
    store.finish_scan_record(scan_id, "completed", 2.0)
    report = {
        "scan": {"scan_id": scan_id, "target": "https://demo.example/", "report_paths": {}},
        "intelligence": {"dns": {"hostname": "demo.example", "observed_addresses": ["127.0.0.1"]}, "services": []},
        "asset_nodes": [], "asset_edges": [], "technologies": [], "endpoints": [],
        "parameters": [], "discovery_signals": [], "live_observations": [],
        "hypotheses": [], "tests": [], "test_plan": [], "findings": [], "candidates": [],
    }
    with sqlite3.connect(path) as con:
        con.execute("INSERT INTO scan_documents(scan_id,report_json) VALUES (?,?)", (scan_id, json.dumps(report)))
    assert cli.cmd_scan_database(scan_id, store) == 0
    output = capsys.readouterr().out
    for section in ("TARGET", "ASSETS", "HOSTS", "SERVICES", "TECHNOLOGIES", "ENDPOINTS",
                    "PARAMETERS", "REQUESTS", "RESPONSES", "OBSERVATIONS", "HYPOTHESES",
                    "TESTS", "CONTROLS", "DIFFERENTIALS", "EVIDENCE", "FINDINGS", "EVENTS"):
        assert section in output
    assert str(path) not in output


def test_stored_dashboard_has_requested_pages_and_real_hypothesis_finding_links():
    hypothesis = {"hypothesis_id": "hyp-1", "category": "injection", "status": "SUPPORTED", "endpoint": "/search", "reason": "Observed parameter"}
    test = {"test_id": "test-1", "hypothesis_id": "hyp-1", "type": "sql-injection-validation", "status": "VERIFIED", "endpoint": "/search"}
    finding = {"id": "finding-1", "status": "VERIFIED", "severity": "high", "title": "Test finding", "evidence": []}
    evidence = {"evidence_id": "evidence-1", "finding_id": "finding-1", "test_id": "test-1", "evidence": {"description": "Stored proof"}}
    bundle = {
        "scan": {"scan_id": "vf-aabbccddeeff", "target": "https://demo.example/", "profile": "lab", "status": "completed", "started_at": 1.0},
        "report": {
            "scan": {"scan_id": "vf-aabbccddeeff", "target": "https://demo.example/", "report_paths": {}},
            "statistics": {"requests_sent": 2},
            "intelligence": {"target": {"hostname": "demo.example"}, "dns": {"hostname": "demo.example", "observed_addresses": ["127.0.0.1"]}, "services": [], "tls": {"status": "NOT DETERMINED"}},
            "request_controls": {"configured_rate_limit_per_second": 2.0, "request_budget": 100},
            "target_rate_limit_observations": {"http_429_responses": 0, "retry_after_responses": 0},
            "asset_nodes": [], "asset_edges": [], "technologies": [], "endpoints": [], "parameters": [],
            "hypotheses": [hypothesis], "tests": [test], "test_plan": [],
            "findings": [finding], "candidates": [], "discovery_signals": [], "live_observations": [],
        },
        "http_history": [], "exchanges": [], "evidence_records": [evidence],
        "events": [{"event_id": 1, "kind": "stage-done", "message": "recon complete", "timestamp": 2.0, "data": {"stage": "recon"}}],
    }
    pages, selectable, records = build_stored_scan_pages(bundle)
    expected = {"Overview", "Recon", "Infrastructure", "Hosts", "Services", "Technologies", "Endpoints",
                "Parameters", "HTTP History", "Requests", "Responses", "Observations", "Hypotheses",
                "Tests", "Controls", "Differentials", "Evidence", "Findings", "Events", "Reports"}
    assert set(pages) == expected
    assert selectable["Hypotheses"][0]["hypothesis_id"] == "hyp-1"
    assert records["tests"][0]["hypothesis_id"] == selectable["Hypotheses"][0]["hypothesis_id"]
    assert selectable["Findings"][0]["id"] == "finding-1"
    assert records["evidence"][0]["finding_id"] == selectable["Findings"][0]["id"]
    assert selectable["Events"][0]["kind"] == "stage-done"
    assert "recon complete" in pages["Events"][0]
    assert "No matching passive signature" in " ".join(pages["Infrastructure"])
