import json
from pathlib import Path
from vulnforge.cli import normalize_target
from vulnforge.core.authorization import AuthorizationContext
from vulnforge.core.profiles import get_profile
from vulnforge.core.store import Store
from vulnforge.engine.orchestrator import ScanConfig, run_scan
from vulnforge.report.renderers import write_html_report, write_markdown_report, write_pdf_report
from vulnforge.report.json_report import write_json_report


def test_target_normalization_preserves_input():
    original, canonical = normalize_target("example.com/path")
    assert original == "example.com/path"
    assert canonical == "https://example.com/path"
    assert normalize_target("http://127.0.0.1:8765")[1] == "http://127.0.0.1:8765/"


def test_intelligence_and_reports_persist(mock_server, tmp_path):
    auth=AuthorizationContext(allowed_hosts=["127.0.0.1"], profile_name="passive", allow_private=True, confirmed=True)
    config=ScanConfig(target=mock_server, original_target=mock_server, profile_name="passive", allowed_hosts=["127.0.0.1"], allow_private=True, authorization_confirmed=True)
    result=run_scan(config,auth)
    ctx=result.context
    assert ctx.intelligence["target"]["original_input"] == mock_server
    assert ctx.intelligence["dns"]["observed_addresses"]
    assert "mfa" in ctx.intelligence and ctx.intelligence["mfa"]["status"] in {"DETECTED","NOT DETERMINED"}
    assert ctx.hypotheses and all(h["status"] in {"OBSERVED","SIGNAL","CANDIDATE","KEEP","DEEPER_TESTING","KILL","VERIFIED"} for h in ctx.hypotheses)
    phases={p.phase_id:p.status for p in ctx.phases}
    assert len(phases)==15 and phases["phase-01"]=="COMPLETE" and phases["phase-10"]=="SKIPPED" and phases["phase-15"]=="PARTIAL"
    assert all(p.status in {"START","RUNNING","COMPLETE","PARTIAL","SKIPPED","BLOCKED","FAILED"} for p in ctx.phases)
    assert ctx.asset_nodes and ctx.asset_edges
    assert ctx.application_model and ctx.application_model.endpoint_ids
    assert ctx.application_model.observed_page_ids and ctx.application_model.javascript_asset_ids
    assert ctx.application_model.api_document_ids and ctx.application_model.declared_operation_ids
    assert ctx.application_model.out_of_scope_endpoint_ids
    out_of_scope=next(ep for ep in ctx.endpoints.values() if "out-of-scope.example" in ep.url)
    assert out_of_scope.scope_status=="OUT_OF_SCOPE"
    assert "allowed_methods" in out_of_scope.scope_reason
    sitemap_endpoint=next(ep for ep in ctx.endpoints.values() if ep.url.endswith("/from-index"))
    child_map=next(ex for ex in ctx.requester.exchanges if ex.url.endswith("/sitemap-child.xml"))
    assert child_map.exchange_id in sitemap_endpoint.evidence_ids
    assert not any("out-of-scope.example" in ex.url for ex in ctx.requester.exchanges)
    assert any(node.asset_type=="ENDPOINT" and node.scope_status=="OUT_OF_SCOPE" for node in ctx.asset_nodes)
    assert ctx.frontend_intelligence["browser_execution"]=="NOT_TESTED"
    assert ctx.live_observations and ctx.live_state_counts
    store=Store(str(tmp_path/"scan.db"))
    store.start_scan_record(ctx.scan_id,ctx.config.target,ctx.config.profile_name,ctx.stats.started_at)
    store.record_event(ctx.scan_id,{"kind":"stage-done","message":"persist before final save","timestamp":ctx.stats.started_at+1,"data":{"stage":"recon"}})
    store.save_scan(result)
    assert store.list_scan_events(ctx.scan_id)[0]["message"]=="persist before final save"
    doc=store.get_report(ctx.scan_id)
    assert doc and doc["intelligence"]["dns"]["hostname"] == "127.0.0.1"
    assert not doc["findings"] and doc["candidates"]
    assert doc["application_model"]["application_id"]
    assert doc["api_documents"] and doc["api_inventory"]
    assert doc["live_observations"] and doc["live_state_counts"]
    assert doc["vulnerability_matrix"] and all(row["supported"] for row in doc["vulnerability_matrix"])
    assert doc["scan"]["test_profile"]=="full"
    assert not store.get_finding(ctx.scan_id)
    paths=[tmp_path/"a.html",tmp_path/"a.md",tmp_path/"a.pdf",tmp_path/"a.json"]
    write_html_report(doc,str(paths[0])); write_markdown_report(doc,str(paths[1])); write_pdf_report(doc,str(paths[2])); write_json_report(result,str(paths[3]))
    assert paths[0].read_text().startswith("<!doctype html>")
    assert "## Technology profile" in paths[1].read_text()
    assert "## Live-service classification" in paths[1].read_text()
    assert "## Vulnerability test matrix" in paths[1].read_text()
    assert "Vulnerability test matrix" in paths[0].read_text()
    assert paths[2].read_bytes().startswith(b"%PDF-1.4")
    assert b"VULNERABILITY TEST MATRIX" in paths[2].read_bytes()
    assert b"LIVE-SERVICE CLASSIFICATION" in paths[2].read_bytes()
    report_json=json.loads(paths[3].read_text())
    schema=json.loads((Path(__file__).parents[2]/"docs"/"schemas"/"vulnforge-report-v1.schema.json").read_text())
    assert report_json["schema_version"]=="1.0"
    assert set(schema["required"]).issubset(report_json)
    assert report_json["scan"]["scan_id"] == ctx.scan_id


def test_security_header_signature_is_not_confirmed(mock_server):
    auth=AuthorizationContext(allowed_hosts=["127.0.0.1"], profile_name="passive", allow_private=True, confirmed=True)
    result=run_scan(ScanConfig(target=mock_server,profile_name="passive",allowed_hosts=["127.0.0.1"],allow_private=True,authorization_confirmed=True),auth)
    assert all(f.status != "VERIFIED" for f in result.context.findings)


def test_master_15_phases_are_real_orchestrator_stages():
    from vulnforge.core.phases import PHASE_SPECS, PHASE_STATES
    from vulnforge.engine.orchestrator import STAGES
    expected=[
        "AUTHORIZATION & TARGET NORMALIZATION", "ASSET & INFRASTRUCTURE DISCOVERY",
        "APPLICATION DISCOVERY", "FRONTEND INTELLIGENCE", "BACKEND & API INTELLIGENCE",
        "APPLICATION MODELING", "SECURITY MODELING", "HYPOTHESIS GENERATION",
        "TEST PLANNING", "CONTROLLED SECURITY TESTING", "VERIFICATION", "CORRELATION",
        "EVIDENCE & FINDINGS", "COVERAGE & RISK ANALYSIS", "REPORTING",
    ]
    assert [p.name for p in PHASE_SPECS]==expected
    assert [p.phase_id for p in PHASE_SPECS]==[f"phase-{i:02d}" for i in range(1,16)]
    stages={stage.name for stage in STAGES}
    assert all(name in stages for phase in PHASE_SPECS for name in phase.stages)
    assert PHASE_STATES==("START","RUNNING","COMPLETE","PARTIAL","SKIPPED","BLOCKED","FAILED")


def test_legacy_confirmed_label_is_not_promoted_to_verified():
    from vulnforge.report.json_report import build_report_dict
    historical={"findings":[{"id":"old-1","title":"legacy result","status":"confirmed","severity":"high"}],
                "statistics":{"findings_total":1}}
    migrated=build_report_dict(historical)
    assert not migrated["findings"]
    assert migrated["verified_findings"]==[]
    assert migrated["candidates"][0]["status"]=="CANDIDATE"
    assert migrated["candidates"][0]["legacy_status"]=="confirmed"


def test_database_schema_version_and_additive_models(tmp_path):
    import sqlite3
    path=tmp_path/"versioned.db"
    Store(str(path))
    con=sqlite3.connect(path)
    assert con.execute("PRAGMA user_version").fetchone()[0]==3
    tables={row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"phases","application_models","asset_nodes","test_plans","scan_events"}.issubset(tables)


def test_schema_upgrade_from_v1_preserves_existing_scan_rows(tmp_path):
    import sqlite3
    path=tmp_path/"v1-existing.db"
    with sqlite3.connect(path) as con:
        con.execute("CREATE TABLE scans(scan_id TEXT PRIMARY KEY,target TEXT NOT NULL,profile TEXT NOT NULL,started_at REAL,finished_at REAL,status TEXT,stats_json TEXT,scope_json TEXT,audit_json TEXT)")
        con.execute("INSERT INTO scans VALUES(?,?,?,?,?,?,?,?,?)",("historic-1","https://example.test","passive",1.0,2.0,"complete","{}","{}","{}"))
        con.execute("PRAGMA user_version=1")
    Store(str(path))
    with sqlite3.connect(path) as con:
        assert con.execute("PRAGMA user_version").fetchone()[0]==3
        assert con.execute("SELECT scan_id,target,status FROM scans").fetchone()==("historic-1","https://example.test","complete")
        tables={row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"phases","application_models","asset_nodes","test_plans","scan_events"}.issubset(tables)


def test_lab_cli_profile_cannot_target_public_host():
    import pytest
    from vulnforge.cli import build_parser, cmd_scan
    args=build_parser().parse_args(["scan","https://example.invalid","--mode","LAB","--yes"])
    with pytest.raises(ValueError,match="loopback"):
        cmd_scan(args)


def test_verified_status_without_matching_test_evidence_is_demoted(mock_server):
    import asyncio
    from vulnforge.core.models import Finding, STATUS_VERIFIED
    from vulnforge.engine.orchestrator import FindingFinalizationStage, ScanConfig, run_scan
    auth=AuthorizationContext(allowed_hosts=["127.0.0.1"],profile_name="passive",allow_private=True,confirmed=True)
    result=run_scan(ScanConfig(target=mock_server,profile_name="passive",allowed_hosts=["127.0.0.1"],allow_private=True,authorization_confirmed=True),auth)
    forged=Finding("Unproven test record","test","high","No test/evidence link",status=STATUS_VERIFIED)
    result.context.findings.append(forged)
    asyncio.run(FindingFinalizationStage().run(result.context))
    assert forged.status=="CANDIDATE" and forged.state=="CANDIDATE"
    assert forged not in result.context.verified_findings


def test_legacy_finding_constructor_cannot_promote_confirmed_label():
    from vulnforge.core.models import Finding
    finding=Finding("Historical","test","high","Old status",status="confirmed")
    assert finding.status=="CANDIDATE" and finding.state=="CANDIDATE"


def test_orchestrator_rejects_credentials_embedded_in_target_url():
    import asyncio
    import pytest
    from vulnforge.core.phases import PhaseTracker
    from vulnforge.core.models import ScanContext
    from vulnforge.engine.orchestrator import AuthGateStage, ScanConfig
    auth=AuthorizationContext(allowed_hosts=["example.com"],confirmed=True)
    ctx=ScanContext("scan-test",ScanConfig(target="https://alice:secret@example.com/"),auth)
    ctx.phases=PhaseTracker().phases
    with pytest.raises(ValueError,match="Credentials"):
        asyncio.run(AuthGateStage().run(ctx))


def test_redacted_http_history_viewer_and_comparer(mock_server,tmp_path,capsys):
    from vulnforge.cli import cmd_diff, cmd_exchange_view
    auth=AuthorizationContext(allowed_hosts=["127.0.0.1"],profile_name="passive",allow_private=True,confirmed=True)
    cfg=ScanConfig(target=mock_server,profile_name="passive",allowed_hosts=["127.0.0.1"],allow_private=True,authorization_confirmed=True)
    result=run_scan(cfg,auth)
    store=Store(str(tmp_path/"history.db")); store.save_scan(result)
    rows=store.list_exchanges(scan_id=result.context.scan_id,method="GET",limit=2)
    assert rows and len(rows)<=2
    exchange=store.get_exchange(rows[0]["exchange_id"])
    assert exchange and "request_headers" in exchange and "response_body" in exchange
    assert cmd_exchange_view("request",rows[0]["exchange_id"],store)==0
    assert "exchange_id" in capsys.readouterr().out
    assert cmd_exchange_view("response",rows[0]["exchange_id"],store)==0
    assert "status" in capsys.readouterr().out
    assert cmd_diff(rows[0]["exchange_id"],rows[0]["exchange_id"],store)==0
    output=capsys.readouterr().out
    assert "SAME" in output and "not a vulnerability determination" in output
    from vulnforge.cli import build_parser, cmd_history
    args=build_parser().parse_args(["history",result.context.scan_id,"--path","/openapi","--format","json"])
    assert cmd_history(args,store)==0
    filtered=json.loads(capsys.readouterr().out)
    assert filtered and all("/openapi" in row["url"] for row in filtered)
    legacy=build_parser().parse_args(["history","--scan-id",result.context.scan_id,"--endpoint","/openapi","--format","json"])
    assert cmd_history(legacy,store)==0
    assert json.loads(capsys.readouterr().out)==filtered
