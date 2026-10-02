import json
from argparse import Namespace
from types import SimpleNamespace

import pytest

from vulnforge.core.store import Store
from vulnforge.engine.browser_capture import (
    correlate_capture_workflow, parse_har_document, validate_configured_workflow,
)


def _har():
    return {"log":{"version":"1.2","entries":[
        {"startedDateTime":"2026-09-30T10:00:00Z","time":4,"pageref":"page_1","_resourceType":"document",
         "request":{"method":"GET","url":"https://app.example.test/","headers":[
             {"name":"Cookie","value":"session=secret-cookie"},{"name":"X-Internal-Auth","value":"secret-auth"}]},
         "response":{"status":200,"headers":[{"name":"Set-Cookie","value":"session=secret-cookie"}],
             "content":{"mimeType":"text/html","text":"<h1>secret response body</h1>","size":27}}},
        {"startedDateTime":"2026-09-30T10:00:01Z","time":8,"pageref":"page_1","_resourceType":"document",
         "request":{"method":"GET","url":"https://app.example.test/next?token=private-token","headers":[
             {"name":"Referer","value":"https://app.example.test/"}]},
         "response":{"status":200,"headers":[{"name":"Content-Type","value":"text/html"}],
             "content":{"mimeType":"text/html","text":"<p>body stays out</p>","size":21}}},
        {"request":{"method":"GET","url":"https://outside.example/asset.js","headers":[]},
         "response":{"status":200,"headers":[],"content":{"mimeType":"application/javascript","text":"secret"}}},
        {"request":{"method":"POST","url":"https://app.example.test/login","headers":[],
             "queryString":[],"postData":{"mimeType":"application/x-www-form-urlencoded","text":"username=a&password=never-store"}},
         "response":{"status":302,"headers":[],"content":{"mimeType":"text/html","text":""}}},
        {"request":{"method":"GET","url":"https://app.example.test/search?session_id=private","headers":[]},
         "response":{"status":200,"headers":[],"content":{"mimeType":"text/html","text":""}}},
    ]}}


def test_har_import_is_bounded_redacted_and_scope_filtered():
    calls=[]
    def allowed(url,method):
        calls.append((url,method))
        return "app.example.test" in url and method in {"GET","POST"}
    result=parse_har_document(_har(),allowed,excluded_param=lambda name:name.lower() in {"session_id","password"},capture_id="capture-test")
    assert result["summary"]["entries_seen"]==5
    assert result["summary"]["imported"]==2
    assert result["summary"]["scope_rejected"]==1
    assert result["summary"]["excluded_parameter"]==2
    assert len(result["exchanges"])==2
    first,second=result["exchanges"]
    assert first["request_headers"]["Cookie"]=="[REDACTED]"
    assert first["request_headers"]["X-Internal-Auth"]=="[REDACTED]"
    assert first["response_headers"]["Set-Cookie"]=="[REDACTED]"
    assert first["response_body"]=="" and second["request_body"]==""
    assert first["capture_bodies_stored"] is False
    assert first["capture_response_body_bytes_omitted"]>0
    assert second["url"]=="https://app.example.test/next?token=%5BREDACTED%5D"
    assert second["capture_referer_url"]=="https://app.example.test/"
    assert "secret response body" not in repr(result)
    assert "never-store" not in repr(result)
    assert all("outside.example" not in str(item) for item in result["exchanges"])
    assert calls


def test_har_workflow_correlation_records_observed_refs_not_verified_transitions():
    result=parse_har_document(_har(),lambda url,method:"app.example.test" in url,
        excluded_param=lambda name:name.lower() in {"session_id","password"},capture_id="capture-test")
    static={"states":[{"state_id":"view-home","url":"https://app.example.test/"},
                      {"state_id":"view-next","url":"https://app.example.test/next?token=[REDACTED]"}],
        "transitions":[{"transition_id":"link-1","source_state_id":"view-home",
            "target_url":"https://app.example.test/next?token=[REDACTED]","method":"GET"}]}
    workflow=correlate_capture_workflow(static,result["exchanges"])
    assert len(workflow["observations"])==1
    observation=workflow["observations"][0]
    assert observation["source_state_id"]=="view-home"
    assert observation["target_state_id"]=="view-next"
    assert observation["static_transition_id"]=="link-1"
    assert observation["status"]=="CAPTURE_SEQUENCE_OBSERVED_NOT_VERIFIED"
    assert observation["causal_user_action_proven"] is False
    assert workflow["summary"]["security_properties_verified"]==0


def test_configured_workflow_transitions_are_scope_gated_and_checked_only_against_capture():
    capture=parse_har_document(_har(),lambda url,method:"app.example.test" in url,
        excluded_param=lambda name:name.lower() in {"session_id","password"},capture_id="capture-spec")
    spec={"workflow_id":"account-navigation","transitions":[
        {"transition_id":"home-next","from":"/","to":"/next?token=private-token",
         "method":"GET","expected_status":[200]},
        {"transition_id":"not-captured","from":"/","to":"/missing","method":"GET","expected_status":200},
        {"transition_id":"out-of-scope","from":"/","to":"https://outside.example/","method":"GET","expected_status":200},
    ]}
    result=validate_configured_workflow(spec,capture["exchanges"],
        lambda url,method:"outside.example" not in url and method=="GET",base_url="https://app.example.test/",
        excluded_param=lambda name:name.lower() in {"session_id","password"})
    states={item["transition_id"]:item["status"] for item in result["transitions"]}
    assert states=={"home-next":"OBSERVED_EXPECTED_STATUS","not-captured":"NOT_OBSERVED_IN_CAPTURE",
                    "out-of-scope":"BLOCKED_BY_SAVED_SCOPE"}
    assert result["summary"]["requests_replayed"]==0
    assert result["summary"]["security_properties_verified"]==0
    assert all(item["security_property_verified"] is False for item in result["transitions"])
    assert "private-token" not in repr(result)


def test_store_appends_capture_to_existing_scan_report_and_http_history(tmp_path):
    store=Store(str(tmp_path/"capture.db"))
    store.start_scan_record("scan-1","https://app.example.test/","standard",1.0)
    store.finish_scan_record("scan-1","completed",2.0)
    report={"scan":{"scan_id":"scan-1","status":"completed"},
        "workflow_model":{"states":[{"state_id":"view-home","url":"https://app.example.test/"}],"transitions":[]}}
    with store._conn() as con:
        con.execute("INSERT INTO scan_documents(scan_id,report_json) VALUES (?,?)",("scan-1",json.dumps(report)))
    capture=parse_har_document(_har(),lambda url,method:"app.example.test" in url,
        excluded_param=lambda name:name.lower() in {"session_id","password"},capture_id="capture-db")
    outcome=store.append_browser_capture("scan-1",capture,workflow_validation={"workflow_id":"w","summary":{"requests_replayed":0}})
    saved=store.get_report("scan-1")
    assert len(store.list_exchanges(scan_id="scan-1",module="browser-capture"))==2
    assert saved["browser_capture_imports"][0]["capture_id"]=="capture-db"
    assert saved["capture_summary"]["exchanges_imported"]==2
    assert saved["workflow_capture_observations"][0]["status"]=="CAPTURE_SEQUENCE_OBSERVATIONS_ONLY"
    assert saved["configured_workflow_capture_validations"][0]["summary"]["requests_replayed"]==0
    assert outcome["capture_import"]["body_policy"]=="OMITTED"
    with pytest.raises(ValueError,match="already been imported"):
        store.append_browser_capture("scan-1",capture)


def test_store_refuses_capture_for_unreported_or_running_scan(tmp_path):
    store=Store(str(tmp_path/"running.db"))
    store.start_scan_record("scan-running","https://app.example.test/","standard",1.0)
    with pytest.raises(ValueError,match="existing scan"):
        store.append_browser_capture("missing",{"capture_id":"c","exchanges":[]})
    with pytest.raises(ValueError,match="while the scan is running"):
        store.append_browser_capture("scan-running",{"capture_id":"c","exchanges":[]})


def test_cli_capture_import_uses_saved_scope_without_live_dns_or_http(tmp_path,monkeypatch,capsys):
    from vulnforge.cli import cmd_capture_import
    import socket

    store=Store(str(tmp_path/"cli.db"))
    store.start_scan_record("scan-cli","https://app.example.test/","standard",1.0)
    store.finish_scan_record("scan-cli","completed",2.0)
    scope={"allowed_hosts":["app.example.test"],"allowed_ips":[],"allowed_ports":[443],
        "allowed_prefixes":[],"excluded_hosts":[],"excluded_paths":[],"excluded_params":["password","session_id"],
        "allowed_methods":["GET"],"not_before":None,"expires_at":None,"profile":"standard",
        "allow_private":False,"confirmed":True}
    report={"scan":{"scan_id":"scan-cli","target":"https://app.example.test/","status":"completed"},
        "intelligence":{"dns":{"hostname":"app.example.test","observed_addresses":["93.184.216.34"]},
                        "target":{"hostname":"app.example.test","resolved_ips":["93.184.216.34"]}},
        "workflow_model":{"states":[{"state_id":"view-home","url":"https://app.example.test/"}],"transitions":[]}}
    with store._conn() as con:
        con.execute("UPDATE scans SET scope_json=? WHERE scan_id=?",(json.dumps(scope),"scan-cli"))
        con.execute("INSERT INTO scan_documents(scan_id,report_json) VALUES (?,?)",("scan-cli",json.dumps(report)))
    har_path=tmp_path/"capture.har"; har_path.write_text(json.dumps(_har()),encoding="utf-8")
    spec_path=tmp_path/"workflow.json"
    spec_path.write_text(json.dumps({"workflow_id":"nav","transitions":[{
        "transition_id":"home-next","from":"/","to":"/next?token=private-token",
        "method":"GET","expected_status":200}]}),encoding="utf-8")
    monkeypatch.setattr(socket,"getaddrinfo",lambda *a,**k: (_ for _ in ()).throw(AssertionError("network DNS must not run")))
    args=Namespace(confirm_authorized=True,scan_id="scan-cli",har_file=str(har_path),
        workflow_spec=str(spec_path),db=str(tmp_path/"cli.db"))
    assert cmd_capture_import(args,store)==0
    captured=capsys.readouterr().out
    assert "OBSERVED_EXPECTED_STATUS" not in captured # CLI prints counts, not raw workflow outcomes
    assert "requests_replayed" in captured
    saved=store.get_report("scan-cli")
    assert saved["configured_workflow_capture_validations"][0]["transitions"][0]["status"]=="OBSERVED_EXPECTED_STATUS"
    assert len(store.list_exchanges(scan_id="scan-cli",module="browser-capture"))==2
