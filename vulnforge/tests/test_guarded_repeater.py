"""Canonical dashboard API tests use only local mock targets."""
import asyncio
import json
import os
import uuid

import pytest

pytest.importorskip("fastapi")

# The dashboard does not initialize a second or legacy database at import.
os.environ.setdefault("VULNFORGE_SCAN_DB_PATH", f"/tmp/vf-research-{uuid.uuid4().hex}-scan.db")
import vulnforge.dashboard as server
from fastapi import HTTPException
from vulnforge.core.authorization import AuthorizationContext
from vulnforge.core.store import Store


def _source_store(tmp_path, mock_server, methods=("GET",)):
    store = Store(str(tmp_path / "research.db"))
    target = mock_server + "/about"
    store.start_scan_record("scan-research", target, "lab", 1.0)
    scope = AuthorizationContext(
        allowed_hosts=["127.0.0.1"], allowed_ports=[int(mock_server.rsplit(":", 1)[-1])],
        allowed_methods=list(methods), profile_name="lab", allow_private=True, confirmed=True,
    ).describe()
    with store._conn() as con:
        con.execute("UPDATE scans SET scope_json=?,status='completed' WHERE scan_id=?",
                    (json.dumps(scope), "scan-research"))
    store.record_exchange("scan-research", {
        "exchange_id": "source-exchange", "method": "GET", "url": target,
        "request_headers": {"host": mock_server.rsplit("//", 1)[-1]},
        "request_header_items": [["host", mock_server.rsplit("//", 1)[-1]]],
        "request_body": "", "status": 200, "module": "crawl", "response_body": "source",
    })
    return store


def _request(raw, **kwargs):
    values = {"raw_request": raw, "source_exchange_id": "source-exchange", "authorized": True}
    values.update(kwargs)
    return server.RepeaterRequest(**values)


def test_guarded_repeater_replays_one_request_through_saved_loopback_scope(tmp_path, mock_server, monkeypatch):
    store = _source_store(tmp_path, mock_server)
    monkeypatch.setattr(server, "_v2_store", lambda: store)
    raw = f"GET /about HTTP/1.1\r\nHost: {mock_server.rsplit('//', 1)[-1]}\r\n\r\n"
    result = asyncio.run(server.api_repeater_send(_request(raw)))
    assert result["status"] == 200
    assert result["module"] == "repeater"
    assert result["parent_exchange_id"] == "source-exchange"
    assert result["request_id"] != result["response_id"]
    assert store.get_exchange(result["exchange_id"])["parent_exchange_id"] == "source-exchange"
    assert store.list_exchanges(scan_id="scan-research", module="repeater")[0]["exchange_id"] == result["exchange_id"]


def test_database_backed_sse_replays_completed_scan_events_after_server_restart(tmp_path, monkeypatch):
    store=Store(str(tmp_path/"events-api.db"))
    scan_id="vf-event-api-1234"
    store.start_scan_record(scan_id,"https://demo.example/","passive",1.0)
    first=store.record_event(scan_id,{"kind":"stage-start","message":"Recon started","data":{"stage":"recon"},"timestamp":2.0})
    final=store.record_event(scan_id,{"kind":"scan-complete","message":"Scan completed","data":{"status":"completed"},"timestamp":3.0})
    store.finish_scan_record(scan_id,"completed",3.0)
    monkeypatch.setattr(server,"_v2_store",lambda:store)

    from starlette.requests import Request
    scope={"type":"http","method":"GET","path":f"/api/vf/scans/{scan_id}/events",
           "headers":[(b"last-event-id",str(first["event_id"]).encode())],"query_string":b"",
           "server":("test",80),"client":("127.0.0.1",1234),"scheme":"http"}
    response=asyncio.run(server.api_stream_vf_scan_events(scan_id,Request(scope),after=0))
    async def read_body():
        chunks=[]
        async for chunk in response.body_iterator:
            chunks.append(chunk.decode() if isinstance(chunk,bytes) else str(chunk))
        return "".join(chunks)
    stream=asyncio.run(read_body())
    assert f"id: {final['event_id']}" in stream
    assert '"kind":"scan-complete"' in stream
    assert f"id: {first['event_id']}" not in stream

    event_log=asyncio.run(server.api_get_vf_event_log(scan_id,after=0,limit=10))
    assert [item["event_id"] for item in event_log["items"]]==[first["event_id"],final["event_id"]]


def test_dashboard_scan_stream_persists_real_engine_events_and_replays_after_worker_restart(tmp_path, monkeypatch, mock_server):
    database=tmp_path/"live-dashboard.db"
    monkeypatch.setenv("VULNFORGE_SCAN_DB_PATH",str(database))
    request=server.V2ScanRequest(target_url=mock_server,authorized=True,test_profile="passive",
                                 safety_mode="LAB",lab_mode=True)
    async def run_scan_to_completion():
        result=await server.api_start_vf_scan(request)
        scan_id=result["scan_id"]
        deadline=asyncio.get_running_loop().time()+45
        while server.V2_SCAN_RUNS[scan_id]["status"]=="running":
            if asyncio.get_running_loop().time()>deadline:
                raise AssertionError("local dashboard scan did not reach a terminal state")
            await asyncio.sleep(0.02)
        return scan_id
    scan_id=asyncio.run(run_scan_to_completion())
    store=Store(str(database))
    events=store.list_scan_events(scan_id,limit=1000)
    assert events and events[0]["kind"]=="scan-started"
    assert any(item["kind"]=="stage-start" for item in events)
    assert any(item["kind"]=="http-exchange" for item in events)
    assert events[-1]["kind"]=="scan-complete"
    assert store.list_exchanges(scan_id=scan_id)

    # Simulate a server restart: the in-memory worker registry is intentionally empty.
    server.V2_SCAN_RUNS.pop(scan_id,None)
    from starlette.requests import Request
    scope={"type":"http","method":"GET","path":f"/api/vf/scans/{scan_id}/events",
           "headers":[],"query_string":b"","server":("test",80),
           "client":("127.0.0.1",1234),"scheme":"http"}
    response=asyncio.run(server.api_stream_vf_scan_events(scan_id,Request(scope),after=0))
    async def read_events():
        chunks=[]
        async for chunk in response.body_iterator:
            chunks.append(chunk.decode() if isinstance(chunk,bytes) else str(chunk))
        return "".join(chunks)
    replay=asyncio.run(read_events())
    assert '"kind":"scan-started"' in replay and '"kind":"scan-complete"' in replay
    assert scan_id in replay


def test_research_object_api_is_allowlisted_scan_scoped_and_searchable(tmp_path, monkeypatch):
    store=Store(str(tmp_path/"research-objects.db"))
    scan_id="vf-research-objects-123"
    store.start_scan_record(scan_id,"https://demo.example/","passive",1.0)
    report={"scan":{"scan_id":scan_id,"target":"https://demo.example/"},
            "hypotheses":[{"hypothesis_id":"hyp-1","category":"authorization","reason":"cross-account boundary"}],
            "tests":[{"test_id":"test-1","hypothesis_id":"hyp-1","control_exchange_id":"ex-ctrl","differential":{"status_changed":True}}],
            "test_plan":[],"parameters":[],"findings":[],"candidates":[],"vulnerability_matrix":[]}
    import sqlite3
    with sqlite3.connect(store.path) as con:
        con.execute("INSERT INTO scan_documents(scan_id,report_json) VALUES (?,?)",(scan_id,json.dumps(report)))
    monkeypatch.setattr(server,"_v2_store",lambda:store)
    hypotheses=asyncio.run(server.api_get_vf_scan_objects(scan_id,"hypotheses",search="cross-account",limit=50,offset=0))
    controls=asyncio.run(server.api_get_vf_scan_objects(scan_id,"controls",search=None,limit=50,offset=0))
    differentials=asyncio.run(server.api_get_vf_scan_objects(scan_id,"differentials",search=None,limit=50,offset=0))
    assert hypotheses["items"][0]["hypothesis_id"]=="hyp-1"
    assert controls["items"][0]["value"]=="ex-ctrl"
    assert differentials["items"][0]["value"]=={"status_changed":True}
    with pytest.raises(HTTPException):
        asyncio.run(server.api_get_vf_scan_objects(scan_id,"../../scans",search=None,limit=50,offset=0))


def test_dashboard_json_report_export_uses_versioned_structured_renderer(tmp_path, monkeypatch):
    store=Store(str(tmp_path/"json-export.db"))
    scan_id="vf-json-export-1234"
    store.start_scan_record(scan_id,"https://demo.example/","passive",1.0)
    report={"scan":{"scan_id":scan_id,"target":"https://demo.example/","profile":"passive",
                     "started_at":1.0,"status":"completed"},
            "statistics":{},"scope":{},"findings":[],"candidates":[],"tests":[],
            "hypotheses":[],"endpoints":[],"parameters":[],"vulnerability_matrix":[]}
    import sqlite3
    with sqlite3.connect(store.path) as con:
        con.execute("INSERT INTO scan_documents(scan_id,report_json) VALUES (?,?)",(scan_id,json.dumps(report)))
    monkeypatch.setattr(server,"_v2_store",lambda:store)
    response=asyncio.run(server.api_export_vf_report(scan_id,"json"))
    exported=json.loads(response.body)
    assert response.media_type=="application/json"
    assert exported["schema_version"]=="1.0"
    assert exported["scan"]["scan_id"]==scan_id
    assert exported["findings"]==[] and exported["candidates"]==[]


def test_web_dashboard_shell_exposes_database_backed_event_explorer():
    import httpx
    async def fetch_root():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=server.app),base_url="http://testserver") as client:
            return await client.get("/")
    response=asyncio.run(fetch_root())
    assert response.status_code==200
    assert "access-control-allow-origin" not in response.headers
    assert 'data-route="events"' in response.text
    assert 'id="events-table-body"' in response.text
    assert 'id="events-more"' in response.text
    assert 'id="event-detail"' in response.text
    assert 'data-route="research"' in response.text
    assert 'id="research-kind-select"' in response.text
    assert 'data-route="parameters"' in response.text
    assert 'id="parameters-table-body"' in response.text


def test_dashboard_response_diff_returns_structured_json_and_exchange_identities(tmp_path, mock_server, monkeypatch):
    store = _source_store(tmp_path, mock_server)
    store.record_exchange("scan-research", {
        "exchange_id": "second-exchange", "method": "GET", "url": mock_server + "/about",
        "status": 200, "module": "crawl", "response_body": '{"user":{"id":2}}',
    })
    first = store.get_exchange("source-exchange")
    first["response_body"] = '{"user":{"id":1}}'
    with store._conn() as con:
        con.execute("UPDATE exchanges SET data_json=? WHERE exchange_id=?",
                    (json.dumps(first), "source-exchange"))
    monkeypatch.setattr(server, "_v2_store", lambda: store)
    result = asyncio.run(server.api_diff_vf_exchanges("source-exchange", "second-exchange"))
    assert result["request_ids"]["a"]
    assert result["response_ids"]["b"]
    assert result["body"]["format"] == "json"
    assert result["body"]["changes"] == [{"kind": "changed", "path": "/user/id", "before": 1, "after": 2}]
    assert "not a vulnerability" in result["interpretation"]


def test_guarded_repeater_requires_fresh_authorization_and_source_scope(tmp_path, mock_server, monkeypatch):
    store = _source_store(tmp_path, mock_server)
    monkeypatch.setattr(server, "_v2_store", lambda: store)
    raw = f"GET /about HTTP/1.1\nHost: {mock_server.rsplit('//', 1)[-1]}\n\n"
    with pytest.raises(HTTPException) as denied:
        asyncio.run(server.api_repeater_send(_request(raw, authorized=False)))
    assert denied.value.status_code == 403
    with pytest.raises(HTTPException) as no_source:
        asyncio.run(server.api_repeater_send(_request(raw, source_exchange_id="missing")))
    assert no_source.value.status_code == 404


def test_guarded_repeater_rejects_host_escape_and_redacted_auth_state(tmp_path, mock_server, monkeypatch):
    store = _source_store(tmp_path, mock_server)
    monkeypatch.setattr(server, "_v2_store", lambda: store)
    with pytest.raises(HTTPException) as escaped:
        asyncio.run(server.api_repeater_send(_request(
            "GET / HTTP/1.1\nHost: example.org\n\n")))
    assert escaped.value.status_code == 403
    with pytest.raises(HTTPException) as redacted:
        asyncio.run(server.api_repeater_send(_request(
            f"GET / HTTP/1.1\nHost: {mock_server.rsplit('//', 1)[-1]}\nAuthorization: [REDACTED]\n\n")))
    assert redacted.value.status_code == 422


def test_guarded_repeater_requires_explicit_per_request_state_change_authorization(tmp_path, mock_server, monkeypatch):
    store = _source_store(tmp_path, mock_server, methods=("GET", "POST"))
    monkeypatch.setattr(server, "_v2_store", lambda: store)
    raw = f"POST /about HTTP/1.1\nHost: {mock_server.rsplit('//', 1)[-1]}\nContent-Type: text/plain\n\nprobe"
    with pytest.raises(HTTPException) as denied:
        asyncio.run(server.api_repeater_send(_request(raw, confirm_state_change=False)))
    assert denied.value.status_code == 403
