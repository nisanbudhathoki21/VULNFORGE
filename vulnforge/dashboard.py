"""Single canonical VulnForge web dashboard and API.

All state is read from/written to :class:`vulnforge.core.store.Store`; no legacy
engine or second database is initialized here. Bind to loopback by default.
"""
from __future__ import annotations
import asyncio
import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import sqlite3
import sys
import time
import urllib.parse
import uuid
from pathlib import Path
from typing import Any, Dict, Optional
from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

app=FastAPI(title="VulnForge Security Assessment Dashboard",version="0.4.0")
V2_SCAN_RUNS: Dict[str,Dict[str,Any]]={}
STATIC_DIR=str(Path(__file__).with_name("dashboard_static"))
app.mount("/static",StaticFiles(directory=STATIC_DIR),name="static")

class RepeaterRequest(BaseModel):
    raw_request: str
    source_exchange_id: str = ""
    authorized: bool = False
    confirm_state_change: bool = False
    timeout: float = Field(default=8.0, ge=0.5, le=10.0)
    title: str = "Scoped Repeater"

class UtilityRequest(BaseModel):
    text: str
    operation: str

class V2ScanRequest(BaseModel):
    target_url: str
    authorized: bool = False
    test_profile: str = "passive"
    safety_mode: str = "PASSIVE"
    lab_mode: bool = False
    store_sensitive_http: bool = False
    headers: Dict[str,str] = Field(default_factory=dict)
    auth_data: Dict[str,Any] = Field(default_factory=dict)
    scope_policy: Dict[str,Any] = Field(default_factory=dict)

def _has_v2_scan_schema(path):
    if not os.path.isfile(path): return False
    try:
        uri="file:"+urllib.parse.quote(os.path.abspath(path))+"?mode=ro"
        with sqlite3.connect(uri,uri=True) as probe:
            exists=probe.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='scans'").fetchone()
            if not exists: return False
            columns={row[1] for row in probe.execute("PRAGMA table_info(scans)")}
            return {"scan_id","target","profile"}.issubset(columns)
    except sqlite3.DatabaseError:
        return False

def _validate_auth_data(data,target_url,priority):
    if not data: return {}
    try: size=len(json.dumps(data,ensure_ascii=False).encode("utf-8"))
    except (TypeError,ValueError) as exc:
        raise HTTPException(status_code=422,detail="Authorization test configuration must be valid JSON data.") from exc
    if size>16000 or not isinstance(data,dict) or set(data)-{"identities","authorization_tests"}:
        raise HTTPException(status_code=422,detail="Authorization test configuration must be an object under 16 KB with only identities and authorization_tests.")
    from vulnforge.engine.vulnerability_registry import VULNERABILITY_CLASSES
    if priority not in VULNERABILITY_CLASSES["bola"]["profiles"] and priority!="full":
        raise HTTPException(status_code=422,detail="Configured BOLA testing requires the Critical, High, or Full vulnerability portfolio.")
    identities=data.get("identities")
    tests=data.get("authorization_tests")
    if not isinstance(identities,dict) or not isinstance(tests,list) or not tests or len(identities)>4 or len(tests)>10:
        raise HTTPException(status_code=422,detail="Provide 2–4 named identities and 1–10 authorization test specifications.")
    token_re=r"[!#$%&'*+.^_`|~0-9A-Za-z-]+"
    managed={"host","content-length","transfer-encoding","connection"}
    header_bytes=0
    for label,identity in identities.items():
        if not isinstance(label,str) or not label or len(label)>64 or not isinstance(identity,dict) or not isinstance(identity.get("headers"),dict):
            raise HTTPException(status_code=422,detail="Each identity must have a short name and a headers object.")
        if len(identity["headers"])>30:
            raise HTTPException(status_code=422,detail="At most 30 headers may be provided per identity.")
        for name,value in identity["headers"].items():
            if not isinstance(name,str) or not re.fullmatch(token_re,name) or name.lower() in managed or not isinstance(value,str) or "\r" in value or "\n" in value:
                raise HTTPException(status_code=422,detail="Identity headers contain an invalid name or value.")
            header_bytes+=len(name)+len(value)
    for spec in tests:
        if not isinstance(spec,dict):
            raise HTTPException(status_code=422,detail="Each authorization test must be an object.")
        url=spec.get("url");owner=spec.get("owner_identity");other=spec.get("other_identity")
        if (not isinstance(url,str) or not url.startswith("/") or url.startswith("//") or
            urllib.parse.urlsplit(url).scheme or urllib.parse.urlsplit(url).netloc or
            not isinstance(owner,str) or not isinstance(other,str) or
            owner not in identities or other not in identities or owner==other):
            raise HTTPException(status_code=422,detail="Each test must use a same-origin relative path and two distinct configured identities.")
        if not isinstance(spec.get("owner_field"),str) or not spec.get("owner_field") or len(spec["owner_field"])>100:
            raise HTTPException(status_code=422,detail="Each test requires an owner_field name.")
        if "owner_value" not in spec or isinstance(spec["owner_value"],(dict,list)):
            raise HTTPException(status_code=422,detail="Each test requires a scalar owner_value.")
        sensitive=spec.get("sensitive_fields")
        assertion=spec.get("identity_assertion")
        if not isinstance(sensitive,list) or not sensitive or len(sensitive)>20 or not all(isinstance(x,str) and x and len(x)<=100 for x in sensitive):
            raise HTTPException(status_code=422,detail="Each test requires 1–20 sensitive_fields names.")
        if not isinstance(assertion,dict) or not isinstance(assertion.get("header"),str) or not re.fullmatch(token_re,assertion["header"]):
            raise HTTPException(status_code=422,detail="Each test requires a valid identity_assertion response header.")
        for key in ("owner_value","other_value"):
            if not isinstance(assertion.get(key),str) or "\r" in assertion[key] or "\n" in assertion[key]:
                raise HTTPException(status_code=422,detail="Identity assertion values must be single-line strings.")
        header_bytes+=len(assertion["header"])+len(assertion["owner_value"])+len(assertion["other_value"])
    if header_bytes>16000:
        raise HTTPException(status_code=422,detail="Combined authorization identity headers exceed 16 KB.")
    return data

def _v2_store():
    """Open the structured scan store without touching an incompatible legacy DB."""
    from vulnforge.core.store import Store as V2Store
    path=os.path.abspath(os.environ.get("VULNFORGE_SCAN_DB_PATH", "vulnforge.db"))
    if os.path.isfile(path):
        try:
            uri="file:"+urllib.parse.quote(path)+"?mode=ro"
            with sqlite3.connect(uri,uri=True) as probe:
                exists=probe.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='scans'").fetchone()
                if exists:
                    columns={row[1] for row in probe.execute("PRAGMA table_info(scans)")}
                    if not {"scan_id","target","profile"}.issubset(columns):
                        raise HTTPException(status_code=409,detail=(
                            "The configured scan database is a different legacy schema. "
                            "Set VULNFORGE_SCAN_DB_PATH to a structured VULNFORGE scan database."
                        ))
        except HTTPException:
            raise
        except sqlite3.DatabaseError as exc:
            raise HTTPException(status_code=409,detail="The configured scan database could not be read safely.") from exc
    try:
        return V2Store(path)
    except (sqlite3.DatabaseError,RuntimeError) as exc:
        raise HTTPException(status_code=409,detail="The configured scan database is not compatible with this VULNFORGE build.") from exc


def _replay_access_allowed(request: Optional[Request]) -> None:
    """Protect active replay while keeping the dashboard readable remotely.

    A dashboard bound to a LAN/public interface is intentionally read-only
    unless an operator configures VULNFORGE_DASHBOARD_TOKEN. The browser
    consent checkbox is not treated as authentication.
    """
    configured = os.environ.get("VULNFORGE_DASHBOARD_TOKEN", "")
    supplied = request.headers.get("x-vulnforge-dashboard-token", "") if request else ""
    if configured:
        if not supplied or not hmac.compare_digest(supplied, configured):
            raise HTTPException(status_code=401, detail="Guarded replay requires the configured dashboard access token.")
        return
    client_host = request.client.host if request and request.client else "127.0.0.1"
    try:
        is_loopback = ipaddress.ip_address(client_host).is_loopback
    except ValueError:
        is_loopback = client_host.lower() in {"localhost", "localhost.localdomain"}
    if not is_loopback:
        raise HTTPException(status_code=403, detail="Remote dashboard access is read-only. Configure VULNFORGE_DASHBOARD_TOKEN for guarded replay.")

@app.get("/", response_class=HTMLResponse)
async def serve_index():
    index_file = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_file):
        with open(index_file, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse("<h1>VulnForge dashboard is running</h1>")

def _publish_v2_event(scan_id, runtime, store, event):
    """Persist a real engine event, then wake active SSE clients.

    SQLite is the source of truth; in-memory queues are wake-up signals only,
    so clients can reconnect, replay missed events, and load finished scans.
    """
    try:
        event=store.record_event(scan_id,event)
    except Exception as exc:
        # Telemetry persistence failure must not interrupt authorized scan work.
        # Keep this real event ephemeral and expose the persistence state.
        print(f"[VULNFORGE] event persistence unavailable for {scan_id} ({type(exc).__name__})",file=sys.stderr)
        event={**event,"event_id":None,"persistence":"unavailable"}
    runtime["events"].append(event)
    if len(runtime["events"])>3000:
        del runtime["events"][:len(runtime["events"])-3000]
    for queue in tuple(runtime["queues"]):
        try:
            if not queue.full(): queue.put_nowait(None)
        except Exception:
            pass
    return event

async def _run_v2_scan_task(scan_id, config, authorization, store):
    runtime=V2_SCAN_RUNS[scan_id]
    sensitive_headers=set(config.extra_headers)
    for identity in config.auth_data.get("identities",{}).values():
        sensitive_headers.update((identity.get("headers") or {}).keys())
    def on_event(kind,message,data):
        payload=dict(data or {})
        exchange=payload.pop("exchange",None)
        if kind=="http-exchange" and isinstance(exchange,dict):
            sensitive_module=str(exchange.get("module","")) in {"browser-workflow","sql-injection-validation"}
            store.record_exchange(scan_id,exchange,sensitive_headers=sensitive_headers,
                                  redact=(not config.store_sensitive_http or sensitive_module))
            payload.pop("url",None)
            payload.pop("error",None)
            payload.update({"exchange_id":exchange.get("exchange_id"),"method":exchange.get("method"),
                "status":exchange.get("status"),"module":exchange.get("module"),
                "duration_ms":exchange.get("duration_ms"),
                "response_chars":len(exchange.get("response_body","") or "")})
            message=f"{exchange.get('method','HTTP')} exchange · {exchange.get('status') or 'no response'}"
        event={"kind":kind,"message":str(message),"data":payload,"timestamp":time.time()}
        _publish_v2_event(scan_id,runtime,store,event)
    try:
        from vulnforge.engine.orchestrator import _run_async
        result=await _run_async(config,authorization,event_fn=on_event)
        await asyncio.to_thread(store.save_scan,result)
        runtime["status"]=("aborted" if result.aborted else ("partial" if result.context.stop_reason else "completed"))
        runtime["finished_at"]=time.time()
        final={"kind":"scan-complete","message":f"Scan {runtime['status']}",
               "data":{"scan_id":scan_id,"status":runtime["status"]},"timestamp":time.time()}
    except Exception as exc:
        print(f"[VULNFORGE] scan {scan_id} failed ({type(exc).__name__}): {exc}",file=sys.stderr)
        runtime["status"]="failed"
        runtime["finished_at"]=time.time()
        try: store.finish_scan_record(scan_id,"failed",runtime["finished_at"])
        except Exception: pass
        final={"kind":"scan-error","message":"Scan failed; consult the server log for details.",
               "data":{"scan_id":scan_id,"status":"failed","error":"Scan failed; consult the server log."},"timestamp":time.time()}
    _publish_v2_event(scan_id,runtime,store,final)

@app.post("/api/vf/scans/start")
async def api_start_vf_scan(req: V2ScanRequest):
    if not req.authorized:
        raise HTTPException(status_code=403,detail="Confirm ownership or explicit authorization before starting a scan.")
    try:
        from vulnforge.cli import normalize_target
        original,target=normalize_target(req.target_url)
    except ValueError as exc:
        raise HTTPException(status_code=422,detail=str(exc)) from exc
    parsed=urllib.parse.urlsplit(target)
    host=(parsed.hostname or "").lower()
    try: loopback=ipaddress.ip_address(host).is_loopback
    except ValueError: loopback=host=="localhost"
    if req.lab_mode and not loopback:
        raise HTTPException(status_code=400,detail="LAB mode is restricted to loopback targets.")
    if loopback and not req.lab_mode:
        raise HTTPException(status_code=400,detail="Loopback targets require the explicit LAB option.")
    if req.store_sensitive_http:
        bind_host=os.environ.get("HOST","127.0.0.1").lower()
        try: local_dashboard=ipaddress.ip_address(bind_host).is_loopback
        except ValueError: local_dashboard=bind_host=="localhost"
        if not local_dashboard:
            raise HTTPException(status_code=400,detail=(
                "Plaintext Cookie/Authorization history requires a loopback-only dashboard. "
                "Start with HOST=127.0.0.1 or disable sensitive HTTP storage."
            ))
    allowed_profiles={"passive","critical","high","medium","low","full"}
    priority=(req.test_profile or "passive").lower()
    if priority not in allowed_profiles:
        raise HTTPException(status_code=422,detail="Unknown vulnerability priority profile.")
    safety_mode=str(req.safety_mode or "PASSIVE").upper()
    if req.lab_mode:
        safety_mode="LAB"
    elif safety_mode not in {"PASSIVE","SAFE_ACTIVE","CONTROLLED_ACTIVE"}:
        raise HTTPException(status_code=422,detail="safety_mode must be PASSIVE, SAFE_ACTIVE, or CONTROLLED_ACTIVE; LAB uses the loopback LAB option.")
    if len(req.headers)>50:
        raise HTTPException(status_code=422,detail="At most 50 extra request headers may be configured.")
    extra_headers={}; seen_names=set(); header_bytes=0
    for name,value in req.headers.items():
        name=str(name).strip(); value=str(value)
        lowered=name.lower()
        if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+",name) or "\r" in value or "\n" in value:
            raise HTTPException(status_code=422,detail="Invalid HTTP header name or value.")
        if lowered in seen_names or lowered in {"host","content-length","transfer-encoding","connection"}:
            raise HTTPException(status_code=422,detail="Duplicate or transport-managed request header.")
        seen_names.add(lowered); header_bytes+=len(name)+len(value)
        if header_bytes>16000:
            raise HTTPException(status_code=422,detail="Combined extra request headers exceed 16 KB.")
        extra_headers[name]=value
    auth_data=_validate_auth_data(req.auth_data,target,priority)
    scope=req.scope_policy if isinstance(req.scope_policy,dict) else None
    if scope is None:
        raise HTTPException(status_code=422,detail="scope_policy must be an object.")
    scope_keys={"allowed_hosts","allowed_ips","allowed_ports","allowed_prefixes","excluded_hosts",
                "excluded_paths","excluded_params","allowed_methods","not_before","expires_at"}
    unknown_scope=set(scope)-scope_keys
    if unknown_scope:
        raise HTTPException(status_code=422,detail="Unknown scope_policy key(s): "+", ".join(sorted(unknown_scope)))
    def scope_list(name, default=None, maximum=500):
        value=scope.get(name,default or [])
        if not isinstance(value,list) or len(value)>maximum:
            raise HTTPException(status_code=422,detail=f"scope_policy.{name} must be a list of at most {maximum} entries.")
        return value
    scoped_hosts=scope_list("allowed_hosts",scope.get("hosts",[]),100)
    if "hosts" in scope:
        raise HTTPException(status_code=422,detail="Use scope_policy.allowed_hosts, not hosts.")
    policy={"allowed_hosts":sorted({host,*[str(x) for x in scoped_hosts]}),
        "allowed_ips":scope_list("allowed_ips"),"allowed_ports":scope_list("allowed_ports"),
        "allowed_prefixes":scope_list("allowed_prefixes"),"excluded_hosts":scope_list("excluded_hosts"),
        "excluded_paths":scope_list("excluded_paths"),"excluded_params":scope_list("excluded_params"),
        "allowed_methods":scope_list("allowed_methods",["GET","HEAD","OPTIONS"],16),
        "not_before":scope.get("not_before"),"expires_at":scope.get("expires_at")}
    from vulnforge.core.authorization import AuthorizationContext
    from vulnforge.engine.orchestrator import ScanConfig
    scan_id="vf-"+uuid.uuid4().hex[:12]
    safety_profile={"PASSIVE":"passive","SAFE_ACTIVE":"safe-active",
                    "CONTROLLED_ACTIVE":"controlled-active","LAB":"lab"}[safety_mode]
    try:
        auth=AuthorizationContext(**policy,profile_name=safety_profile,
            allow_private=bool(req.lab_mode and loopback),confirmed=True)
    except (TypeError,ValueError) as exc:
        raise HTTPException(status_code=422,detail=str(exc)) from exc
    config=ScanConfig(target=target,scan_id=scan_id,profile_name=safety_profile,
        **policy,allow_private=bool(req.lab_mode and loopback),
        authorization_confirmed=True,active_requested=(priority!="passive"),
        test_profile=priority,test_profile_explicit=(priority!="passive"),
        original_target=original,auto_scheme=("://" not in original),
        extra_headers=extra_headers,auth_data=auth_data,
        store_sensitive_http=req.store_sensitive_http)
    store=_v2_store()
    if req.store_sensitive_http:
        try: os.chmod(store.path,0o600)
        except OSError as exc:
            raise HTTPException(status_code=500,detail="Could not secure the scan database file for sensitive HTTP history.") from exc
    started=time.time()
    store.start_scan_record(scan_id,target,safety_profile,started)
    V2_SCAN_RUNS[scan_id]={"status":"running","started_at":started,"finished_at":None,
                           "events":[],"queues":set()}
    _publish_v2_event(scan_id,V2_SCAN_RUNS[scan_id],store,{"kind":"scan-started",
        "message":"Authorized scan accepted; engine task created.",
        "data":{"scan_id":scan_id,"target":target,"status":"running"},"timestamp":started})
    asyncio.create_task(_run_v2_scan_task(scan_id,config,auth,store))
    return {"scan_id":scan_id,"target":target,"status":"running","started_at":started,
            "sensitive_values_stored":req.store_sensitive_http,
            "configured_authorization_tests":len(auth_data.get("authorization_tests",[]))}

@app.get("/api/vf/scans")
async def api_get_vf_scans():
    """Structured scan list enriched with actual stored counts and state."""
    return _v2_store().list_scans()

@app.get("/api/vf/dashboard")
async def api_get_vf_dashboard():
    store=_v2_store(); scans=store.list_scans()
    recent_findings=store.list_all_findings(limit=5)
    finding_states=store.finding_state_counts()
    normalized=store.relational_metrics()
    database=store.database_status(); database.pop("path", None)
    return {"scan_count":len(scans),"target_count":normalized.get("targets",len({s.get("target") for s in scans if s.get("target")})),
        "project_count":normalized.get("projects",0),"host_count":normalized.get("hosts",0),
        "verified_count":sum(s.get("verified_count",0) for s in scans),
        "candidate_count":sum(s.get("candidates_count",0) for s in scans),
        "finding_count":sum(finding_states.values()),"finding_state_counts":finding_states,
        "endpoint_count":normalized.get("endpoints",sum(s.get("endpoints_count",0) for s in scans)),
        "parameter_count":normalized.get("parameters",0),
        "request_count":normalized.get("requests",sum(s.get("requests_count",0) for s in scans)),
        "response_count":normalized.get("responses",0),"test_count":normalized.get("tests",0),
        "evidence_count":normalized.get("evidence",0),"control_count":normalized.get("controls",0),
        "differential_count":normalized.get("diffs",0),"database":database,
        "recent_scans":scans[:5],"recent_findings":recent_findings}

@app.get("/api/vf/settings")
async def api_get_vf_settings():
    """Expose only canonical, redacted runtime and structured-store metadata."""
    scan_path=os.path.abspath(os.environ.get("VULNFORGE_SCAN_DB_PATH","vulnforge.db"))
    exists=os.path.isfile(scan_path)
    scan_status=("compatible" if _has_v2_scan_schema(scan_path) else ("incompatible" if exists else "not created yet"))
    try:
        scan_stat=os.stat(scan_path) if exists else None
        permissions=(oct(scan_stat.st_mode & 0o777) if scan_stat else "not created")
        size_bytes=(scan_stat.st_size if scan_stat else None)
    except OSError:
        permissions="unavailable";size_bytes=None
    return {"runtime":{"bind_host":os.environ.get("HOST","127.0.0.1"),"port":os.environ.get("PORT","8000")},
        "structured_database":{"file":os.path.basename(scan_path),"status":scan_status,
            "permissions":permissions,"size_bytes":size_bytes},
        "sensitive_http_history":"Redacted by default; per-scan plaintext opt-in is loopback-only.",
        "traffic_capture":"Prepared request and parsed response; not packet/TLS capture.",
        "active_verification":"Current confirmable checks: configured read-only two-identity authorization and paired open redirect. CORS and SQL checks are observation-only; other classes remain unsupported/not tested.",
        "configuration_source":"Environment variables; restart the dashboard to change bind/database paths."}


@app.get("/api/vf/targets")
async def api_get_vf_targets():
    scans=_v2_store().list_scans(); targets={}
    for scan in scans:
        target=scan.get("target") or ""
        if not target: continue
        entry=targets.setdefault(target,{"target":target,"scan_count":0,"last_scan":None,"status":"unknown"})
        entry["scan_count"]+=1
        if entry["last_scan"] is None:
            entry["last_scan"]=scan.get("started_at")
            entry["status"]=scan.get("status") or "unknown"
    return list(targets.values())

@app.get("/api/vf/endpoints")
async def api_get_vf_endpoints(scan_id: Optional[str]=Query(None),search: Optional[str]=Query(None),
                               limit: int=Query(500,ge=1,le=1000),offset: int=Query(0,ge=0)):
    return _v2_store().list_endpoints(scan_id or "",search or "",limit,offset)

@app.get("/api/vf/technologies")
async def api_get_vf_technologies(scan_id: Optional[str]=Query(None),search: Optional[str]=Query(None),
                                  limit: int=Query(500,ge=1,le=1000),offset: int=Query(0,ge=0)):
    return _v2_store().list_technologies(scan_id or "",search or "",limit,offset)

@app.get("/api/vf/findings")
async def api_get_vf_findings(scan_id: Optional[str]=Query(None),status: Optional[str]=Query(None),
                              severity: Optional[str]=Query(None),search: Optional[str]=Query(None),
                              limit: int=Query(500,ge=1,le=1000),offset: int=Query(0,ge=0)):
    return _v2_store().list_all_findings(scan_id or "",status or "",severity or "",search or "",limit,offset)

@app.get("/api/vf/evidence")
async def api_get_vf_evidence(scan_id: Optional[str]=Query(None),finding_id: Optional[str]=Query(None),
                             limit: int=Query(500,ge=1,le=1000),offset: int=Query(0,ge=0)):
    return _v2_store().list_evidence(scan_id or "",finding_id or "",limit,offset)

@app.get("/api/vf/findings/{finding_id}")
async def api_get_vf_finding(finding_id: str):
    store=_v2_store(); finding=store.get_finding(finding_id)
    if not finding: raise HTTPException(status_code=404, detail="Finding not found")
    return {"finding": finding, "evidence_chain": store.get_evidence_chain(finding_id)}

@app.get("/api/vf/endpoints/{endpoint_id}")
async def api_get_vf_endpoint(endpoint_id: str):
    endpoint=_v2_store().get_endpoint_detail(endpoint_id)
    if not endpoint: raise HTTPException(status_code=404, detail="Endpoint not found")
    return endpoint

@app.get("/api/vf/search")
async def api_search_vf(q: str=Query(..., min_length=1, max_length=200), limit: int=Query(50,ge=1,le=200)):
    return _v2_store().global_search(q, limit)

@app.get("/api/vf/reports")
async def api_get_vf_reports():
    return _v2_store().list_scans()

@app.get("/api/vf/scans/{scan_id}")
async def api_get_vf_scan(scan_id: str):
    store=_v2_store()
    report=store.get_report(scan_id)
    if report is not None:
        from vulnforge.report.json_report import build_report_dict
        report=build_report_dict(report)
        scan_info=report.get("scan",{}) if isinstance(report.get("scan"),dict) else {}
        status=scan_info.get("status") or V2_SCAN_RUNS.get(scan_id,{}).get("status")
        report["status"]=status
        report["in_progress"]=status=="running"
        return report
    scan=store.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404,detail="Scan not found")
    return {"scan":scan,"status":scan.get("status"),"in_progress":scan.get("status")=="running"}

@app.get("/api/vf/scans/{scan_id}/coverage")
async def api_get_vf_scan_coverage(scan_id: str):
    store = _v2_store(); report = store.get_report(scan_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Scan report not found")
    from vulnforge.core.coverage import coverage_summary
    class _Context:
        vulnerability_matrix = report.get("vulnerability_matrix", [])
        endpoints = {str(i): item for i, item in enumerate(report.get("endpoints", []) or [])}
        parameters = {str(i): item for i, item in enumerate(report.get("parameters", []) or [])}
        requester = type("Requester", (), {"exchanges": report.get("exchanges", []) or report.get("http_history", []) or []})()
    return {"scan_id": scan_id, **coverage_summary(_Context())}

@app.get("/api/vf/scans/{scan_id}/objects/{object_type}")
async def api_get_vf_scan_objects(scan_id: str, object_type: str,
                                 search: Optional[str]=Query(None,max_length=200),
                                 limit: int=Query(500,ge=1,le=1000),
                                 offset: int=Query(0,ge=0)):
    """Return allowlisted, scan-scoped research objects as structured JSON."""
    store=_v2_store(); scan=store.get_scan(scan_id)
    if scan is None: raise HTTPException(status_code=404,detail="Scan not found")
    report=store.get_report(scan_id) or {}
    allowed={"parameters","hypotheses","tests","test_plan","api_inventory","api_documents",
             "actors","resources","security_properties","asset_nodes","asset_edges","attack_paths",
             "observations","controls","differentials","evidence","events","application_model"}
    kind=object_type.lower()
    if kind not in allowed: raise HTTPException(status_code=404,detail="Unknown stored research object type")
    if kind=="observations":
        items=(report.get("discovery_signals",[]) or [])+(report.get("live_observations",[]) or [])
    elif kind=="evidence": items=store.list_evidence(scan_id=scan_id,limit=10000,offset=0)
    elif kind=="events": items=store.list_scan_events(scan_id,limit=10000)
    elif kind in {"controls","differentials"}:
        needle=kind[:-1]
        items=[]
        def collect(value,owner,path=""):
            if isinstance(value,dict):
                for key,item in value.items():
                    next_path=f"{path}.{key}" if path else str(key)
                    if needle in str(key).lower():
                        items.append({"test_id":owner,"field_path":next_path,"value":item})
                    elif isinstance(item,(dict,list)): collect(item,owner,next_path)
            elif isinstance(value,list):
                for index,item in enumerate(value): collect(item,owner,f"{path}[{index}]")
        for test in report.get("tests",[]) or []:
            if isinstance(test,dict): collect(test,str(test.get("test_id") or test.get("type") or "test"))
        for plan in report.get("test_plan",[]) or []:
            if kind=="controls" and isinstance(plan,dict):
                methodology=plan.get("methodology",{})
                if isinstance(methodology,dict):
                    for control in methodology.get("negative_controls",[]) or []:
                        items.append({"test_id":plan.get("test_id"),"field_path":"methodology.negative_controls","value":control})
    else:
        value=report.get(kind,[])
        items=[value] if isinstance(value,dict) else (value if isinstance(value,list) else [])
    from vulnforge.core.store import _redact_sensitive_urls
    from vulnforge.core.redaction import redact_any
    items=redact_any(_redact_sensitive_urls(items))
    query=(search or "").strip().lower()
    if query: items=[item for item in items if query in json.dumps(item,ensure_ascii=False,default=str).lower()]
    total=len(items); offset=max(0,int(offset)); limit=max(1,min(int(limit),1000))
    return {"scan_id":scan_id,"object_type":kind,"items":items[offset:offset+limit],
            "total":total,"limit":limit,"offset":offset,"has_more":offset+limit<total,
            "scan_status":scan.get("status"),"report_available":bool(report)}

@app.get("/api/vf/scans/{scan_id}/export/{report_format}")
async def api_export_vf_report(scan_id: str,report_format: str):
    store=_v2_store(); report=store.get_report(scan_id)
    if report is None: raise HTTPException(status_code=404,detail="A completed report is not available for this scan yet.")
    fmt=report_format.lower()
    if fmt=="har":
        exchanges=store.list_exchanges(scan_id=scan_id,limit=1000,offset=0)
        entries=[]
        for item in exchanges:
            exchange=store.get_exchange(item.get("exchange_id","")) or {}
            parsed=urllib.parse.urlsplit(str(exchange.get("url") or item.get("url") or ""))
            entries.append({"startedDateTime":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime(exchange.get("timestamp") or time.time())),"time":exchange.get("duration_ms",0),"request":{"method":exchange.get("method","GET"),"url":exchange.get("url",""),"httpVersion":exchange.get("request_version","HTTP/1.1"),"headers":[{"name":k,"value":v} for k,v in (exchange.get("request_headers") or {}).items()],"queryString":[{"name":k,"value":v} for k,v in urllib.parse.parse_qsl(parsed.query,keep_blank_values=True)]},"response":{"status":exchange.get("status",0),"statusText":exchange.get("reason_phrase","")+"", "httpVersion":exchange.get("response_version","HTTP/1.1"),"headers":[{"name":k,"value":v} for k,v in (exchange.get("response_headers") or {}).items()],"content":{"size":len(str(exchange.get("response_body") or "").encode("utf-8")),"mimeType":next((v for k,v in (exchange.get("response_headers") or {}).items() if str(k).lower()=="content-type"),"")}}})
        content=json.dumps({"log":{"version":"1.2","creator":{"name":"VulnForge","version":"0.5"},"entries":entries}},ensure_ascii=False,indent=2).encode("utf-8")
        media="application/json"
    elif fmt=="json":
        from vulnforge.report.json_report import build_report_dict
        content=json.dumps(build_report_dict(report),ensure_ascii=False,indent=2,default=str).encode("utf-8")
        media="application/json"
    elif fmt in ("md","html","pdf"):
        import tempfile
        from pathlib import Path
        from vulnforge.report.renderers import write_markdown_report,write_html_report,write_pdf_report
        with tempfile.TemporaryDirectory(prefix="vulnforge-report-") as tmp:
            path=str(Path(tmp)/("report."+fmt))
            if fmt=="md": write_markdown_report(report,path); media="text/markdown; charset=utf-8"
            elif fmt=="html": write_html_report(report,path); media="text/html; charset=utf-8"
            else: write_pdf_report(report,path); media="application/pdf"
            content=Path(path).read_bytes()
    else:
        raise HTTPException(status_code=400,detail="Supported formats: json, md, html, pdf, har")
    safe_id="".join(ch for ch in scan_id if ch.isalnum() or ch in "-_" )[:80]
    return Response(content=content,media_type=media,headers={"Content-Disposition":f'attachment; filename="VULNFORGE_Report_{safe_id}.{fmt}"'})

@app.get("/api/vf/scans/{scan_id}/status")
async def api_get_vf_scan_status(scan_id: str):
    runtime=V2_SCAN_RUNS.get(scan_id)
    if runtime is not None:
        return {"scan_id":scan_id,"status":runtime["status"],"started_at":runtime.get("started_at"),
                "finished_at":runtime.get("finished_at")}
    scan=_v2_store().get_scan(scan_id)
    if scan is None: raise HTTPException(status_code=404,detail="Scan not found")
    return {"scan_id":scan_id,"status":scan.get("status"),"started_at":scan.get("started_at"),
            "finished_at":scan.get("finished_at")}

@app.get("/api/vf/scans/{scan_id}/event-log")
async def api_get_vf_event_log(scan_id: str, after: int=Query(0,ge=0),
                               limit: int=Query(250,ge=1,le=1000)):
    store=_v2_store()
    if not store.get_scan(scan_id):
        raise HTTPException(status_code=404,detail="Scan not found")
    items=store.list_scan_events(scan_id,after_event_id=after,limit=limit)
    return {"scan_id":scan_id,"items":items,"limit":limit,
            "next_after":items[-1]["event_id"] if items else after,
            "has_more":len(items)==limit}

@app.get("/api/vf/scans/{scan_id}/events")
async def api_stream_vf_scan_events(scan_id: str, request: Request,
                                    after: int=Query(0,ge=0)):
    """Replay persisted events and stream new scan events using SSE.

    SQLite cursors make reconnects and completed-scan reopens work after a
    dashboard refresh or server restart. In-process queues are only wakeups;
    when a worker is elsewhere, a bounded DB cursor poll is the fallback.
    """
    store=_v2_store()
    scan=store.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404,detail="Scan not found")
    runtime=V2_SCAN_RUNS.get(scan_id)
    try: header_cursor=int(request.headers.get("last-event-id","0") or 0)
    except (TypeError,ValueError): header_cursor=0
    initial_cursor=max(after,header_cursor,0)

    async def event_generator():
        queue=asyncio.Queue(maxsize=1)
        if runtime is not None: runtime["queues"].add(queue)
        cursor=initial_cursor
        try:
            while True:
                rows=await asyncio.to_thread(store.list_scan_events,scan_id,cursor,250)
                finished=False
                for event in rows:
                    cursor=event["event_id"]
                    payload=json.dumps(event,ensure_ascii=False,separators=(",",":"))
                    yield f"id: {cursor}\ndata: {payload}\n\n"
                    if event["kind"] in {"scan-complete","scan-error","scan-stopped"}:
                        finished=True
                        break
                if finished: return
                if len(rows)==250:
                    # Drain the next persisted cursor page before honoring a
                    # terminal scan status; a large completed history may span pages.
                    continue
                current=store.get_scan(scan_id)
                status=(runtime.get("status") if runtime is not None else None) or (current or {}).get("status")
                if str(status or "").lower() not in {"running","queued"}:
                    return
                if runtime is not None:
                    try: await asyncio.wait_for(queue.get(),timeout=1.0)
                    except asyncio.TimeoutError: pass
                else:
                    await asyncio.sleep(1.0)
                if await request.is_disconnected(): return
        finally:
            if runtime is not None: runtime["queues"].discard(queue)

    return StreamingResponse(event_generator(),media_type="text/event-stream",
        headers={"Cache-Control":"no-cache, no-transform","X-Accel-Buffering":"no"})

@app.get("/api/vf/scans/{scan_id}/traffic")
async def api_get_vf_traffic(scan_id: str, method: Optional[str] = Query(None),
                             host: Optional[str] = Query(None), endpoint: Optional[str] = Query(None),
                             status: Optional[int] = Query(None), module: Optional[str] = Query(None),
                             has_error: Optional[bool] = Query(None),
                             parent_exchange_id: Optional[str] = Query(None, max_length=100),
                             limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    store=_v2_store()
    if not store.get_scan(scan_id):
        raise HTTPException(status_code=404,detail="Scan not found")
    items=store.list_exchanges(scan_id=scan_id,method=method or "",host=host or "",
        endpoint=endpoint or "",status=status,limit=limit,offset=offset,
        module=module or "",has_error=has_error,parent_exchange_id=parent_exchange_id or "")
    return {"scan_id":scan_id,"items":items,"limit":limit,"offset":offset,
            "has_more":len(items)==limit}

@app.get("/api/vf/traffic/diff")
async def api_diff_vf_exchanges(exchange_a: str = Query(..., min_length=1, max_length=100),
                               exchange_b: str = Query(..., min_length=1, max_length=100)):
    from vulnforge.engine.research import compare_response_bodies
    store=_v2_store(); a=store.get_exchange(exchange_a); b=store.get_exchange(exchange_b)
    if not a or not b:
        raise HTTPException(status_code=404,detail="One or both HTTP exchanges were not found")
    body_a=str(a.get("response_body") or ""); body_b=str(b.get("response_body") or "")
    if len(body_a.encode("utf-8","replace"))>2_000_000 or len(body_b.encode("utf-8","replace"))>2_000_000:
        raise HTTPException(status_code=413,detail="Stored response is too large for interactive comparison (2 MB limit).")
    body_diff=compare_response_bodies(body_a,body_b)
    headers_a={str(k).lower():v for k,v in (a.get("response_headers") or {}).items()}
    headers_b={str(k).lower():v for k,v in (b.get("response_headers") or {}).items()}
    return {"exchange_a":exchange_a,"exchange_b":exchange_b,
        "request_ids":{"a":a.get("request_id"),"b":b.get("request_id")},
        "response_ids":{"a":a.get("response_id"),"b":b.get("response_id")},
        "status":{"a":a.get("status"),"b":b.get("status"),"different":a.get("status")!=b.get("status")},
        "headers":{"different":headers_a!=headers_b,"a":headers_a,"b":headers_b},
        "body":body_diff,
        "interpretation":"Observed response differences only; this is not a vulnerability determination."}

@app.get("/api/vf/traffic/{exchange_id}")
async def api_get_vf_exchange(exchange_id: str):
    exchange=_v2_store().get_exchange(exchange_id)
    if exchange is None:
        raise HTTPException(status_code=404,detail="HTTP exchange not found")
    return exchange

@app.post("/api/vf/repeater/send")
async def api_repeater_send(req: RepeaterRequest, request: Request = None):
    """Send one edited request through the scan's saved scope and common request gate."""
    _replay_access_allowed(request)
    if not req.authorized:
        raise HTTPException(status_code=403, detail="Confirm that you own or are explicitly authorized to test this scan target.")
    if not req.source_exchange_id or len(req.source_exchange_id)>100:
        raise HTTPException(status_code=422, detail="Select a stored HTTP exchange as the request's scope and provenance source.")
    try:
        from urllib.parse import urlsplit
        from dataclasses import replace
        from vulnforge.core.authorization import AuthorizationContext
        from vulnforge.core.profiles import get_profile
        from vulnforge.engine.research import parse_raw_http_request
        from vulnforge.http.client import Requester
        from vulnforge.core.redaction import SENSITIVE_HEADERS

        store=_v2_store()
        source=store.get_exchange(req.source_exchange_id)
        if not source:
            raise HTTPException(status_code=404, detail="Source exchange not found")
        scan_id=str(source.get("scan_id") or "")
        scan=store.get_scan(scan_id) if scan_id else None
        if not scan:
            raise HTTPException(status_code=409, detail="The source exchange has no compatible structured scan record.")
        if str(scan.get("status") or "").lower() not in {"completed", "partial", "aborted"}:
            raise HTTPException(status_code=409, detail="Replay is available only after its source scan has been saved.")
        scope=scan.get("scope_policy") or {}
        safety_profile=str(scan.get("profile") or "").lower()
        if safety_profile not in {"passive", "safe-active", "controlled-active", "lab"}:
            raise HTTPException(status_code=403, detail="The source scan has no supported explicit safety profile for replay.")
        if not isinstance(scope,dict) or not scope.get("allowed_hosts") or not scope.get("confirmed"):
            raise HTTPException(status_code=403, detail="The saved scan does not contain a confirmed reusable scope policy.")
        source_url=urlsplit(str(source.get("url") or ""))
        if source_url.scheme not in {"http", "https"} or not source_url.hostname:
            raise HTTPException(status_code=422, detail="The source exchange URL is invalid.")
        method,path,headers,body=parse_raw_http_request(req.raw_request)
        if "[REDACTED]" in req.raw_request:
            raise HTTPException(status_code=422, detail="Remove redaction placeholders; redacted history cannot be replayed as exact authentication state.")
        source_port=source_url.port or (443 if source_url.scheme=="https" else 80)
        source_host=source_url.hostname.encode("idna").decode("ascii").lower().rstrip(".")
        host_header_names=[name for name in headers if name.lower()=="host"]
        supplied_host=headers.pop(host_header_names[0]) if host_header_names else source_url.netloc
        supplied=urlsplit("//"+supplied_host)
        if supplied.username or supplied.password or not supplied.hostname:
            raise HTTPException(status_code=422, detail="Invalid Host header in Repeater request.")
        supplied_host_name=supplied.hostname.encode("idna").decode("ascii").lower().rstrip(".")
        supplied_port=supplied.port or (443 if source_url.scheme=="https" else 80)
        if supplied_host_name!=source_host or supplied_port!=source_port:
            raise HTTPException(status_code=403, detail="Repeater cannot change the source exchange host or port.")
        target=f"{source_url.scheme}://{source_url.netloc}{path}"
        forbidden={"content-length", "transfer-encoding", "connection", "proxy-authorization", "proxy-connection", "upgrade"}
        if any(name.lower() in forbidden for name in headers):
            raise HTTPException(status_code=422, detail="Transport-managed headers are not accepted.")
        if method not in {"GET", "HEAD", "OPTIONS"}:
            if not req.confirm_state_change:
                raise HTTPException(status_code=403, detail="State-changing request requires the explicit per-request confirmation.")
            if safety_profile not in {"safe-active", "controlled-active", "lab"}:
                raise HTTPException(status_code=403, detail="State-changing replay is disabled for this scan's safety profile.")
            if not scope.get("methods_explicit") or method not in (scope.get("allowed_methods") or []):
                raise HTTPException(status_code=403, detail="The original scan did not explicitly authorize this HTTP method.")
        allowed_scope={key:scope.get(key) for key in (
            "allowed_hosts", "allowed_ips", "allowed_ports", "allowed_prefixes", "excluded_hosts",
            "excluded_paths", "excluded_params", "allowed_methods", "not_before", "expires_at") if key in scope}
        auth=AuthorizationContext(**allowed_scope,profile_name=safety_profile,
            allow_private=bool(scope.get("allow_private",False)),confirmed=True)
        base_profile=get_profile(safety_profile)
        profile=replace(base_profile,requests_per_second=min(1.0,base_profile.requests_per_second),
            max_concurrency=1,max_requests=1,scan_timeout_s=min(15,int(req.timeout)+3),max_response_bytes=262_144)
        requester=Requester(auth,profile,timeout=req.timeout)
        try:
            exchange=await requester.send(method,target,headers=headers,body=body or None,
                module="repeater",follow_redirects=False)
        finally:
            await requester.close()
        exchange.parent_exchange_id=req.source_exchange_id
        sensitive=set(SENSITIVE_HEADERS)
        sensitive.update(name for name in headers if re.search(r"(?i)(auth|token|secret|key|cookie|session|pass)",name))
        store.record_exchange(scan_id,exchange.to_dict(),sensitive_headers=sensitive,redact=True)
        store.record_audit("request_replayed", object_type="exchange", object_id=exchange.exchange_id, scan_id=scan_id, metadata={"parent_exchange_id": req.source_exchange_id, "title": req.title})
        return store.get_exchange(exchange.exchange_id) or exchange.to_dict()
    except HTTPException:
        raise
    except (ValueError,TypeError,UnicodeError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        print(f"[VULNFORGE] Repeater request failed ({type(exc).__name__}).",file=sys.stderr)
        raise HTTPException(status_code=400, detail="Guarded Repeater request failed; inspect the stored exchange for a redacted error summary.") from exc

@app.get("/api/vf/repeater/history")
async def api_vf_repeater_history(scan_id: Optional[str] = Query(None, max_length=100)):
    return _v2_store().list_exchanges(scan_id=scan_id or "",module="repeater",limit=100)

@app.post("/api/tools/encode-decode")
async def api_encode_decode(req: UtilityRequest):
    text, op = req.text, req.operation
    if len(text)>65536:
        raise HTTPException(status_code=413,detail="Utility input exceeds the 64 KB limit.")
    try:
        if op == "url_encode": res = urllib.parse.quote(text,safe="")
        elif op == "url_decode": res = urllib.parse.unquote(text,errors="strict")
        elif op == "b64_encode": res = base64.b64encode(text.encode("utf-8")).decode("ascii")
        elif op == "b64_decode": res = base64.b64decode(text.encode("ascii"),validate=True).decode("utf-8",errors="strict")
        elif op == "md5": res = hashlib.md5(text.encode("utf-8")).hexdigest()
        elif op == "sha256": res = hashlib.sha256(text.encode("utf-8")).hexdigest()
        else: raise HTTPException(status_code=422,detail="Unsupported utility operation.")
    except HTTPException:
        raise
    except (ValueError,UnicodeError) as exc:
        raise HTTPException(status_code=422,detail="Input is invalid for the selected utility operation.") from exc
    return {"result": res, "operation": op}


def main():
    """Run the one dashboard server using HOST and PORT environment settings."""
    import uvicorn
    host=os.environ.get("HOST","127.0.0.1")
    port=int(os.environ.get("PORT","8000"))
    uvicorn.run(app,host=host,port=port,reload=False)


if __name__=="__main__":
    main()
