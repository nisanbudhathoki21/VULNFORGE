"""Optional browser workflow adapter; every HTTP request is delegated to Requester."""
from __future__ import annotations

import asyncio
import inspect
import json
import os
import re
import stat
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple
from urllib.parse import urljoin, urlsplit

from ..core.models import PlannedTest
from ..core.profiles import get_profile
from ..core.redaction import redact_url_query_values
from .methodology import build_test_methodology
from .normalize import canonicalize

MAX_BROWSER_WORKFLOWS=3
MAX_BROWSER_STEPS=10
MAX_BROWSER_REQUESTS_EACH=20
MAX_BROWSER_REQUESTS_TOTAL=40
MAX_STORAGE_STATE_BYTES=5*1024*1024
SAFE_BROWSER_METHODS={"GET","HEAD","OPTIONS"}
_ACTIONS={"navigate","assert_selector","wait_for_selector","assert_url"}
_SELECTOR_RE=re.compile(r"^[^\x00-\x1f]{1,256}$")


def _normalize_workflow(spec: Any, target: str) -> Dict[str,Any]:
    if not isinstance(spec,dict): raise ValueError("browser workflow must be an object")
    workflow_id=str(spec.get("workflow_id") or "")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}",workflow_id):
        raise ValueError("browser workflow_id must be 1-64 safe identifier characters")
    start_raw=str(spec.get("start_url") or "")
    if not start_raw or len(start_raw)>8192: raise ValueError(f"browser workflow {workflow_id} requires a start_url")
    start=urljoin(target,start_raw)
    parsed=urlsplit(start)
    if parsed.scheme.lower() not in ("http","https") or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("browser workflow start_url must resolve to HTTP(S) without embedded credentials")
    steps=spec.get("steps",[])
    if not isinstance(steps,list) or len(steps)>MAX_BROWSER_STEPS:
        raise ValueError(f"browser workflow {workflow_id} supports at most {MAX_BROWSER_STEPS} steps")
    normalized=[]
    for index,step in enumerate(steps):
        if not isinstance(step,dict): raise ValueError(f"browser workflow step {index+1} must be an object")
        action=str(step.get("action") or "")
        if action not in _ACTIONS: raise ValueError(f"browser workflow step {index+1}: unsupported action")
        record={"action":action,"step_id":str(step.get("step_id") or f"step-{index+1}")[:64]}
        if action=="navigate":
            raw=str(step.get("url") or "")
            dest=urljoin(start,raw)
            parts=urlsplit(dest)
            if not raw or len(raw)>8192 or parts.scheme.lower() not in ("http","https") or not parts.hostname or parts.username or parts.password:
                raise ValueError(f"browser workflow step {index+1}: invalid navigation URL")
            record["url"]=canonicalize(dest,drop_tracking=False)
        elif action in ("assert_selector","wait_for_selector"):
            selector=str(step.get("selector") or "")
            if not _SELECTOR_RE.fullmatch(selector): raise ValueError(f"browser workflow step {index+1}: selector must be 1-256 printable characters")
            record["selector"]=selector
        elif action=="assert_url":
            path=str(step.get("path") or "")
            if not path.startswith("/") or len(path)>2048 or any(ord(ch)<0x20 for ch in path):
                raise ValueError(f"browser workflow step {index+1}: assert_url.path must be an origin-form path")
            record["path"]=path
        normalized.append(record)
    request_cap=spec.get("max_requests")
    if not isinstance(request_cap,int) or isinstance(request_cap,bool) or not 1<=request_cap<=MAX_BROWSER_REQUESTS_EACH:
        raise ValueError(f"browser workflow {workflow_id} requires max_requests between 1 and {MAX_BROWSER_REQUESTS_EACH}")
    timeout=spec.get("step_timeout_ms",5000)
    if not isinstance(timeout,int) or isinstance(timeout,bool) or not 250<=timeout<=15000:
        raise ValueError("step_timeout_ms must be an integer from 250 to 15000")
    return {"workflow_id":workflow_id,"start_url":canonicalize(start,drop_tracking=False),
            "steps":normalized,"max_requests":request_cap,"step_timeout_ms":timeout}


def plan_browser_workflows(specs: Any, target: str, authorization, *, can_run: bool,
                           available_requests: int, browser_available: bool) -> Tuple[List[PlannedTest],List[Dict[str,Any]],int,List[str]]:
    if specs in (None,[]): return [],[],0,[]
    if not isinstance(specs,list): return [],[],0,["browser_workflows must be a list"]
    if len(specs)>MAX_BROWSER_WORKFLOWS:
        return [],[],0,[f"browser_workflows may contain at most {MAX_BROWSER_WORKFLOWS} items"]
    plans=[]; runnable=[]; errors=[]; reserved=0; seen=set()
    for index,spec in enumerate(specs):
        try:
            item=_normalize_workflow(spec,target)
            if item["workflow_id"] in seen: raise ValueError("duplicate browser workflow_id")
            seen.add(item["workflow_id"])
            targets=[item["start_url"]]+[step["url"] for step in item["steps"] if step["action"]=="navigate"]
            scope_errors=[]
            for url in targets:
                allowed,reason=authorization.check(url,purpose="browser-workflow-plan",method="GET")
                if not allowed: scope_errors.append(reason)
            enough=reserved+item["max_requests"]<=min(max(0,int(available_requests)),MAX_BROWSER_REQUESTS_TOTAL)
            if not browser_available:
                status="BLOCKED"; reason="Optional Playwright browser dependency is unavailable. Install VulnForge with the browser extra and install Chromium."
            elif not can_run:
                status="BLOCKED"; reason="Explicit active request and active-capable safety profile are required."
            elif scope_errors:
                status="BLOCKED"; reason="; ".join(scope_errors)
            elif not enough:
                status="BLOCKED"; reason="Browser request cap does not fit within the remaining scan budget."
            else:
                status="PLANNED"; reason=""
            safe_start_url=redact_url_query_values(item["start_url"])
            methodology=build_test_methodology("browser-read-only-workflow",safe_start_url)
            methodology.update({"status":status,"request_cost":item["max_requests"],"planning_note":reason})
            plan=PlannedTest("test-browser-"+item["workflow_id"],"","browser-read-only-workflow",
                safe_start_url,"GET",item["max_requests"],"LOW_READ_ONLY",True,status,methodology=methodology)
            plans.append(plan)
            if status=="PLANNED":
                runnable.append({**item,"test_id":plan.test_id}); reserved+=item["max_requests"]
        except (TypeError,ValueError) as exc:
            errors.append(f"browser workflow {index+1}: {exc}")
    return plans,runnable,reserved,errors


class BrowserWorkflowRunner:
    """A temporary, non-persistent browser whose HTTP is fetched only via Requester."""
    def __init__(self, requester, authorization, workflow: Dict[str,Any]):
        self.requester=requester; self.authorization=authorization; self.workflow=workflow
        self.request_count=0; self.exchange_ids=[]; self.blocked=[]

    async def handle_route(self,route):
        request=route.request
        url=str(request.url); method=str(request.method or "GET").upper()
        resource=str(getattr(request,"resource_type","other") or "other").lower()
        if self.request_count>=self.workflow["max_requests"]:
            self.blocked.append({"url":redact_url_query_values(url),"method":method,"resource_type":resource,"reason":"workflow request cap reached"})
            await route.abort(); return
        self.request_count+=1
        parts=urlsplit(url)
        if parts.scheme.lower() not in ("http","https"):
            self.blocked.append({"url":redact_url_query_values(url),"method":method,"resource_type":resource,"reason":"non-HTTP scheme blocked"})
            await route.abort(); return
        if method not in SAFE_BROWSER_METHODS:
            self.blocked.append({"url":redact_url_query_values(url),"method":method,"resource_type":resource,"reason":"state-changing or unsupported method blocked"})
            await route.abort(); return
        if resource in {"image","font","media"}:
            self.blocked.append({"url":redact_url_query_values(url),"method":method,"resource_type":resource,"reason":"nonessential binary resource blocked"})
            await route.abort(); return
        try:
            headers=await request.all_headers()
        except Exception:
            headers={}
        hop_by_hop={"host","content-length","connection","proxy-connection","proxy-authorization",
            "transfer-encoding","upgrade","keep-alive","accept-encoding"}
        forwarded={str(k):str(v) for k,v in (headers or {}).items() if str(k).lower() not in hop_by_hop}
        try:
            exchange=await self.requester.send(method,url,headers=forwarded,module="browser-workflow",
                follow_redirects=False,max_redirects=0)
        except Exception as exc:
            self.blocked.append({"url":redact_url_query_values(url),"method":method,"resource_type":resource,
                "reason":"central requester rejected/failed","error_type":type(exc).__name__})
            await route.abort(); return
        if not exchange.ok or not 100<=int(exchange.status or 0)<=599:
            self.blocked.append({"url":redact_url_query_values(url),"method":method,"resource_type":resource,
                "reason":"central scope/request gate refused request"})
            await route.abort(); return
        response_headers={str(k):str(v) for k,v in exchange.response_headers.items()
            if str(k).lower() not in {"content-length","content-encoding","transfer-encoding","connection","keep-alive","proxy-connection"}}
        content_type=(exchange.header("content-type") or "").lower().split(";",1)[0].strip()
        binary_prefixes=("image/","font/","audio/","video/")
        binary_types={"application/octet-stream","application/pdf","application/zip",
            "application/gzip","application/x-7z-compressed","application/x-rar-compressed",
            "application/wasm","application/vnd.ms-fontobject"}
        if content_type.startswith(binary_prefixes) or content_type in binary_types:
            self.blocked.append({"url":redact_url_query_values(url),"method":method,"resource_type":resource,"reason":"binary response blocked"})
            await route.abort(); return
        if any(str(k).lower()=="content-disposition" and "attachment" in str(v).lower()
               for k,v in response_headers.items()):
            self.blocked.append({"url":redact_url_query_values(url),"method":method,"resource_type":resource,"reason":"download response blocked"})
            await route.abort(); return
        self.exchange_ids.append(exchange.exchange_id)
        try:
            await route.fulfill(status=exchange.status,headers=response_headers,body=exchange.response_body or "")
        except Exception:
            self.blocked.append({"url":redact_url_query_values(url),"method":method,"resource_type":resource,"reason":"browser response fulfillment failed"})
            try: await route.abort()
            except Exception: pass

    async def _block_websocket(self, websocket_route):
        self.blocked.append({"url":"","method":"WEBSOCKET","resource_type":"websocket","reason":"WebSockets are disabled in read-only browser workflow mode"})
        result=websocket_route.close(code=1008,reason="VulnForge read-only workflow policy")
        if inspect.isawaitable(result): await result

    async def run(self, storage_state_path: str="") -> Dict[str,Any]:
        try:
            from playwright.async_api import async_playwright
        except ImportError as exc:
            raise RuntimeError("Browser workflows require `pip install 'vulnforge[browser]'` and `python -m playwright install chromium`.") from exc
        if storage_state_path:
            state=Path(storage_state_path)
            if not state.is_file() or state.stat().st_size>MAX_STORAGE_STATE_BYTES:
                raise ValueError("Browser storage-state file is missing or exceeds the 5 MiB limit.")
            if os.name=="posix" and stat.S_IMODE(state.stat().st_mode)&0o077:
                raise PermissionError("Browser storage-state file must be owner-only (chmod 600); VulnForge will not copy it.")
            try:
                if not isinstance(json.loads(state.read_text(encoding="utf-8")),dict): raise ValueError
            except (OSError,UnicodeError,json.JSONDecodeError,ValueError,RecursionError) as exc:
                raise ValueError("Browser storage-state file must be valid JSON object data.") from exc
        async with async_playwright() as playwright:
            browser=await playwright.chromium.launch(headless=True,args=["--disable-background-networking","--disable-component-update","--dns-prefetch-disable","--disable-features=SpeculationRulesPrefetchProxy","--no-first-run"])
            context=None
            try:
                context_args={"accept_downloads":False,"service_workers":"block","ignore_https_errors":False}
                if storage_state_path: context_args["storage_state"]=storage_state_path
                context=await browser.new_context(**context_args)
                websocket_router=getattr(context,"route_web_socket",None)
                if not callable(websocket_router):
                    raise RuntimeError("Installed Playwright cannot enforce the WebSocket block; browser workflow is fail-closed.")
                await context.route("**/*",self.handle_route)
                await websocket_router("**/*",self._block_websocket)
                page=await context.new_page()
                workflow_record={"workflow_id":self.workflow["workflow_id"],"status":"INCOMPLETE",
                    "steps":[],"exchange_ids":self.exchange_ids,"blocked_requests":self.blocked,
                    "request_count":0,"security_property_verified":False,"finding_promoted":False,
                    "storage_state_persisted":False,"browser_state_persisted":False}
                try:
                    response=await page.goto(self.workflow["start_url"],wait_until="domcontentloaded",timeout=15000)
                    workflow_record["start_status"]=int(response.status) if response else None
                    for step in self.workflow["steps"]:
                        timeout=self.workflow["step_timeout_ms"]
                        action=step["action"]
                        step_result={"step_id":step["step_id"],"action":action,"status":"OBSERVED"}
                        if action=="navigate":
                            nav=await page.goto(step["url"],wait_until="domcontentloaded",timeout=timeout)
                            step_result["http_status"]=int(nav.status) if nav else None
                        elif action=="assert_selector":
                            step_result["assertion_passed"]=await page.locator(step["selector"]).count()>0
                            if not step_result["assertion_passed"]: step_result["status"]="ASSERTION_FAILED"
                        elif action=="wait_for_selector":
                            try: await page.locator(step["selector"]).wait_for(state="attached",timeout=timeout)
                            except Exception: step_result["status"]="TIMEOUT_OR_NOT_FOUND"
                        elif action=="assert_url":
                            step_result["assertion_passed"]=urlsplit(page.url).path==step["path"]
                            if not step_result["assertion_passed"]: step_result["status"]="ASSERTION_FAILED"
                        workflow_record["steps"].append(step_result)
                        if step_result["status"]!="OBSERVED": break
                    workflow_record["status"]=("OBSERVED" if all(x["status"]=="OBSERVED" for x in workflow_record["steps"]) else "OBSERVED_MISMATCH")
                except Exception as exc:
                    workflow_record["status"]="INCOMPLETE"
                    workflow_record["execution_error_type"]=type(exc).__name__
                workflow_record["request_count"]=self.request_count
                workflow_record["blocked_requests"]=list(self.blocked)
                workflow_record["exchange_ids"]=list(self.exchange_ids)
                return workflow_record
            finally:
                if context is not None: await context.close()
                await browser.close()


async def execute_browser_workflows(ctx) -> None:
    specs=list(getattr(ctx,"_browser_workflow_specs",[]) or [])
    if not specs or ctx.stopped: return
    profile=get_profile(ctx.config.profile_name)
    if not ctx.config.active_requested or not profile.allows_active: return
    plans={p.test_id:p for p in ctx.test_plan if p.test_type=="browser-read-only-workflow"}
    storage_state=str(ctx.config.auth_data.get("browser_storage_state") or "")
    for spec in specs:
        planned=plans.get(spec.get("test_id"))
        if not planned or planned.status!="PLANNED" or ctx.stopped: continue
        runner=BrowserWorkflowRunner(ctx.requester,ctx.authorization,spec)
        started=time.time()
        try:
            record=await runner.run(storage_state_path=storage_state)
            planned.status="EXECUTED" if record["status"] in {"OBSERVED","OBSERVED_MISMATCH"} else "INCOMPLETE"
        except (RuntimeError,ValueError,PermissionError) as exc:
            record={"workflow_id":spec["workflow_id"],"status":"NOT_RUN","steps":[],
                "request_count":0,"security_property_verified":False,"finding_promoted":False,
                "storage_state_persisted":False,"error_type":type(exc).__name__}
            planned.status="BLOCKED"
            ctx.emit("stage",f"Browser workflow {spec['workflow_id']} not run: {exc}")
        record.update({"test_id":planned.test_id,"type":"browser-read-only-workflow",
            "started_at":started,"finished_at":time.time(),
            "verification_method":"Human-defined read-only browser observation through the central Requester",
            "limitations":["Browser actions are limited to navigation and selector/URL observations.",
                "Only GET, HEAD, and OPTIONS requests are sent; redirects are re-routed through the scope gate.",
                "State-changing requests, downloads, binary assets, and WebSockets are blocked.",
                "No vulnerability property or impact is inferred."]})
        ctx.tests.append(record)
