"""Explicit, read-only HTTP workflow planning and execution through Requester.

This is a bounded workflow foundation, not a browser engine or vulnerability
verifier. Every outbound step still passes the central scope/rate/budget/stop gate.
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Tuple
from urllib.parse import urljoin, urlsplit

from ..core.models import PlannedTest
from ..core.profiles import get_profile
from .methodology import build_test_methodology
from .normalize import canonicalize

MAX_WORKFLOWS=5
MAX_STEPS_PER_WORKFLOW=10
MAX_TOTAL_STEPS=30
SAFE_METHODS={"GET","HEAD","OPTIONS"}
_ID_RE=re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


def _normalize_spec(spec: Any, target: str) -> Dict[str,Any]:
    if not isinstance(spec,dict): raise ValueError("workflow entry must be an object")
    workflow_id=str(spec.get("workflow_id") or "")
    if not _ID_RE.fullmatch(workflow_id): raise ValueError("workflow_id must be 1-64 safe identifier characters")
    steps=spec.get("steps")
    if not isinstance(steps,list) or not 1<=len(steps)<=MAX_STEPS_PER_WORKFLOW:
        raise ValueError(f"workflow {workflow_id} must contain 1-{MAX_STEPS_PER_WORKFLOW} steps")
    stop_on_mismatch=spec.get("stop_on_mismatch",True)
    if not isinstance(stop_on_mismatch,bool): raise ValueError("stop_on_mismatch must be true or false")
    normalized=[]; seen=set()
    for index,step in enumerate(steps):
        if not isinstance(step,dict): raise ValueError(f"workflow {workflow_id} step {index+1} must be an object")
        if any(key in step for key in ("body","payload","headers","script","javascript")):
            raise ValueError("workflow steps do not accept bodies, payloads, custom headers, or scripts")
        method=str(step.get("method") or "GET").upper()
        if method not in SAFE_METHODS:
            raise ValueError(f"workflow step {index+1}: only GET, HEAD, and OPTIONS are supported in this read-only runner")
        raw_url=str(step.get("url") or "")
        if not raw_url or len(raw_url)>8192:
            raise ValueError(f"workflow step {index+1} requires a URL/path up to 8192 characters")
        url=urljoin(target,raw_url)
        parts=urlsplit(url)
        if parts.scheme.lower() not in ("http","https") or not parts.hostname or parts.username or parts.password:
            raise ValueError(f"workflow step {index+1} must resolve to an HTTP(S) URL without embedded credentials")
        step_id=str(step.get("step_id") or f"step-{index+1}")
        if not _ID_RE.fullmatch(step_id) or step_id in seen:
            raise ValueError(f"workflow {workflow_id} has an invalid or duplicate step_id")
        seen.add(step_id)
        expected=step.get("expected_status")
        if expected is not None:
            if isinstance(expected,int) and not isinstance(expected,bool): expected=[expected]
            if (not isinstance(expected,list) or not expected or len(expected)>10 or
                    any(not isinstance(code,int) or isinstance(code,bool) or not 100<=code<=599 for code in expected)):
                raise ValueError(f"workflow step {step_id}: expected_status must be an HTTP status or a list of 1-10 statuses")
            expected=sorted(set(expected))
        normalized.append({"step_id":step_id,"method":method,
            "url":canonicalize(url,drop_tracking=False),"expected_status":expected})
    return {"workflow_id":workflow_id,"steps":normalized,
            "stop_on_mismatch":stop_on_mismatch}


def plan_read_only_workflows(specs: Any, target: str, authorization, *, can_run: bool,
                             available_requests: int) -> Tuple[List[PlannedTest],List[Dict[str,Any]],int,List[str]]:
    """Validate explicit workflow specs, scope-check every step, reserve request cost."""
    if specs in (None,[]): return [],[],0,[]
    if not isinstance(specs,list): return [],[],0,["workflow_tests must be a list"]
    if len(specs)>MAX_WORKFLOWS: return [],[],0,[f"workflow_tests may contain at most {MAX_WORKFLOWS} workflows"]
    plans=[]; runnable=[]; errors=[]; reserved=0; total_steps=0
    seen_workflow_ids=set()
    for index,raw in enumerate(specs):
        try:
            item=_normalize_spec(raw,target)
            if item["workflow_id"] in seen_workflow_ids:
                raise ValueError("duplicate workflow_id")
            seen_workflow_ids.add(item["workflow_id"])
            total_steps+=len(item["steps"])
            if total_steps>MAX_TOTAL_STEPS: raise ValueError(f"workflow_tests may contain at most {MAX_TOTAL_STEPS} total steps")
            scope_errors=[]
            for step in item["steps"]:
                from urllib.parse import parse_qsl
                excluded=[name for name,_ in parse_qsl(urlsplit(step["url"]).query,keep_blank_values=True)
                          if authorization.param_excluded(name)]
                if excluded:
                    scope_errors.append(f"{step['step_id']}: query contains excluded parameter(s)")
                    continue
                allowed,reason=authorization.check(step["url"],purpose="workflow-plan",method=step["method"])
                if not allowed: scope_errors.append(f"{step['step_id']}: {reason}")
            cost=len(item["steps"])
            enough=reserved+cost<=max(0,int(available_requests))
            status="PLANNED" if can_run and not scope_errors and enough else "BLOCKED"
            methodology=build_test_methodology("configured-read-only-workflow",item["workflow_id"])
            methodology.update({"request_cost":cost,"status":status,
                "planning_note":("" if status=="PLANNED" else
                    "; ".join(scope_errors) if scope_errors else
                    "Explicit active mode and an active-capable safety profile are required." if not can_run else
                    "Insufficient remaining request budget for the whole workflow.")})
            plan=PlannedTest("test-workflow-"+item["workflow_id"],"", "configured-read-only-workflow",
                item["steps"][0]["url"],item["steps"][0]["method"],cost,"LOW_READ_ONLY",True,status,
                methodology=methodology)
            plans.append(plan)
            if status=="PLANNED":
                runnable.append({**item,"test_id":plan.test_id})
                reserved+=cost
        except (TypeError,ValueError) as exc:
            errors.append(f"workflow {index+1}: {exc}")
            continue
    return plans,runnable,reserved,errors


async def execute_read_only_workflows(ctx) -> None:
    """Execute only preplanned safe-method steps; record observations, not findings."""
    specs=list(getattr(ctx,"_workflow_test_specs",[]) or [])
    if not specs or ctx.stopped: return
    profile=get_profile(ctx.config.profile_name)
    if not ctx.config.active_requested or not profile.allows_active:
        return
    plans={p.test_id:p for p in ctx.test_plan if p.test_type=="configured-read-only-workflow"}
    for spec in specs:
        planned=plans.get(spec.get("test_id"))
        if not planned or planned.status!="PLANNED" or ctx.stopped: continue
        started=time.time()
        step_results=[]; mismatched=False; incomplete=False
        for step in spec["steps"]:
            if ctx.stopped:
                incomplete=True; break
            from ..http.client import ScanAborted
            try:
                exchange=await ctx.requester.send(step["method"],step["url"],module="configured-read-only-workflow",
                    follow_redirects=False,max_redirects=0)
            except ScanAborted as exc:
                step_results.append({"step_id":step["step_id"],"method":step["method"],"url":step["url"],
                    "status":"INCOMPLETE","error_type":type(exc).__name__,"exchange_id":""})
                incomplete=True
                break
            expected=step.get("expected_status")
            if not exchange.ok:
                observed="INCOMPLETE"; incomplete=True
            elif expected is not None and exchange.status not in expected:
                observed="OBSERVED_MISMATCH"; mismatched=True
            elif expected is not None:
                observed="OBSERVED_EXPECTED_STATUS"
            else:
                observed="OBSERVED"
            step_results.append({"step_id":step["step_id"],"method":step["method"],"url":exchange.url,
                "http_status":exchange.status,"expected_status":expected,"status":observed,
                "content_type":exchange.header("content-type"),"exchange_id":exchange.exchange_id,
                "redirect_followed":False})
            if (incomplete or (mismatched and spec.get("stop_on_mismatch",True))): break
        all_observed=bool(step_results) and len(step_results)==len(spec["steps"]) and not incomplete
        status="INCOMPLETE" if incomplete or not all_observed else "OBSERVED_MISMATCH" if mismatched else "OBSERVED"
        planned.status="EXECUTED" if all_observed else "INCOMPLETE"
        ctx.tests.append({"test_id":planned.test_id,"type":"configured-read-only-workflow",
            "workflow_id":spec["workflow_id"],"status":status,"steps":step_results,
            "started_at":started,"finished_at":time.time(),
            "verification_method":"Explicit configured read-only HTTP sequence through Requester",
            "security_property_verified":False,"finding_promoted":False,
            "request_count":len(step_results),"replayed_captured_requests":False,
            "limitations":["Observations only; HTTP status expectations are not vulnerability assertions.",
                "No browser JavaScript is executed and redirects are not followed."]})
