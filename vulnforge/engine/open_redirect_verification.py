"""Bounded, non-following open-redirect validation for observed GET parameters."""
from __future__ import annotations
import time
import uuid
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit, urljoin
from typing import Any

from ..core.models import EvidenceItem, Finding, STATUS_VERIFIED

EXTERNAL_MARKER="https://vf-redirect.invalid/vf-validation"
INTERNAL_CONTROL="/vf-internal-validation"
REDIRECT_STATUSES={301,302,303,307,308}


def replace_query_value(url: str, parameter: str, value: str) -> str:
    parsed=urlsplit(url)
    pairs=parse_qsl(parsed.query,keep_blank_values=True)
    found=False; updated=[]
    for name,current in pairs:
        if name==parameter:
            updated.append((name,value)); found=True
        else:
            updated.append((name,current))
    if not found:
        raise ValueError("The observed redirect parameter is no longer present in the URL.")
    return urlunsplit((parsed.scheme,parsed.netloc,parsed.path,urlencode(updated,doseq=True),""))


def _origin(url: str):
    parsed=urlsplit(url)
    if not parsed.scheme or not parsed.hostname:
        return None
    return (parsed.scheme.lower(),parsed.hostname.lower().rstrip("."),
            parsed.port or (443 if parsed.scheme.lower()=="https" else 80))


async def execute_open_redirect_tests(ctx) -> None:
    specs=list(getattr(ctx,"_open_redirect_test_specs",[]))
    if not specs or ctx.stopped:
        return
    from ..core.profiles import get_profile
    profile=get_profile(ctx.config.profile_name)
    if not ctx.config.active_requested or not profile.allows_active:
        for planned in ctx.test_plan:
            if planned.test_type=="open-redirect-validation" and planned.status=="PLANNED":
                planned.status="BLOCKED"
        ctx.emit("stage","Open-redirect checks blocked: active mode is not enabled")
        return
    for spec in specs:
        if ctx.stopped: break
        planned=next((p for p in ctx.test_plan if p.test_id==spec["test_id"]),None)
        record={"test_id":spec["test_id"],"hypothesis_id":spec["hypothesis_id"],
            "type":"open-redirect-validation","status":"INCOMPLETE","endpoint":spec["url"],
            "parameter":spec["parameter"],"methodology_id":"VF-METHOD-REDIRECT-1",
            "started_at":time.time(),"observations":[],"impact_proven":False}
        try:
            external_url=replace_query_value(spec["url"],spec["parameter"],EXTERNAL_MARKER)
            control_url=replace_query_value(spec["url"],spec["parameter"],INTERNAL_CONTROL)
            for test_url,kind in ((external_url,"external-marker"),(control_url,"same-origin-control")):
                exchange=await ctx.requester.send("GET",test_url,module="open-redirect-validation",follow_redirects=False)
                location=str(exchange.header("location","") or "")
                resolved=urljoin(test_url,location) if location else ""
                record["observations"].append({"kind":kind,"exchange_id":exchange.exchange_id,
                    "status":exchange.status,"error":exchange.error,"location":location,
                    "resolved_location":resolved})
                if exchange.error or exchange.status<=0:
                    break
            complete=len(record["observations"])==2
            record["status"]="EXECUTED" if complete else "INCOMPLETE"
            record["reproduction_status"]="REPRODUCED" if complete and _redirect_proof(record) else "CANDIDATE"
            record["finished_at"]=time.time()
            if planned: planned.status="EXECUTED" if complete else "INCOMPLETE"
            ctx.tests.append(record)
        except Exception as exc:
            record["status"]="INCOMPLETE"
            record["reason"]=f"{type(exc).__name__}: open-redirect check did not complete"
            record["finished_at"]=time.time()
            if planned: planned.status="INCOMPLETE"
            ctx.tests.append(record)
            if type(exc).__name__ in {"ScanAborted","CancelledError"}:
                raise
    ctx.emit("stage",f"Open-redirect observations collected: {sum(t.get('type')=='open-redirect-validation' for t in ctx.tests)}")


def _redirect_proof(record) -> bool:
    observations=record.get("observations",[])
    if len(observations)!=2:
        return False
    external,control=observations
    endpoint=str(record.get("endpoint") or "")
    target_origin=_origin(endpoint)
    external_location=external.get("resolved_location") or ""
    control_location=control.get("resolved_location") or ""
    external_parts=urlsplit(external_location)
    control_parts=urlsplit(control_location)
    return bool(
        external.get("status") in REDIRECT_STATUSES and control.get("status") in REDIRECT_STATUSES and
        external.get("error") in (None,"") and control.get("error") in (None,"") and
        _origin(external_location)==("https","vf-redirect.invalid",443) and
        external_parts.path=="/vf-validation" and _origin(control_location)==target_origin and
        control_parts.path=="/vf-internal-validation"
    )


def verify_open_redirect_tests(ctx) -> None:
    hypotheses={h.hypothesis_id:h for h in ctx.hypotheses}
    for record in ctx.tests:
        if record.get("type")!="open-redirect-validation" or record.get("status")!="EXECUTED":
            continue
        proof=_redirect_proof(record)
        record["status"]="VERIFIED" if proof else "CANDIDATE"
        record["reproduction_status"]="VERIFIED" if proof else "CANDIDATE"
        record["independent_verifier"]="external reserved marker redirect plus same-origin control; redirects were not followed"
        record["impact_proven"]=False
        hypothesis=hypotheses.get(record.get("hypothesis_id"))
        if hypothesis: hypothesis.status="VERIFIED" if proof else "DEEPER_TESTING"
        if not proof: continue
        endpoint=str(record.get("endpoint") or "")
        finding=Finding(title="Unvalidated external redirect parameter",category="redirect / open redirect",
            severity="medium",description=(f"The observed `{record.get('parameter','')}` parameter directed a scoped GET response to the reserved "
                "vf-redirect.invalid marker, while the same-origin control remained on the original origin. Redirects were not followed."),
            endpoint=endpoint,parameter=str(record.get("parameter") or ""),method="GET",confidence=0.92,
            status=STATUS_VERIFIED,state="VERIFIED",
            evidence=[EvidenceItem(description="Paired external marker and same-origin control satisfied the independent Location-header verifier.",
                request_summary=f"Two bounded GET requests mutating only {record.get('parameter','')} (redirects not followed)",
                response_summary="External marker Location observed; same-origin control stayed same-origin; no external navigation occurred",
                detail={**record,"test_id":record["test_id"]})],
            remediation="Validate redirect destinations against a strict same-origin or explicit destination allowlist; prefer server-side route identifiers over arbitrary URLs.",
            impact="May enable trusted-domain redirect abuse; phishing success, credential theft, and business impact were not tested.",
            manual_verification="Review intended redirect destinations and confirm the application rejects untrusted external origins.")
        finding.id="VF-"+uuid.uuid4().hex[:12]
        ctx.findings.append(finding)
        record["finding_id"]=finding.id
