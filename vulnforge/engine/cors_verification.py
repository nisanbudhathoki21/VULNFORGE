"""Read-only CORS policy verification using bounded, provenance-linked GET requests."""
from __future__ import annotations
import time
from typing import Any, Dict, List

TEST_ORIGINS = (
    "https://vf-a.invalid",
    "https://vf-b.invalid",
    "https://vf-c.invalid",
)


def _header(exchange, name: str) -> str:
    return str(exchange.header(name, "") or "").strip()


async def execute_cors_tests(ctx) -> None:
    """Collect three harmless GET observations per planned surface; do not infer impact."""
    specs=list(getattr(ctx,"_cors_test_specs",[]))
    if not specs or ctx.stopped:
        return
    from ..core.profiles import get_profile
    profile=get_profile(ctx.config.profile_name)
    if not ctx.config.active_requested or not profile.allows_active:
        for planned in ctx.test_plan:
            if planned.test_type=="cors-origin-reflection" and planned.status=="PLANNED":
                planned.status="BLOCKED"
        ctx.emit("stage","CORS checks blocked: explicit active request and active-capable safety mode are required")
        return
    for spec in specs:
        if ctx.stopped:
            break
        planned=next((p for p in ctx.test_plan if p.test_id==spec["test_id"]),None)
        record={"test_id":spec["test_id"],"hypothesis_id":spec["hypothesis_id"],
                "type":"cors-origin-reflection","status":"INCOMPLETE","endpoint":spec["url"],
                "methodology_id":"VF-METHOD-CORS-1","started_at":time.time(),
                "observations":[],"security_claim":"credentialed CORS origin-reflection response policy",
                "impact_proven":False}
        try:
            for origin in TEST_ORIGINS:
                exchange=await ctx.requester.send("GET",spec["url"],headers={"Origin":origin},
                    module="cors-origin-reflection",follow_redirects=False)
                observation={"origin":origin,"exchange_id":exchange.exchange_id,
                    "status":exchange.status,"error":exchange.error,
                    "allow_origin":_header(exchange,"access-control-allow-origin"),
                    "allow_credentials":_header(exchange,"access-control-allow-credentials").lower(),
                    "vary":_header(exchange,"vary")}
                record["observations"].append(observation)
                if exchange.error or exchange.status<=0:
                    break
            completed=len(record["observations"])==len(TEST_ORIGINS)
            record["status"]="EXECUTED" if completed else "INCOMPLETE"
            record["reproduction_status"]="REPRODUCED" if completed and all(
                item["allow_origin"]==item["origin"] and item["allow_credentials"]=="true"
                for item in record["observations"]) else "CANDIDATE"
            record["finished_at"]=time.time()
            if planned: planned.status="EXECUTED" if completed else "INCOMPLETE"
            ctx.tests.append(record)
        except Exception as exc:
            record["status"]="INCOMPLETE"
            record["reason"]=f"{type(exc).__name__}: bounded CORS observation did not complete"
            record["finished_at"]=time.time()
            if planned: planned.status="INCOMPLETE"
            ctx.tests.append(record)
            if type(exc).__name__ in {"ScanAborted", "CancelledError"}:
                raise
    ctx.emit("stage",f"CORS observations collected: {sum(t.get('type')=='cors-origin-reflection' for t in ctx.tests)}")


def verify_cors_tests(ctx) -> None:
    """Record a reproducible CORS header observation, never a confirmed vulnerability.

    Header reflection and Allow-Credentials do not prove browser credential delivery,
    origin trust, sensitive response access, or impact. These tests therefore remain
    candidates until a separately authorized browser/data-boundary validation exists.
    """
    hypotheses={h.hypothesis_id:h for h in ctx.hypotheses}
    for record in ctx.tests:
        if record.get("type")!="cors-origin-reflection" or record.get("status")!="EXECUTED":
            continue
        observations=record.get("observations",[])
        reproduced=(len(observations)==len(TEST_ORIGINS) and all(
            item.get("status") is not None and 200<=int(item["status"])<300 and
            item.get("error") in (None,"") and item.get("origin")==expected and
            item.get("allow_origin")==expected and item.get("allow_credentials")=="true"
            for item,expected in zip(observations,TEST_ORIGINS)))
        record["status"]="CANDIDATE"
        record["reproduction_status"]="REPRODUCED" if reproduced else "CANDIDATE"
        record["claim_status"]="RESPONSE_HEADER_POLICY_ONLY"
        record["independent_verifier"]=("three distinct reserved origins were reflected with credential allowance; this does not prove browser access or impact"
            if reproduced else "the bounded three-origin reflection condition was not reproduced")
        record["impact_proven"]=False
        record["candidate_reason"]=("CORS response headers alone do not establish that an untrusted browser origin can read sensitive authenticated data."
            if reproduced else "The response did not meet the bounded reflection observation contract.")
        record["required_follow_up"]="Only with explicit authorization: verify browser credential behavior and demonstrate access to a non-public researcher-controlled response; never use real user data."
        hypothesis=hypotheses.get(record.get("hypothesis_id"))
        if hypothesis:
            hypothesis.status="DEEPER_TESTING"
