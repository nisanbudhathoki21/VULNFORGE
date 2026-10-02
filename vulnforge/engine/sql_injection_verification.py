"""Conservative, read-only SQL error-behavior check on observed query parameters.

This is not an exploitation module: it does not use boolean extraction, timing,
stacked statements, writes, or out-of-band callbacks. A finding is limited to a
repeatable database parser error caused by a single quote in a researcher-visible
GET parameter, with both original and benign-suffix controls.
"""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ..core.redaction import SENSITIVE_PARAMS, redact_url_query_values

MAX_SQLI_SURFACES = 3
MAX_PARAMETER_VALUE_CHARS = 96
SQLI_REQUEST_COST = 4
_SENSITIVE_NAME = re.compile(
    r"(?:passw(?:or)?d|passwd|secret|token|api.?key|auth|session|cookie|csrf|xsrf|"
    r"email|phone|address|account.?number|ssn|credential|signature|nonce)", re.I)
_SENSITIVE_VALUE = re.compile(
    r"(?:eyJ[A-Za-z0-9_-]{12,}\.|AKIA[0-9A-Z]{16}|@[^\s.]+\.|^[0-9a-f]{32,}$)", re.I)
_STATEFUL_PATH = re.compile(r"(?:^|/)(?:logout|signout|delete|remove|unsubscribe|purchase|checkout|pay|transfer)(?:/|$)", re.I)

# High-confidence server-side database parser/driver error fingerprints only.
_DATABASE_ERROR_PATTERNS = (
    ("mysql", re.compile(r"(?:you have an error in your sql syntax|mysql_fetch_|mysqli?[_ .]|pdoexception.{0,80}mysql)", re.I)),
    ("postgresql", re.compile(r"(?:postgresql.{0,80}(?:error|exception)|pg_query\(|psqlexception|syntax error at or near)", re.I)),
    ("sqlite", re.compile(r"(?:sqlite(?:3)?\.(?:operationalerror|databaseerror)|sqlite_error|near [\"'][^\"']+[\"']: syntax error)", re.I)),
    ("mssql", re.compile(r"(?:unclosed quotation mark after the character string|incorrect syntax near|microsoft ole db provider for sql server)", re.I)),
    ("oracle", re.compile(r"(?:ORA-\d{5}|quoted string not properly terminated)", re.I)),
    ("generic-sqlstate", re.compile(r"SQLSTATE\[[0-9A-Z]{5}\].{0,100}(?:syntax|query|statement)", re.I)),
)


def _query_parameter(url: str, name: str) -> Optional[str]:
    try:
        matches=[value for key,value in parse_qsl(urlsplit(url).query,keep_blank_values=True) if key==name]
    except (TypeError,ValueError):
        return None
    return matches[0] if len(matches)==1 else None


def _safe_candidate(endpoint, parameter, authorization) -> Tuple[bool,str]:
    name=str(getattr(parameter,"name",""))
    url=str(getattr(endpoint,"url",""))
    if str(getattr(endpoint,"method","GET")).upper()!="GET": return False,"only observed GET endpoints are eligible"
    if getattr(endpoint,"scope_status","")!="IN_SCOPE": return False,"endpoint is not known in scope"
    if getattr(endpoint,"state_changing",False): return False,"endpoint is marked state-changing"
    if not 200<=int(getattr(endpoint,"status",0) or 0)<300: return False,"endpoint lacks a successful observed baseline"
    if _STATEFUL_PATH.search(urlsplit(url).path or "/"): return False,"stateful route names are excluded"
    if str(getattr(parameter,"location",""))!="query": return False,"only query parameters are eligible"
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}",name): return False,"parameter name is not a safe identifier"
    if SENSITIVE_PARAMS.search(name) or _SENSITIVE_NAME.search(name) or authorization.param_excluded(name):
        return False,"sensitive or explicitly excluded parameter"
    value=_query_parameter(url,name)
    if value is None or not value or len(value)>MAX_PARAMETER_VALUE_CHARS:
        return False,"parameter must have one non-empty, bounded observed value"
    if any(ord(ch)<0x20 for ch in value) or _SENSITIVE_VALUE.search(value):
        return False,"parameter value is sensitive or not a safe test candidate"
    allowed,reason=authorization.check(url,purpose="sql-injection-plan",method="GET")
    if not allowed: return False,reason
    return True,""


def _replace_query_value(url: str, name: str, value: str) -> str:
    parts=urlsplit(url)
    pairs=parse_qsl(parts.query,keep_blank_values=True)
    found=0; replaced=[]
    for key,current in pairs:
        if key==name:
            found+=1; replaced.append((key,value))
        else:
            replaced.append((key,current))
    if found!=1: raise ValueError("query parameter must occur exactly once")
    return urlunsplit((parts.scheme,parts.netloc,parts.path,urlencode(replaced,doseq=True),""))


def _database_errors(body: str) -> List[str]:
    text=str(body or "")[:2_000_000]
    return [name for name,pattern in _DATABASE_ERROR_PATTERNS if pattern.search(text)]


def collect_sql_injection_candidates(ctx) -> List[Dict[str,Any]]:
    """Return deduplicated leads from observed, in-scope endpoint parameters."""
    candidates=[]; seen=set()
    for endpoint in sorted(ctx.endpoints.values(),key=lambda item:(item.url,item.method)):
        for parameter in getattr(endpoint,"params",[]):
            ok,_reason=_safe_candidate(endpoint,parameter,ctx.authorization)
            key=(str(endpoint.url),str(parameter.name))
            if ok and key not in seen:
                seen.add(key)
                candidates.append({"url":str(endpoint.url),"parameter":str(parameter.name),
                    "value":_query_parameter(str(endpoint.url),str(parameter.name)),
                    "evidence_ids":list(getattr(endpoint,"evidence_ids",[]) or [])})
                if len(candidates)>=MAX_SQLI_SURFACES: return candidates
    return candidates


async def execute_sql_injection_tests(ctx) -> None:
    specs=list(getattr(ctx,"_sql_injection_test_specs",[]) or [])
    if not specs or ctx.stopped: return
    from ..core.profiles import get_profile
    if not ctx.config.active_requested or not get_profile(ctx.config.profile_name).allows_active:
        for planned in ctx.test_plan:
            if planned.test_type=="sql-injection-validation" and planned.status=="PLANNED": planned.status="BLOCKED"
        ctx.emit("stage","SQL injection checks blocked: explicit active request and active-capable mode are required")
        return
    for spec in specs:
        if ctx.stopped: break
        planned=next((item for item in ctx.test_plan if item.test_id==spec["test_id"]),None)
        if not planned or planned.status!="PLANNED": continue
        record={"test_id":planned.test_id,"hypothesis_id":planned.hypothesis_id,
            "type":"sql-injection-validation","status":"INCOMPLETE",
            "endpoint":redact_url_query_values(spec["url"]).split("?",1)[0],
            "parameter":spec["parameter"],"methodology_id":"VF-METHOD-SQLI-1",
            "security_claim":"repeatable database parser error triggered by a single-quote query mutation",
            "started_at":time.time(),"observations":[],"impact_proven":False,
            "data_extraction_attempted":False,"state_changes_attempted":False}
        try:
            # Original and plain alphanumeric suffix are negative controls. Two
            # identical quote probes are required for reproducible DB-error evidence.
            urls=[(spec["url"],"baseline"),
                (_replace_query_value(spec["url"],spec["parameter"],spec["value"]+"vf"),"benign-control"),
                (_replace_query_value(spec["url"],spec["parameter"],spec["value"]+"'"),"single-quote-probe"),
                (_replace_query_value(spec["url"],spec["parameter"],spec["value"]+"'"),"single-quote-repeat")]
            for test_url,kind in urls:
                allowed,reason=ctx.authorization.check(test_url,purpose="sql-injection-validation",method="GET")
                if not allowed:
                    record["scope_blocked"]=True; record["scope_reason"]=reason; break
                exchange=await ctx.requester.send("GET",test_url,module="sql-injection-validation",
                    follow_redirects=False,max_redirects=0)
                record["observations"].append({"kind":kind,"exchange_id":exchange.exchange_id,
                    "status":exchange.status,"error":exchange.error,
                    "database_error_families":_database_errors(exchange.response_body)})
                if exchange.error or exchange.status<=0: break
            record["status"]="EXECUTED" if len(record["observations"])==SQLI_REQUEST_COST else "INCOMPLETE"
            record["finished_at"]=time.time()
            planned.status=record["status"]
            ctx.tests.append(record)
        except Exception as exc:
            record.update({"status":"INCOMPLETE","error_type":type(exc).__name__,"finished_at":time.time()})
            planned.status="INCOMPLETE"; ctx.tests.append(record)
            if type(exc).__name__ in {"ScanAborted","CancelledError"}: raise
    ctx.emit("stage",f"SQL injection observations collected: {sum(t.get('type')=='sql-injection-validation' for t in ctx.tests)}")


def _error_proof(record: Dict[str,Any]) -> bool:
    items=record.get("observations",[])
    if len(items)!=SQLI_REQUEST_COST: return False
    baseline,control,probe,repeat=items
    if any(item.get("error") or not item.get("status") for item in items): return False
    if not (200<=int(baseline["status"])<300 and 200<=int(control["status"])<300): return False
    if not baseline.get("database_error_families") and not control.get("database_error_families"):
        probe_errors=set(probe.get("database_error_families",[]))
        repeat_errors=set(repeat.get("database_error_families",[]))
        return bool(probe_errors and probe_errors==repeat_errors)
    return False


def verify_sql_injection_tests(ctx) -> None:
    """Keep repeated parser errors as candidates; they do not prove SQL impact.

    The four-request contract distinguishes a repeatable parser response from a
    generic error, but without a safe query-semantics/data-boundary validation it
    cannot prove exploitable SQL injection. No VERIFIED finding is emitted here.
    """
    hypotheses={h.hypothesis_id:h for h in ctx.hypotheses}
    for record in ctx.tests:
        if record.get("type")!="sql-injection-validation" or record.get("status")!="EXECUTED":
            continue
        reproduced=_error_proof(record)
        record["status"]="CANDIDATE"
        record["reproduction_status"]="REPRODUCED" if reproduced else "CANDIDATE"
        record["claim_status"]="PARSER_ERROR_BEHAVIOR_ONLY"
        record["independent_verifier"]=("baseline and benign control lack a database parser error; both repeated quote probes show the same parser-error family"
            if reproduced else "the bounded baseline/control/repeat contract was not satisfied")
        record["impact_proven"]=False
        record["candidate_reason"]=("A reproducible parser error does not prove altered query semantics, unauthorized data access, or other security impact."
            if reproduced else "The parser-error behavior was not reproducible against both controls.")
        record["required_follow_up"]="Review parameterized-query use with the application owner; only use a separately authorized local fixture to validate a non-destructive query-boundary property."
        hypothesis=hypotheses.get(record.get("hypothesis_id"))
        if hypothesis:
            hypothesis.status="DEEPER_TESTING"
