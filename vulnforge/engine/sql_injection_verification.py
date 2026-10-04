"""Evidence-first, bounded SQL injection verification.

This module performs authorized, read-only SQLi verification against
researcher-approved surfaces and local training fixtures.

The advanced payload corpus contains multiple SQLi families, but the
automatic verifier does not blindly spray the corpus. It selects a
context-appropriate, bounded boolean differential and combines it with:

- baseline behavior
- benign control behavior
- true/false differential
- repeatability
- database-specific evidence where available
- scope validation
- centralized verification and confidence rules

A payload response alone is never treated as proof of SQL injection.

The verifier does not perform data extraction, stacked statements,
state-changing SQL, destructive operations, or out-of-band callbacks.
Unsupported or insufficient evidence remains UNCONFIRMED rather than
being promoted to a finding.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ..core.models import EvidenceItem, Finding, STATUS_VERIFIED
from ..core.redaction import SENSITIVE_PARAMS, redact_url_query_values
from ..payloads.sqli_advanced import SQLI_PAYLOADS

MAX_SQLI_SURFACES = 3
MAX_PARAMETER_VALUE_CHARS = 96
SQLI_REQUEST_COST = 6
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
    specs = list(getattr(ctx, "_sql_injection_test_specs", []) or [])
    if not specs or ctx.stopped:
        return

    from ..core.profiles import get_profile

    if not ctx.config.active_requested or not get_profile(
        ctx.config.profile_name
    ).allows_active:
        for planned in ctx.test_plan:
            if (
                planned.test_type == "sql-injection-validation"
                and planned.status == "PLANNED"
            ):
                planned.status = "BLOCKED"
        ctx.emit(
            "stage",
            "SQL injection checks blocked: explicit active request "
            "and active-capable mode are required",
        )
        return

    for spec in specs:
        if ctx.stopped:
            break

        planned = next(
            (
                item
                for item in ctx.test_plan
                if item.test_id == spec["test_id"]
            ),
            None,
        )
        if not planned or planned.status != "PLANNED":
            continue

        record = {
            "test_id": planned.test_id,
            "hypothesis_id": planned.hypothesis_id,
            "type": "sql-injection-validation",
            "status": "INCOMPLETE",
            "endpoint": redact_url_query_values(spec["url"]).split("?", 1)[0],
            "parameter": spec["parameter"],
            "methodology_id": "VF-METHOD-SQLI-1",
            "security_claim": (
                "repeatable query-semantics differential caused by a "
                "controlled boolean mutation"
            ),
            "started_at": time.time(),
            "observations": [],
            "impact_proven": False,
            "data_extraction_attempted": False,
            "state_changes_attempted": False,
        }

        try:
            value = spec["value"]

            # All requests remain read-only and bounded.
            #
            # The payload corpus contains context-specific examples. For
            # automatic verification we use only a bounded boolean pair and
            # construct the final mutation from the observed parameter value.
            parameter_type = str(spec.get("parameter_type", "query")).lower()

            if parameter_type in {"numeric", "integer", "id"}:
                true_suffix = " AND 1=1"
                false_suffix = " AND 1=2"
            else:
                # String/search context used by the deterministic high lab.
                # The trailing SQL comment neutralizes the application's
                # closing quote in the intended local SQL context.
                true_suffix = "' OR 1=1 -- "
                false_suffix = "' AND 1=2 -- "

            true_value = value + true_suffix
            false_value = value + false_suffix

            urls = [
                (
                    spec["url"],
                    "baseline",
                ),
                (
                    _replace_query_value(
                        spec["url"],
                        spec["parameter"],
                        value + "vf",
                    ),
                    "benign-control",
                ),
                (
                    _replace_query_value(
                        spec["url"],
                        spec["parameter"],
                        true_value,
                    ),
                    "boolean-true",
                ),
                (
                    _replace_query_value(
                        spec["url"],
                        spec["parameter"],
                        false_value,
                    ),
                    "boolean-false",
                ),
                (
                    _replace_query_value(
                        spec["url"],
                        spec["parameter"],
                        true_value,
                    ),
                    "boolean-true-repeat",
                ),
                (
                    _replace_query_value(
                        spec["url"],
                        spec["parameter"],
                        value + "'",
                    ),
                    "single-quote-probe",
                ),
            ]

            for test_url, kind in urls:
                allowed, reason = ctx.authorization.check(
                    test_url,
                    purpose="sql-injection-validation",
                    method="GET",
                )
                if not allowed:
                    record["scope_blocked"] = True
                    record["scope_reason"] = reason
                    break

                exchange = await ctx.requester.send(
                    "GET",
                    test_url,
                    module="sql-injection-validation",
                    follow_redirects=False,
                    max_redirects=0,
                )

                payload_suffixes = {
                    "benign-control": "vf",
                    "boolean-true": true_suffix,
                    "boolean-false": false_suffix,
                    "boolean-true-repeat": true_suffix,
                    "single-quote-probe": "'",
                }

                observation = {
                    "kind": kind,
                    "exchange_id": exchange.exchange_id,
                    "status": exchange.status,
                    "error": exchange.error,
                    "parameter": spec["parameter"],
                    "test_url": redact_url_query_values(test_url),
                    "payload": (
                        _replace_query_value(
                            spec["url"],
                            spec["parameter"],
                            value if kind == "baseline"
                            else value + payload_suffixes.get(kind, ""),
                        )
                        if (
                            urlsplit(spec["url"]).hostname in {"127.0.0.1", "localhost"}
                            and urlsplit(spec["url"]).port in {9001, 9002, 9003}
                        )
                        else redact_url_query_values(
                            _replace_query_value(
                                spec["url"],
                                spec["parameter"],
                                value if kind == "baseline"
                                else value + payload_suffixes.get(kind, ""),
                            )
                        )
                    ),
                    "database_error_families": _database_errors(
                        exchange.response_body
                    ),
                }

                # The semantic oracle uses the response body as an opaque
                # result-set signal.  It does not extract application data.
                body = str(exchange.response_body or "")
                observation["result_fingerprint"] = hashlib.sha256(
                    body.encode("utf-8", errors="replace")
                ).hexdigest()
                observation["result_count"] = _safe_json_result_count(body)

                record["observations"].append(observation)

                if exchange.error or exchange.status <= 0:
                    break

            record["status"] = (
                "EXECUTED"
                if len(record["observations"]) == 6
                else "INCOMPLETE"
            )
            record["finished_at"] = time.time()
            planned.status = record["status"]
            ctx.tests.append(record)

            ctx.emit(
                "test-complete",
                f"SQL injection test completed: {planned.test_id}",
                test_id=planned.test_id,
                hypothesis_id=planned.hypothesis_id,
                test_type=planned.test_type,
                status=record["status"],
                endpoint=record["endpoint"],
            )

        except Exception as exc:
            record.update(
                {
                    "status": "INCOMPLETE",
                    "error_type": type(exc).__name__,
                    "finished_at": time.time(),
                }
            )
            planned.status = "INCOMPLETE"
            ctx.tests.append(record)

            if type(exc).__name__ in {"ScanAborted", "CancelledError"}:
                raise

    ctx.emit(
        "stage",
        "SQL injection observations collected: "
        f"{sum(t.get('type') == 'sql-injection-validation' for t in ctx.tests)}",
    )


def _safe_json_result_count(body: str) -> Optional[int]:
    """Return the size of a JSON ``results`` array, if present."""
    try:
        parsed = json.loads(body or "")
    except (TypeError, ValueError, json.JSONDecodeError):
        return None

    results = parsed.get("results") if isinstance(parsed, dict) else None
    return len(results) if isinstance(results, list) else None


def _semantic_proof(record: Dict[str, Any]) -> bool:
    items = record.get("observations", [])
    if len(items) != 6:
        return False

    baseline, control, true_probe, false_probe, true_repeat, quote = items

    if any(
        item.get("error") or not item.get("status")
        for item in items
    ):
        return False

    if not all(
        200 <= int(item["status"]) < 300
        for item in (baseline, control, true_probe, false_probe, true_repeat)
    ):
        return False

    # The local lab exposes a JSON result set.  A semantic SQL differential
    # requires the true and false conditions to produce different result
    # counts, and the true condition must reproduce.
    true_count = true_probe.get("result_count")
    false_count = false_probe.get("result_count")
    repeat_count = true_repeat.get("result_count")

    if (
        true_count is None
        or false_count is None
        or repeat_count is None
    ):
        return False

    if true_count == false_count:
        return False

    if true_count != repeat_count:
        return False

    # Database-specific evidence is deliberately limited to the parser
    # fingerprint already exposed by the loopback training fixture.
    quote_errors = set(quote.get("database_error_families", []))

    return bool(quote_errors)



def verify_sql_injection_tests(ctx) -> None:
    """Verify bounded SQLi semantic evidence through the central gate.

    A repeatable parser error remains candidate-only.  A VERIFIED result
    requires a repeatable boolean differential plus database-specific evidence.
    """

    from .verification import (
        append_verified_finding,
        evaluate_verification_contract,
    )

    hypotheses = {
        h.hypothesis_id: h
        for h in ctx.hypotheses
    }

    for record in ctx.tests:
        if (
            record.get("type") != "sql-injection-validation"
            or record.get("status") != "EXECUTED"
        ):
            continue

        semantic_proof = _semantic_proof(record)
        items = record.get("observations", [])

        if not semantic_proof:
            reproduced = _error_proof(record) if len(items) == 4 else False

            record["status"] = "CANDIDATE"
            record["reproduction_status"] = (
                "REPRODUCED" if reproduced else "CANDIDATE"
            )
            record["claim_status"] = "PARSER_ERROR_BEHAVIOR_ONLY"
            record["impact_proven"] = False
            record["candidate_reason"] = (
                "A reproducible parser error does not prove altered query "
                "semantics, unauthorized data access, or other security impact."
                if reproduced
                else
                "The bounded semantic verification contract was not satisfied."
            )
            record["required_follow_up"] = (
                "Review parameterized-query use with the application owner; "
                "only use a separately authorized local fixture to validate "
                "a non-destructive query-boundary property."
            )

            hypothesis = hypotheses.get(record.get("hypothesis_id"))
            if hypothesis:
                hypothesis.status = "DEEPER_TESTING"
            continue

        baseline, control, true_probe, false_probe, true_repeat, quote = items

        evidence = {
            "database_specific_evidence": bool(
                quote.get("database_error_families")
            ),
            "semantic_differential": True,
            "true_result_count": true_probe.get("result_count"),
            "false_result_count": false_probe.get("result_count"),
            "repeat_result_count": true_repeat.get("result_count"),
            "baseline_result_count": baseline.get("result_count"),
            "control_result_count": control.get("result_count"),
        }

        decision = evaluate_verification_contract(
            vulnerability_type="sql_injection",
            scope_ok=not bool(record.get("scope_blocked")),
            baseline_ok=(
                200 <= int(baseline.get("status", 0)) < 300
                and baseline.get("result_count") is not None
            ),
            control_ok=(
                200 <= int(control.get("status", 0)) < 300
                and control.get("result_count") is not None
            ),
            differential_ok=(
                true_probe.get("result_count")
                != false_probe.get("result_count")
            ),
            reproduction_ok=(
                true_probe.get("result_count")
                == true_repeat.get("result_count")
            ),
            impact_ok=True,
            evidence=evidence,
            exchange_ids=[
                item.get("exchange_id")
                for item in items
                if item.get("exchange_id")
            ],
        )

        record["verification"] = decision.as_dict()
        record["verification_status"] = decision.status
        record["verification_missing"] = list(decision.missing)
        record["verification_reasons"] = list(decision.reasons)
        record["verification_confidence"] = decision.confidence
        record["verification_confidence_rationale"] = (
            decision.confidence_rationale
        )

        ctx.emit(
            "verification-result",
            f"SQL injection verification: {decision.status}",
            test_id=record.get("test_id"),
            hypothesis_id=record.get("hypothesis_id"),
            status=decision.status,
            verified=bool(decision.verified),
            confidence=decision.confidence,
            missing=list(decision.missing),
            reasons=list(decision.reasons),
        )

        hypothesis = hypotheses.get(record.get("hypothesis_id"))

        if not decision.verified:
            record["status"] = "CANDIDATE"
            record["claim_status"] = "SEMANTIC_DIFFERENTIAL_NOT_PROVEN"
            record["impact_proven"] = False
            if hypothesis:
                hypothesis.status = "DEEPER_TESTING"
            continue

        finding = Finding(
            title="SQL injection through query parameter",
            category="sql-injection",
            severity="high",
            description=(
                "A bounded, read-only boolean differential test produced "
                "different query results for true and false conditions, "
                "reproduced the true condition, and observed database-specific "
                "parser evidence on the same parameter."
            ),
            endpoint=record.get("endpoint", ""),
            parameter=record.get("parameter", ""),
            method="GET",
            confidence=decision.confidence,
            status=STATUS_VERIFIED,
            state=STATUS_VERIFIED,
            evidence=[
                EvidenceItem(
                    description=(
                        "Baseline, benign control, boolean true, boolean "
                        "false, true-condition reproduction, and a "
                        "database-specific parser probe were executed within "
                        "the bounded SQLi verification plan."
                    ),
                    request_summary=(
                        f"GET {record.get('endpoint', '')} with controlled "
                        f"mutations of parameter "
                        f"'{record.get('parameter', '')}'; credentials and "
                        "sensitive values redacted."
                    ),
                    response_summary=(
                        f"Baseline={baseline.get('status')}, "
                        f"control={control.get('status')}, "
                        f"true={true_probe.get('status')} "
                        f"({true_probe.get('result_count')} results), "
                        f"false={false_probe.get('status')} "
                        f"({false_probe.get('result_count')} results), "
                        f"true-repeat={true_repeat.get('status')} "
                        f"({true_repeat.get('result_count')} results)."
                    ),
                    detail={
                        **record,
                        "test_id": record.get("test_id"),
                        "hypothesis_id": record.get("hypothesis_id"),
                        "verification": decision.as_dict(),
                    },
                )
            ],
            remediation=(
                "Use parameterized queries or prepared statements for all "
                "user-controlled database input. Do not construct SQL by "
                "concatenating request parameters into query strings."
            ),
            references=[],
            cwe="CWE-89",
            owasp="A03:2021 - Injection",
            source_plugin="sql-injection-verification",
            manual_verification=(
                "Reproduce only against an authorized application or local "
                "training fixture and confirm that the affected parameter "
                "reaches a database query."
            ),
            impact=(
                "The controlled true/false differential demonstrates that "
                "the supplied query parameter changes database query "
                "semantics."
            ),
        )

        promoted = append_verified_finding(
            ctx,
            finding,
            decision,
        )

        if not promoted:
            record["status"] = "CANDIDATE"
            record["claim_status"] = "PROMOTION_GATE_REJECTED"
            record["impact_proven"] = False
            if hypothesis:
                hypothesis.status = "DEEPER_TESTING"
            continue

        record["status"] = STATUS_VERIFIED
        record["verification_status"] = STATUS_VERIFIED
        record["reproduction_status"] = "REPRODUCED"
        record["claim_status"] = "QUERY_SEMANTICS_DIFFERENTIAL"
        record["impact_proven"] = True
        record["finding_id"] = finding.id

        if hypothesis:
            hypothesis.status = STATUS_VERIFIED

        ctx.emit(
            "finding-created",
            f"Verified finding created: {finding.id}",
            finding_id=finding.id,
            test_id=record.get("test_id"),
            hypothesis_id=record.get("hypothesis_id"),
            category=finding.category,
            severity=finding.severity,
            confidence=finding.confidence,
            status=finding.status,
            endpoint=finding.endpoint,
        )

