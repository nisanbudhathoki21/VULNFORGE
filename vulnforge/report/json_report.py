"""
VulnForge — JSON report renderer.
"""
from __future__ import annotations

import json
import time
from copy import deepcopy
from typing import Any, Dict

from ..core.redaction import redact_any
from ..core.outcomes import class_result_status, finding_result_status, outcome_counts, test_result_status

DISCLAIMER = ("VulnForge performs automated security assessment and identifies "
              "potential vulnerabilities. Results require validation. Automated "
              "tools cannot exhaustively detect business-logic, authorization, or "
              "chained vulnerabilities — manual review is essential.")


def _records(items):
    return [item.to_dict() if hasattr(item, "to_dict") else item for item in items]


def _field(item, name, default=None):
    """Read a field from either a dict record or a model/object."""
    if isinstance(item, dict):
        return item.get(name, default)
    return getattr(item, name, default)


def _status(item):
    return str(_field(item, "status", "") or "").upper()


def _endpoint(item):
    return str(_field(item, "endpoint", "") or "")


def _parameter(item):
    return str(_field(item, "parameter", "") or "")


def _finding_state_counts(items):
    """Canonical lifecycle counts used by every report renderer."""
    records = list(items or [])

    confirmed = sum(
        1 for item in records
        if _status(item) in {"VERIFIED", "CONFIRMED"}
    )

    candidates = sum(
        1 for item in records
        if _status(item) not in {"VERIFIED", "CONFIRMED"}
    )

    killed = sum(
        1 for item in records
        if _status(item) == "KILLED"
    )

    unconfirmed = sum(
        1 for item in records
        if _status(item) == "UNCONFIRMED"
    )

    skipped = sum(
        1 for item in records
        if _status(item) == "SKIPPED"
    )

    return {
        "total_records": len(records),
        "confirmed": confirmed,
        "verified": confirmed,
        "candidates": candidates,
        "unconfirmed": unconfirmed,
        "killed": killed,
        "skipped": skipped,
    }


def _with_test_outcomes(items):
    records = deepcopy(list(items or []))
    for item in records:
        if isinstance(item, dict):
            item["result_status"] = test_result_status(item)
    return records


def _with_class_outcomes(items):
    records = deepcopy(list(items or []))
    for item in records:
        if isinstance(item, dict):
            item["result_status"] = class_result_status(item)
    return records


def _with_finding_outcomes(items):
    records = _records(items)
    for item in records:
        if isinstance(item, dict):
            item["result_status"] = finding_result_status(item)
    return records


def build_report_dict(scan) -> Dict[str, Any]:
    if isinstance(scan, dict):
        # Historical reports used `confirmed` before the explicit VERIFIED
        # lifecycle existed. Do not silently trust/promote those old labels.
        doc=deepcopy(scan)
        doc.setdefault("schema_version","1.0")
        doc.setdefault("tool","VulnForge")
        doc.setdefault("version","0.4.0")
        doc.setdefault("statistics",{})
        doc.setdefault("scope",{})
        doc.setdefault("findings",[])
        doc.setdefault("candidates",[])
        doc.setdefault("hypotheses",[])
        doc.setdefault("tests",[])
        doc.setdefault("endpoints",[])
        doc.setdefault("parameters",[])
        doc.setdefault("vulnerability_matrix",[])
        if not isinstance(doc.get("statistics"),dict): doc["statistics"]={}
        if not isinstance(doc.get("scope"),dict): doc["scope"]={}
        for key in ("findings","candidates","hypotheses","tests","endpoints","parameters","vulnerability_matrix"):
            if not isinstance(doc.get(key),list): doc[key]=[]
        scan_info=doc.setdefault("scan",{})
        if not isinstance(scan_info,dict):
            doc["scan"]={"scan_id":"","target":"","profile":"","started_at":None,"status":"unknown"}
        else:
            scan_info.setdefault("scan_id","")
            scan_info.setdefault("target","")
            scan_info.setdefault("profile","")
            scan_info.setdefault("started_at",None)
            scan_info.setdefault("status","unknown")
        original=doc.get("findings",[])
        verified=[f for f in original if f.get("status")=="VERIFIED"]
        unverified=[]
        for item in original:
            if item.get("status")=="VERIFIED": continue
            item["legacy_status"]=item.get("status","UNKNOWN")
            item["status"]="CANDIDATE"; item["state"]="CANDIDATE"
            unverified.append(item)
        doc["findings"]=_with_finding_outcomes(verified)
        doc["verified_findings"]=_with_finding_outcomes(verified)
        doc["candidates"]=_with_finding_outcomes(list(doc.get("candidates",[]))+unverified)
        doc["tests"]=_with_test_outcomes(doc.get("tests",[]))
        doc["vulnerability_matrix"]=_with_class_outcomes(doc.get("vulnerability_matrix",[]))
        doc["result_summary"]={
            "tests":outcome_counts(doc["tests"]),
            "classes":outcome_counts(doc["vulnerability_matrix"],classifier=class_result_status),
        }
        if "statistics" in doc:
            doc["statistics"]["findings_total"]=len(verified)
            doc["statistics"]["verified_findings_total"]=len(verified)
            doc["statistics"]["candidates_total"]=len(doc["candidates"])
        return doc
    ctx = scan.context
    sev_order = ["critical", "high", "medium", "low", "info"]
    sev_counts = {s: 0 for s in sev_order}
    all_findings = list(getattr(ctx, "findings", []) or [])

    verified = [
        f for f in all_findings
        if _status(f) in {"VERIFIED", "CONFIRMED"}
    ]

    candidates = [
        f for f in all_findings
        if _status(f) not in {"VERIFIED", "CONFIRMED"}
    ]
    for f in verified:
        sev_counts[f.severity.lower() if f.severity.lower() in sev_counts else "info"] += 1
    test_records=_with_test_outcomes(getattr(ctx,"tests",[]))
    class_records=_with_class_outcomes(getattr(ctx,"vulnerability_matrix",[]))
    verified_records=_with_finding_outcomes(verified)
    candidate_records=_with_finding_outcomes(candidates)
    result_summary={
        "tests": outcome_counts(test_records),
        "classes": outcome_counts(
            class_records,
            classifier=class_result_status,
        ),
        "findings": _finding_state_counts(all_findings),
    }

    evidence_records = _records(getattr(ctx, "evidence", []))

    finding_summary = _finding_state_counts(all_findings)

    integrity = {
        "database_source_of_truth": True,
        "validated": False,
        "hypotheses": len(getattr(ctx, "hypotheses", []) or []),
        "tests": len(getattr(ctx, "tests", []) or []),
        "test_runs": 0,
        "findings_total": finding_summary["total_records"],
        "confirmed_findings": finding_summary["confirmed"],
        "candidates": finding_summary["candidates"],
        "evidence": len(evidence_records),
        "integrity_errors": [],
    }
    duration = (ctx.stats.finished_at or time.time()) - ctx.stats.started_at
    return redact_any({
        "schema_version": "1.0",
        "tool": "VulnForge",
        "version": "0.4.0",
        "disclaimer": DISCLAIMER,
        "scan": {
            "scan_id": ctx.scan_id,
            "target": ctx.config.target,
            "profile": ctx.config.profile_name,
            "test_profile": getattr(ctx.config,"test_profile","full"),
            "started_at": ctx.stats.started_at,
            "duration_s": round(duration, 2),
            "aborted": scan.aborted,
            "status": ("stopped" if scan.aborted else ("partial" if ctx.stop_reason else "completed")),
            "stop_reason": ctx.stop_reason,
            "stage_timings": scan.stage_timings,
            "report_paths": getattr(scan,"report_paths",{}),
        },
        "scope": ctx.authorization.describe(),
        "request_controls": {
            "configured_rate_limit_per_second": getattr(ctx.config,"request_rate",None),
            "request_budget": getattr(ctx.config,"request_budget",None),
            "timeout_seconds": getattr(ctx.config,"request_timeout",None),
            "requests_used": getattr(ctx.stats,"requests_sent",0),
        },
        "target_rate_limit_observations": {
            "http_429_responses": sum(1 for exchange in getattr(getattr(ctx,"requester",None),"exchanges",[]) if getattr(exchange,"status",0)==429),
            "retry_after_responses": sum(1 for exchange in getattr(getattr(ctx,"requester",None),"exchanges",[]) if any(str(k).lower()=="retry-after" for k in getattr(exchange,"response_headers",{}))),
            "interpretation": "Observed 429/Retry-After responses only; no maximum safe target rate is inferred.",
        },
        "target_normalization": getattr(ctx,"target_normalization",{}),
        "statistics": {**ctx.stats.to_dict(),
                       "scope_denied": ctx.authorization.stats.get("denied", 0),
                       "crawl_status_counts": getattr(ctx,"crawl_status_counts",{}),
                       "findings_total": len(verified),
                       "verified_findings_total": len(verified),
                       "candidates_total": len(candidates),
                       "by_severity": sev_counts},
        "result_summary": result_summary,
        "finding_summary": finding_summary,
        "integrity": integrity,
        "technologies": [t.to_dict() for t in ctx.technologies.values()],
        "intelligence": getattr(ctx, "intelligence", {}),
        "frontend_intelligence": getattr(ctx,"frontend_intelligence",{}),
        "application_model": (ctx.application_model.to_dict() if getattr(ctx,"application_model",None) else {}),
        "report_manifest": getattr(ctx,"report_manifest",{}),
        "endpoints": [e.to_dict() for e in ctx.endpoints.values()],
        "parameters": [p.to_dict() for p in ctx.parameters.values()],
        "asset_nodes": _records(getattr(ctx,"asset_nodes",[])),
        "asset_edges": _records(getattr(ctx,"asset_edges",[])),
        "actors": _records(getattr(ctx,"actors",[])),
        "resources": _records(getattr(ctx,"resources",[])),
        "security_properties": _records(getattr(ctx,"security_properties",[])),
        "api_inventory": getattr(ctx,"api_inventory",[]),
        "api_documents": getattr(ctx,"api_documents",[]),
        "vulnerability_matrix": class_records,
        "live_observations": getattr(ctx,"live_observations",[]),
        "live_state_counts": getattr(ctx,"live_state_counts",{}),
        "hypotheses": _records(getattr(ctx, "hypotheses", [])),
        "test_plan": _records(getattr(ctx,"test_plan",[])),
        "tests": test_records,
        "evidence": evidence_records,
        "attack_paths": _records(getattr(ctx,"attack_paths",[])),
        "attack_path_summary": {
            "records": len(getattr(ctx,"attack_paths",[])),
            "verified_components": sum(1 for p in getattr(ctx,"attack_paths",[]) if getattr(p,"status","")=="VERIFIED_COMPONENT"),
            "hypothesis_paths": sum(1 for p in getattr(ctx,"attack_paths",[]) if getattr(p,"status","")=="HYPOTHESIS"),
            "end_to_end_verified": False,
            "warning": "Component-level evidence and hypotheses only; no end-to-end exploitability is inferred."
        },
        "workflow_model": getattr(ctx,"workflow_model",{}),
        "workflow_plan_errors": list(getattr(ctx,"workflow_plan_errors",[])),
        "workflow_summary": (getattr(ctx,"workflow_model",{}).get("summary",{})
            if isinstance(getattr(ctx,"workflow_model",{}),dict) else {}),
        "configured_workflow_summary": {
            "planned": sum(1 for item in getattr(ctx,"test_plan",[]) if getattr(item,"test_type","")=="configured-read-only-workflow"),
            "records": sum(1 for item in getattr(ctx,"tests",[]) if item.get("type")=="configured-read-only-workflow"),
            "observed_steps": sum(len(item.get("steps",[])) for item in getattr(ctx,"tests",[]) if item.get("type")=="configured-read-only-workflow"),
            "security_properties_verified": 0
        },
        "browser_workflow_summary": {
            "planned": sum(1 for item in getattr(ctx,"test_plan",[]) if getattr(item,"test_type","")=="browser-read-only-workflow"),
            "records": sum(1 for item in getattr(ctx,"tests",[]) if item.get("type")=="browser-read-only-workflow"),
            "outbound_http_routed_through_requester": True,
            "state_changing_requests_allowed": False,
            "browser_state_persisted": False,
            "security_properties_verified": 0
        },
        "phases": [p.to_dict() if hasattr(p,"to_dict") else p for p in getattr(ctx,"phases",[])],
        "coverage": __import__("vulnforge.core.coverage",fromlist=["build_coverage"]).build_coverage(ctx),
        "risk_summary": getattr(ctx,"risk_summary",{}),
        "discovery_signals":  [s.to_dict() for s in ctx.signals],
        "findings": verified_records,
        "verified_findings": verified_records,
        "candidates": candidate_records,
        "audit_log": ctx.authorization.audit_dump(),
    })


def write_json_report(scan, path: str) -> str:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(build_report_dict(scan), fh, indent=2, ensure_ascii=False)
    return path
