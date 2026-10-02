"""Evidence-backed coverage reporting.

Coverage is a record of what the current run actually selected, observed,
executed, blocked, or left untestable. It never infers coverage from the
existence of a scanner class alone.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List


def _status(row: Dict[str, Any]) -> str:
    status = str(row.get("status") or "NOT_TESTED").upper()
    aliases = {
        "VERIFIED": "CONFIRMED",
        "CANDIDATE": "UNCONFIRMED",
        "INCONCLUSIVE": "UNCONFIRMED",
        "OBSERVATION_ONLY": "UNCONFIRMED",
        "TESTED_CLEAN": "KILLED",
        "NO_TEST_SURFACE": "UNTESTABLE",
        "NOT_SELECTED": "SKIPPED",
    }
    return aliases.get(status, status)


def _row_from_matrix(row: Dict[str, Any]) -> Dict[str, Any]:
    result = dict(row)
    result.setdefault("category", {
        "bola": "Object-level authorization",
        "bfla": "Function-level authorization",
        "tenant_isolation": "Tenant isolation",
        "xss": "Cross-site scripting",
        "sqli": "SQL injection",
        "ssrf": "SSRF indicators",
        "open_redirect": "Open redirect",
        "security_headers": "Security headers",
        "cookie_session": "Cookie/session controls",
    }.get(str(row.get("class_id")), row.get("name") or row.get("class_id") or "Unknown"))
    # Keep the historical human-facing BLOCKED label for a configured
    # authorization plan that was prevented before its first request. The
    # canonical class result remains SKIPPED in ``final_status``.
    if row.get("class_id") == "bola" and row.get("status") == "SKIPPED" and row.get("planned", 0):
        result["status"] = "BLOCKED"
    result["final_status"] = _status(row)
    result["evidence_backed"] = bool(
        row.get("verified") or row.get("executed") or row.get("hypotheses") or row.get("test_surface_count")
    )
    result.setdefault("notes", row.get("reason") or "No execution note was recorded.")
    return result


def build_coverage(ctx) -> List[Dict[str, Any]]:
    """Build the implementation-backed vulnerability and discovery matrix."""
    matrix = list(getattr(ctx, "vulnerability_matrix", []) or [])
    rows = [_row_from_matrix(row) for row in matrix if isinstance(row, dict)]
    if rows:
        return rows

    # A scan may be interrupted before the vulnerability matrix stage. Return
    # honest discovery coverage instead of fabricating vulnerability results.
    endpoints = getattr(ctx, "endpoints", {}) or {}
    parameters = getattr(ctx, "parameters", {}) or {}
    exchanges = list(getattr(getattr(ctx, "requester", None), "exchanges", []) or [])
    return [
        {
            "class_id": "discovery",
            "category": "Endpoint discovery",
            "name": "Endpoint discovery",
            "selected": True,
            "supported": True,
            "status": "PARTIAL" if endpoints else "NOT_TESTED",
            "final_status": "UNCONFIRMED" if endpoints else "UNTESTABLE",
            "evidence_backed": bool(endpoints),
            "test_surface_count": len(endpoints),
            "notes": "Persisted endpoint inventory from the current scan.",
        },
        {
            "class_id": "parameters",
            "category": "Parameter inventory",
            "name": "Parameter inventory",
            "selected": True,
            "supported": True,
            "status": "PARTIAL" if parameters else "NOT_TESTED",
            "final_status": "UNCONFIRMED" if parameters else "UNTESTABLE",
            "evidence_backed": bool(parameters),
            "test_surface_count": len(parameters),
            "notes": "Persisted parameter records from observed requests and forms.",
        },
        {
            "class_id": "http-traffic",
            "category": "HTTP traffic capture",
            "name": "HTTP traffic capture",
            "selected": True,
            "supported": True,
            "status": "PARTIAL" if exchanges else "NOT_TESTED",
            "final_status": "UNCONFIRMED" if exchanges else "UNTESTABLE",
            "evidence_backed": bool(exchanges),
            "test_surface_count": len(exchanges),
            "notes": "Normalized request and response records captured by the central requester.",
        },
    ]


def coverage_summary(ctx) -> Dict[str, Any]:
    rows = build_coverage(ctx)
    counts: Dict[str, int] = {}
    for row in rows:
        status = str(row.get("final_status") or row.get("status") or "NOT_TESTED")
        counts[status] = counts.get(status, 0) + 1
    return {
        "total": len(rows),
        "counts": counts,
        "selected": sum(1 for row in rows if row.get("selected")),
        "supported": sum(1 for row in rows if row.get("supported")),
        "evidence_backed": sum(1 for row in rows if row.get("evidence_backed")),
        "rows": rows,
    }
