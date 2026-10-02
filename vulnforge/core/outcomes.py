"""Public, evidence-conscious result states for reports and CLI output.

Internal status values are retained for compatibility with existing records;
this module adds a stable user-facing assessment state without promoting leads.
"""
from __future__ import annotations

from collections import Counter
from typing import Any, Dict, Iterable

RESULT_STATES = (
    "CONFIRMED",
    "UNCONFIRMED",
    "KILLED",
    "UNTESTABLE",
    "SKIPPED",
    "UNSUPPORTED",
    "INFORMATIONAL",
)


def test_result_status(record: Dict[str, Any]) -> str:
    """Map an executed test record to a conservative public result state."""
    status = str(record.get("status", "")).strip().upper()
    if status in {"VERIFIED", "CONFIRMED"}:
        return "CONFIRMED"
    if status in {"KILLED", "FALSE_POSITIVE", "FALSE-POSITIVE"}:
        return "KILLED"
    if status in {"CANDIDATE", "REPRODUCED", "SIGNAL", "OBSERVED", "DEEPER_TESTING", "UNCONFIRMED"}:
        return "UNCONFIRMED"
    if status in {"UNSUPPORTED"}:
        return "UNSUPPORTED"
    if status in {"INFORMATIONAL", "HARDENING"}:
        return "INFORMATIONAL"
    if status in {"INCOMPLETE", "UNTESTABLE", "ERROR", "FAILED"}:
        return "UNTESTABLE"
    if status in {"NOT_RUN", "BLOCKED", "SKIPPED", "NOT_SELECTED"}:
        return "SKIPPED"
    # Unknown states must never be interpreted as success.
    return "UNTESTABLE"


def finding_result_status(record: Dict[str, Any]) -> str:
    """Keep observed hardening advice distinct from unconfirmed exploit leads."""
    category = str(record.get("category", "")).lower().replace("_", " ")
    status = str(record.get("status", "")).strip().upper()
    if status != "VERIFIED" and any(token in category for token in (
        "header hardening", "security-header observation", "security header observation"
    )):
        return "INFORMATIONAL"
    return test_result_status(record)


def class_result_status(row: Dict[str, Any]) -> str:
    """Map registry planning states without hiding unsupported or skipped work."""
    status = str(row.get("status", "")).strip().upper()
    if not row.get("supported", status != "UNSUPPORTED") or status == "UNSUPPORTED":
        return "UNSUPPORTED"
    if status in {"CONFIRMED", "VERIFIED"} or int(row.get("verified", 0)) > 0:
        return "CONFIRMED"
    if status in {"KILLED", "TESTED_CLEAN"}:
        return "KILLED"
    if (status in {"INCONCLUSIVE", "UNCONFIRMED", "OBSERVATION_ONLY"}
            or int(row.get("inconclusive", 0)) > 0
            or int(row.get("reproduced_observations", 0)) > 0):
        return "UNCONFIRMED"
    if status in {"NO_TEST_SURFACE", "UNTESTABLE", "PLANNED"}:
        return "UNTESTABLE"
    if status in {"BLOCKED", "NOT_SELECTED", "SKIPPED"}:
        return "SKIPPED"
    if status in {"INFORMATIONAL", "HARDENING"}:
        return "INFORMATIONAL"
    return "UNTESTABLE"


def outcome_counts(items: Iterable[Dict[str, Any]], *, classifier=test_result_status) -> Dict[str, int]:
    counts = Counter(classifier(item) for item in items)
    return {state: counts.get(state, 0) for state in RESULT_STATES}
