"""Canonical evidence lifecycle for every planned security test.

The scanner may stop at any point. A test's persisted lifecycle therefore
contains explicit states for every stage rather than implying that a response
or a difference reached a finding decision.
"""
from __future__ import annotations

PIPELINE_STAGES = (
    "DISCOVERY",
    "OBSERVATION",
    "HYPOTHESIS",
    "TEST PLANNING",
    "BASELINE",
    "CONTROL",
    "DIFFERENTIAL TEST",
    "REPRODUCTION",
    "IMPACT VALIDATION",
    "FINDING DECISION",
)


def build_pipeline(test: dict) -> list[dict[str, str]]:
    """Return an honest stage ledger for a test result.

    This function only derives lifecycle state from fields actually present in
    the test record. Missing exchanges, controls, or impact assertions remain
    SKIPPED/UNTESTABLE; they are never upgraded because a payload was sent.
    """
    status = str(test.get("status") or "NOT_RUN").upper()
    has_endpoint = bool(test.get("endpoint"))
    has_observation = bool(test.get("observations") or test.get("observation") or test.get("observed"))
    has_hypothesis = bool(test.get("hypothesis_id") or test.get("hypothesis"))
    planned = status not in {"NOT_RUN", "BLOCKED", "SKIPPED"} or test.get("planned") is True
    has_baseline = bool(test.get("baseline_exchange_id") or test.get("baseline_status") is not None)
    has_control = bool(
        test.get("control_exchange_id") or test.get("negative_control_exchange_id")
        or test.get("control") or test.get("controls")
    )
    has_difference = bool(test.get("differential") or test.get("diff") or test.get("differences"))
    reproduced = str(test.get("reproduction_status") or "").upper() in {"REPRODUCED", "VERIFIED"}
    impact = bool(test.get("impact_proven") or test.get("impact_validated"))
    decision = status in {"VERIFIED", "CONFIRMED", "CANDIDATE", "INCONCLUSIVE", "KILLED", "UNTESTABLE", "SKIPPED", "BLOCKED"}

    states = {
        "DISCOVERY": "COMPLETE" if has_endpoint else "SKIPPED",
        "OBSERVATION": "COMPLETE" if has_observation or has_endpoint else "SKIPPED",
        "HYPOTHESIS": "COMPLETE" if has_hypothesis else "UNTESTABLE",
        "TEST PLANNING": "COMPLETE" if planned else ("BLOCKED" if status in {"BLOCKED", "SKIPPED"} else "SKIPPED"),
        "BASELINE": "COMPLETE" if has_baseline else ("BLOCKED" if status in {"BLOCKED", "SKIPPED"} else "UNTESTABLE"),
        "CONTROL": "COMPLETE" if has_control else ("UNTESTABLE" if has_baseline else "SKIPPED"),
        "DIFFERENTIAL TEST": "COMPLETE" if has_difference else ("UNTESTABLE" if has_baseline else "SKIPPED"),
        "REPRODUCTION": "COMPLETE" if reproduced else ("KILLED" if status == "KILLED" else "UNTESTABLE"),
        "IMPACT VALIDATION": "COMPLETE" if impact else ("UNTESTABLE" if reproduced else "SKIPPED"),
        "FINDING DECISION": "COMPLETE" if decision else "PENDING",
    }
    return [{"stage": stage, "status": states[stage]} for stage in PIPELINE_STAGES]


def current_stage(test: dict) -> str:
    ledger = build_pipeline(test)
    for entry in reversed(ledger):
        if entry["status"] == "COMPLETE":
            return entry["stage"]
    return "DISCOVERY"
