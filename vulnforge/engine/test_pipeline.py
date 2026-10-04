"""Canonical evidence-driven lifecycle for VulnForge research tests.

Scanner observations are never findings by themselves.

The lifecycle is generic at the stage level, while evidence completeness is
evaluated through vulnerability-specific contracts. The central verifier
remains authoritative for the actual security verdict.
"""

from __future__ import annotations

from typing import Any


PIPELINE_STAGES = (
    "SCOPE",
    "DISCOVERY",
    "OBSERVATION",
    "HYPOTHESIS",
    "TEST PLANNING",
    "BASELINE",
    "CONTROL",
    "MUTATION",
    "DIFFERENTIAL TEST",
    "REPRODUCTION",
    "IMPACT VALIDATION",
    "EVIDENCE ASSEMBLY",
    "VERIFICATION GATE",
    "FINDING DECISION",
)

TERMINAL_STATUSES = {
    "VERIFIED",
    "CANDIDATE",
    "INCONCLUSIVE",
    "KILLED",
    "UNTESTABLE",
    "BLOCKED",
    "SKIPPED",
}

BLOCKED_STATUSES = {
    "BLOCKED",
    "SKIPPED",
}

VERIFIED_STATUSES = {
    "VERIFIED",
}


def _text(value: Any) -> str:
    return str(value or "").strip()


def _upper(value: Any) -> str:
    return _text(value).upper()


def _nonempty(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, tuple, set, dict)):
        return bool(value)
    return bool(value)


def _has_any(test: dict, *keys: str) -> bool:
    return any(_nonempty(test.get(key)) for key in keys)


def _has_exchange(test: dict, *keys: str) -> bool:
    return any(_nonempty(test.get(key)) for key in keys)


def _test_type(test: dict) -> str:
    return _text(
        test.get("type")
        or test.get("category")
        or test.get("vulnerability_type")
        or test.get("test_type")
    ).lower()


def _is_bola(test: dict) -> bool:
    value = _test_type(test)

    boundary = _text(
        test.get("security_boundary")
    ).lower()

    return (
        "bola" in value
        or "idor" in value
        or "object-level authorization" in value
        or "object-level authorization" in boundary
        or "cross-account-object-authorization" in value
        or "cross-account" in value and "authorization" in value
    )


def _has_observation(test: dict) -> bool:
    """Require an actual observation, not merely endpoint discovery."""

    return _has_any(
        test,
        "observations",
        "observation",
        "observed",
        "observation_id",
        "observation_ids",
        "signal",
        "signals",
    ) or _has_exchange(
        test,
        "baseline_exchange_id",
        "test_exchange_id",
        "cross_account_exchange_id",
    )


def _has_hypothesis(test: dict) -> bool:
    return _has_any(
        test,
        "hypothesis_id",
        "hypothesis",
        "hypothesis_ids",
    )


def _has_plan(test: dict) -> bool:
    return _has_any(
        test,
        "test_plan_id",
        "test_plan",
        "planned",
        "methodology",
        "strategy",
    )


def _has_baseline(test: dict) -> bool:
    return _has_exchange(
        test,
        "baseline_exchange_id",
    ) or _has_any(
        test,
        "baseline",
        "baseline_status",
        "baseline_observation",
        "baseline_response_sha256",
    )


def _has_control(test: dict) -> bool:
    """Evaluate the control contract appropriate to the test.

    Generic tests require explicit control artifacts.

    BOLA tests can satisfy the control contract through the verifier's
    identity-boundary assertions:
      owner identity verified
      other identity verified
      baseline owner matches
    """

    if _is_bola(test):
        return (
            _has_exchange(
                test,
                "control_exchange_id",
                "identity_control_exchange_id",
                "object_control_exchange_id",
            )
            or _has_any(
                test,
                "controls",
                "control",
                "control_records",
            )
            or (
                test.get("owner_identity_verified") is True
                and test.get("other_identity_verified") is True
                and test.get("baseline_owner_matches") is True
            )
        )

    return _has_exchange(
        test,
        "control_exchange_id",
        "negative_control_exchange_id",
        "positive_control_exchange_id",
        "identity_control_exchange_id",
        "object_control_exchange_id",
    ) or _has_any(
        test,
        "controls",
        "control",
        "control_records",
    )


def _has_mutation(test: dict) -> bool:
    return _has_any(
        test,
        "mutation",
        "mutations",
        "mutation_id",
        "mutation_ids",
        "payload",
        "payloads",
        "mutated_request",
        "mutated_requests",
    ) or _has_exchange(
        test,
        "test_exchange_id",
        "cross_account_exchange_id",
    )


def _has_differential(test: dict) -> bool:
    if _has_any(
        test,
        "differential",
        "diff",
        "differences",
        "differential_id",
        "diff_id",
        "semantic_diff",
    ):
        return True

    if _is_bola(test):
        # The verifier's cross-account comparison is the differential
        # evidence. It is deliberately not inferred from "different status"
        # or any arbitrary response change.
        return (
            _has_exchange(
                test,
                "baseline_exchange_id",
            )
            and _has_exchange(
                test,
                "cross_account_exchange_id",
            )
            and (
                _has_any(
                    test,
                    "baseline_response_sha256",
                    "cross_account_response_sha256",
                    "baseline_owner_matches",
                    "cross_owner_matches",
                    "baseline_sensitive_fields_present",
                    "cross_sensitive_fields_present",
                )
                or _has_exchange(
                    test,
                    "cross_account_exchange_id",
                )
            )
        )

    return False


def _has_reproduction(test: dict) -> bool:
    status = _upper(test.get("reproduction_status"))

    if status in {
        "REPRODUCED",
        "VERIFIED",
        "SUCCESS",
        "PASS",
        "MATCHED",
    }:
        return True

    return _has_any(
        test,
        "reproduction",
        "reproduction_result",
        "reproduction_evidence",
        "repeat_exchange_id",
        "repeat_exchange_ids",
        "reproduction_exchange_id",
        "reproduction_exchange_ids",
    )


def _has_impact(test: dict) -> bool:
    if test.get("impact_proven") is True:
        return True

    if test.get("impact_validated") is True:
        return True

    if _has_any(
        test,
        "impact",
        "impact_contract",
        "impact_evidence",
    ):
        return True

    if _is_bola(test):
        # BOLA impact is a security-boundary contract rather than a generic
        # "impact" field. Presence of the boundary plus concrete affected
        # resource/actor evidence is required.
        return bool(
            _text(test.get("security_boundary"))
            and (
                _has_any(
                    test,
                    "sensitive_fields",
                    "cross_account_exchange_id",
                    "cross_account_status",
                    "cross_owner_matches",
                )
            )
        )

    return False


def _has_evidence(test: dict) -> bool:
    if _has_any(
        test,
        "evidence",
        "evidence_ids",
        "evidence_records",
        "evidence_bundle",
    ):
        return True

    if _is_bola(test):
        # Existing verifier-produced evidence is acceptable as evidence
        # assembly input. A finding_id alone is intentionally insufficient.
        concrete = (
            _has_exchange(
                test,
                "baseline_exchange_id",
                "cross_account_exchange_id",
            )
            and _has_exchange(
                test,
                "repeat_exchange_id",
            )
            and _has_any(
                test,
                "security_boundary",
                "sensitive_fields",
                "finding_id",
            )
        )
        return concrete

    return False


def _scope_allowed(test: dict) -> bool:
    decision = _upper(
        test.get("scope_decision")
        or test.get("scope_status")
        or test.get("authorization_status")
    )

    if decision in {
        "BLOCKED",
        "BLOCKED_BY_POLICY",
        "OUT_OF_SCOPE",
        "DENIED",
        "REJECTED",
        "UNAUTHORIZED",
    }:
        return False

    if test.get("scope_ok") is False:
        return False

    if test.get("authorized") is False:
        return False

    return True


def _decision_state(status: str) -> str:
    if status in TERMINAL_STATUSES:
        return "COMPLETE"

    return "PENDING"


def _verification_contract(test: dict) -> dict[str, bool]:
    """Return evidence gates without making the security verdict.

    The returned values describe whether the evidence required by the
    applicable lifecycle contract is present. The central verifier still
    decides whether a vulnerability is actually VERIFIED.
    """

    return {
        "scope": _scope_allowed(test),
        "observation": _has_observation(test),
        "hypothesis": _has_hypothesis(test),
        "plan": _has_plan(test),
        "baseline": _has_baseline(test),
        "control": _has_control(test),
        "mutation": _has_mutation(test),
        "differential": _has_differential(test),
        "reproduction": _has_reproduction(test),
        "impact": _has_impact(test),
        "evidence": _has_evidence(test),
    }


def build_pipeline(test: dict) -> list[dict[str, str]]:
    """Build the lifecycle ledger.

    Evidence requirements are vulnerability-contract aware.

    This function never promotes a finding and never replaces the central
    verifier.
    """

    if not isinstance(test, dict):
        test = {}

    status = _upper(test.get("status") or "NOT_RUN")

    endpoint_present = _has_any(
        test,
        "endpoint",
        "endpoint_id",
        "url",
    )

    scope_allowed = _scope_allowed(test)
    observation = _has_observation(test)
    hypothesis = _has_hypothesis(test)
    plan = _has_plan(test)
    baseline = _has_baseline(test)
    control = _has_control(test)
    mutation = _has_mutation(test)
    differential = _has_differential(test)
    reproduction = _has_reproduction(test)
    impact = _has_impact(test)
    evidence = _has_evidence(test)

    discovery_state = (
        "COMPLETE"
        if endpoint_present
        else (
            "BLOCKED"
            if status in BLOCKED_STATUSES
            else "UNTESTABLE"
        )
    )

    scope_state = "COMPLETE" if scope_allowed else "BLOCKED"

    observation_state = (
        "COMPLETE"
        if observation
        else (
            "BLOCKED"
            if not scope_allowed
            else "UNTESTABLE"
        )
    )

    hypothesis_state = (
        "COMPLETE"
        if hypothesis
        else (
            "UNTESTABLE"
            if observation
            else "SKIPPED"
        )
    )

    planning_state = (
        "COMPLETE"
        if plan
        else (
            "UNTESTABLE"
            if hypothesis
            else "SKIPPED"
        )
    )

    baseline_state = (
        "COMPLETE"
        if baseline
        else (
            "BLOCKED"
            if not scope_allowed
            else (
                "UNTESTABLE"
                if plan
                else "SKIPPED"
            )
        )
    )

    control_state = (
        "COMPLETE"
        if control
        else (
            "UNTESTABLE"
            if baseline
            else "SKIPPED"
        )
    )

    mutation_state = (
        "COMPLETE"
        if mutation
        else (
            "UNTESTABLE"
            if baseline
            else "SKIPPED"
        )
    )

    differential_state = (
        "COMPLETE"
        if differential
        else (
            "UNTESTABLE"
            if mutation and baseline
            else "SKIPPED"
        )
    )

    reproduction_state = (
        "COMPLETE"
        if reproduction
        else (
            "KILLED"
            if status == "KILLED"
            else (
                "UNTESTABLE"
                if differential
                else "SKIPPED"
            )
        )
    )

    impact_state = (
        "COMPLETE"
        if impact
        else (
            "UNTESTABLE"
            if reproduction
            else "SKIPPED"
        )
    )

    evidence_state = (
        "COMPLETE"
        if evidence
        else (
            "UNTESTABLE"
            if reproduction
            else "SKIPPED"
        )
    )

    contract = _verification_contract(test)

    all_verification_evidence = all(contract.values())

    central_verified = (
        status in VERIFIED_STATUSES
        and _nonempty(test.get("finding_id"))
    )

    verification_state = (
        "COMPLETE"
        if central_verified and all_verification_evidence
        else (
            "BLOCKED"
            if not scope_allowed
            else (
                "UNTESTABLE"
                if not all_verification_evidence
                else "PENDING"
            )
        )
    )

    decision_state = _decision_state(status)

    states = {
        "SCOPE": scope_state,
        "DISCOVERY": discovery_state,
        "OBSERVATION": observation_state,
        "HYPOTHESIS": hypothesis_state,
        "TEST PLANNING": planning_state,
        "BASELINE": baseline_state,
        "CONTROL": control_state,
        "MUTATION": mutation_state,
        "DIFFERENTIAL TEST": differential_state,
        "REPRODUCTION": reproduction_state,
        "IMPACT VALIDATION": impact_state,
        "EVIDENCE ASSEMBLY": evidence_state,
        "VERIFICATION GATE": verification_state,
        "FINDING DECISION": decision_state,
    }

    return [
        {
            "stage": stage,
            "status": states[stage],
        }
        for stage in PIPELINE_STAGES
    ]


def current_stage(test: dict) -> str:
    """Return the furthest legitimately completed stage."""

    ledger = build_pipeline(test)

    for entry in reversed(ledger):
        if entry["status"] == "COMPLETE":
            return entry["stage"]

    return "SCOPE"


def verification_ready(test: dict) -> bool:
    """Return whether lifecycle evidence is complete.

    This does not itself mark a finding VERIFIED.
    """

    contract = _verification_contract(
        test if isinstance(test, dict) else {}
    )

    required = {
        "scope",
        "observation",
        "hypothesis",
        "plan",
        "baseline",
        "control",
        "mutation",
        "differential",
        "reproduction",
        "impact",
        "evidence",
    }

    return required.issubset(
        {
            key
            for key, value in contract.items()
            if value
        }
    )


def pipeline_summary(test: dict) -> dict[str, Any]:
    """Machine-readable lifecycle summary for CLI/dashboard consumers."""

    test = test if isinstance(test, dict) else {}

    ledger = build_pipeline(test)

    completed = [
        entry["stage"]
        for entry in ledger
        if entry["status"] == "COMPLETE"
    ]

    blocked = [
        entry["stage"]
        for entry in ledger
        if entry["status"] == "BLOCKED"
    ]

    untestable = [
        entry["stage"]
        for entry in ledger
        if entry["status"] == "UNTESTABLE"
    ]

    killed = [
        entry["stage"]
        for entry in ledger
        if entry["status"] == "KILLED"
    ]

    contract = _verification_contract(test)

    missing = [
        key
        for key, value in contract.items()
        if not value
    ]

    if not _scope_allowed(test):
        next_action = "Authorization or scope must be resolved."
    elif missing:
        next_action = f"Complete evidence gate: {missing[0]}."
    elif _upper(test.get("status")) == "VERIFIED":
        next_action = "No further lifecycle evidence required."
    elif _upper(test.get("status")) in TERMINAL_STATUSES:
        next_action = "Terminal test state reached."
    else:
        next_action = "Proceed to the next research stage."

    return {
        "version": 2,
        "current_stage": current_stage(test),
        "verification_ready": verification_ready(test),
        "central_verification": (
            "VERIFIED"
            if (
                _upper(test.get("status")) == "VERIFIED"
                and _nonempty(test.get("finding_id"))
            )
            else "NOT_VERIFIED"
        ),
        "decision": _upper(
            test.get("decision")
            or test.get("finding_decision")
            or test.get("verification_decision")
            or test.get("status")
            or "NOT_RUN"
        ),
        "completed_stages": completed,
        "blocked_stages": blocked,
        "untestable_stages": untestable,
        "killed_stages": killed,
        "missing_gates": missing,
        "next_action": next_action,
        "contract": contract,
        "status": _upper(
            test.get("status") or "NOT_RUN"
        ),
        "pipeline": ledger,
    }
