"""Lab contract validation for severity-specific training labs."""

from __future__ import annotations

from typing import Any, Dict, Optional

from ..core.models import STATUS_CANDIDATE, STATUS_VERIFIED

LAB_SEVERITIES = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
}


def expected_lab_severity(test_profile: str) -> Optional[str]:
    """Return the mandatory finding severity for a severity-specific lab."""
    return LAB_SEVERITIES.get(str(test_profile or "").lower().strip())


def validate_finding_severity(
    finding: Any,
    *,
    test_profile: str,
) -> Dict[str, Any]:
    """Validate a verified finding against the active lab severity contract."""
    expected = expected_lab_severity(test_profile)

    if expected is None:
        return {
            "valid": True,
            "enforced": False,
            "expected": None,
            "actual": str(getattr(finding, "severity", "")).lower(),
            "reason": "No severity-specific lab contract is active.",
        }

    actual = str(getattr(finding, "severity", "") or "").lower().strip()

    if actual == expected:
        return {
            "valid": True,
            "enforced": True,
            "expected": expected,
            "actual": actual,
            "reason": "Finding severity matches the active lab contract.",
        }

    return {
        "valid": False,
        "enforced": True,
        "expected": expected,
        "actual": actual,
        "reason": (
            f"Severity mismatch: lab requires {expected.upper()} "
            f"but finding is {actual.upper() or 'UNSPECIFIED'}."
        ),
    }


def validate_verified_findings(ctx: Any) -> int:
    """Prevent severity-mismatched verified findings from finalization."""
    profile = str(
        getattr(getattr(ctx, "config", None), "test_profile", "full") or "full"
    ).lower()

    results = []
    rejected = 0

    for finding in list(getattr(ctx, "findings", [])):
        if getattr(finding, "status", "") != STATUS_VERIFIED:
            continue

        result = validate_finding_severity(
            finding,
            test_profile=profile,
        )
        results.append({
            "finding_id": getattr(finding, "id", ""),
            "category": getattr(finding, "category", ""),
            **result,
        })

        if not result["valid"]:
            finding.status = STATUS_CANDIDATE
            finding.state = STATUS_CANDIDATE
            finding.manual_verification = result["reason"]
            rejected += 1

    ctx.lab_contract_results = results
    return rejected
