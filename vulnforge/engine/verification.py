"""VulnForge verification and proof engine.

Architecture:

    OBSERVATION
        ↓
    HYPOTHESIS
        ↓
    CONTROLLED TEST
        ↓
    BASELINE
        ↓
    CONTROL
        ↓
    DIFFERENTIAL
        ↓
    REPRODUCTION
        ↓
    IMPACT
        ↓
    EVIDENCE
        ↓
    CENTRAL VERIFICATION GATE
        ↓
    VERIFIED / CANDIDATE / UNTESTABLE / KILLED

This module intentionally separates:

    1. test execution
    2. evidence collection
    3. proof evaluation
    4. finding promotion

A scanner signal, heuristic, or single anomalous response can never by
itself become a VERIFIED finding.

The module is designed for explicitly authorized assessments and uses the
shared VulnForge requester so scope, request budgets, rate limits and
emergency-stop controls remain enforced.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence
import hashlib
import json
import math
import time
import uuid

from urllib.parse import urljoin, urlsplit

from ..core.models import (
    EvidenceItem,
    Finding,
    STATUS_VERIFIED,
)


# ============================================================================
# Constants
# ============================================================================

VERIFICATION_VERSION = "2.0"

STATUS_VERIFIED_LOCAL = "VERIFIED"
STATUS_CANDIDATE = "CANDIDATE"
STATUS_UNTESTABLE = "UNTESTABLE"
STATUS_KILLED = "KILLED"
STATUS_INCOMPLETE = "INCOMPLETE"

TERMINAL_VERIFICATION_STATES = {
    STATUS_VERIFIED_LOCAL,
    STATUS_CANDIDATE,
    STATUS_UNTESTABLE,
    STATUS_KILLED,
}

# These are proof properties, not severity levels.
PROOF_PROPERTIES = (
    "scope",
    "baseline",
    "control",
    "differential",
    "reproduction",
    "impact",
)

# Vulnerability-specific contracts.
#
# Important:
# "impact" is deliberately not mandatory for every vulnerability class.
# Some classes prove the security-boundary violation itself through the
# controlled differential. Other classes require an additional impact proof.
VERIFICATION_CONTRACTS: Dict[str, frozenset[str]] = {
    "authorization": frozenset(
        {
            "scope",
            "baseline",
            "identity_separation",
            "protected_resource",
            "differential",
            "reproduction",
            "impact",
        }
    ),
    "bola": frozenset(
        {
            "scope",
            "baseline",
            "identity_separation",
            "protected_resource",
            "differential",
            "reproduction",
            "impact",
        }
    ),
    "cross-account-object-authorization": frozenset(
        {
            "scope",
            "baseline",
            "identity_separation",
            "protected_resource",
            "differential",
            "reproduction",
            "impact",
        }
    ),
    "privilege_escalation": frozenset(
        {
            "scope",
            "baseline",
            "identity_separation",
            "protected_resource",
            "differential",
            "reproduction",
            "role_separation",
        }
    ),
    "open_redirect": frozenset(
        {
            "scope",
            "baseline",
            "control",
            "external_destination",
            "differential",
            "reproduction",
        }
    ),
    "cors": frozenset(
        {
            "scope",
            "baseline",
            "control",
            "origin_differential",
            "reproduction",
            "browser_data_boundary",
        }
    ),
    "sql_injection": frozenset(
        {
            "scope",
            "baseline",
            "control",
            "differential",
            "reproduction",
            "database_specific_evidence",
        }
    ),
    "mass_assignment": frozenset(
        {
            "scope",
            "baseline",
            "control",
            "differential",
            "reproduction",
        }
    ),
}


# ============================================================================
# Data structures
# ============================================================================


@dataclass
class VerificationDecision:
    """Immutable-style result of the central verification gate."""

    status: str
    verified: bool

    reasons: List[str] = field(default_factory=list)
    missing: List[str] = field(default_factory=list)

    evidence: Dict[str, Any] = field(default_factory=dict)

    evidence_ids: List[str] = field(default_factory=list)
    exchange_ids: List[str] = field(default_factory=list)

    confidence: float = 0.0
    confidence_rationale: str = ""

    contract: str = ""
    verifier_version: str = VERIFICATION_VERSION

    @property
    def state(self) -> str:
        return self.status

    @property
    def terminal(self) -> bool:
        return self.status in TERMINAL_VERIFICATION_STATES

    def as_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "verified": self.verified,
            "reasons": list(self.reasons),
            "missing": list(self.missing),
            "evidence": dict(self.evidence),
            "evidence_ids": list(self.evidence_ids),
            "exchange_ids": list(self.exchange_ids),
            "confidence": self.confidence,
            "confidence_rationale": self.confidence_rationale,
            "contract": self.contract,
            "verifier_version": self.verifier_version,
        }


@dataclass(frozen=True)
class EvidenceRequirement:
    """Description of one mandatory verification property."""

    name: str
    description: str
    required: bool = True


@dataclass
class EvidenceBundle:
    """Normalized proof material supplied to the verification gate."""

    vulnerability_type: str

    scope_ok: bool = False
    baseline_ok: bool = False
    control_ok: bool = False
    differential_ok: bool = False
    reproduction_ok: bool = False
    impact_ok: bool = False

    identity_separation: bool = False
    protected_resource: bool = False

    external_destination: bool = False
    origin_differential: bool = False
    browser_data_boundary: bool = False
    database_specific_evidence: bool = False

    evidence_ids: List[str] = field(default_factory=list)
    exchange_ids: List[str] = field(default_factory=list)

    details: Dict[str, Any] = field(default_factory=dict)

    def checks(self) -> Dict[str, bool]:
        return {
            "scope": self.scope_ok,
            "baseline": self.baseline_ok,
            "control": self.control_ok,
            "differential": self.differential_ok,
            "reproduction": self.reproduction_ok,
            "impact": self.impact_ok,
            "identity_separation": self.identity_separation,
            "protected_resource": self.protected_resource,
            "external_destination": self.external_destination,
            "origin_differential": self.origin_differential,
            "browser_data_boundary": self.browser_data_boundary,
            "database_specific_evidence": self.database_specific_evidence,
        }

    def as_dict(self) -> Dict[str, Any]:
        return {
            "vulnerability_type": self.vulnerability_type,
            "checks": self.checks(),
            "evidence_ids": list(self.evidence_ids),
            "exchange_ids": list(self.exchange_ids),
            "details": dict(self.details),
        }


# ============================================================================
# Generic helpers
# ============================================================================


def _safe_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def _sha256_text(value: Any) -> str:
    """Stable hash used for comparison/evidence, not authentication."""
    if value is None:
        value = ""

    if not isinstance(value, str):
        value = str(value)

    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def _parse_json(exchange: Any) -> Optional[Dict[str, Any]]:
    """Parse a JSON object response without throwing verifier errors."""
    try:
        data = json.loads(exchange.response_body)
        return data if isinstance(data, dict) else None
    except (ValueError, TypeError, AttributeError):
        return None


def _response_ok(exchange: Any) -> bool:
    """Successful, complete HTTP exchange suitable for proof."""
    if exchange is None:
        return False

    try:
        if not exchange.ok:
            return False
    except Exception:
        return False

    status = getattr(exchange, "status", None)

    try:
        return status is not None and 200 <= int(status) < 300
    except (TypeError, ValueError):
        return False


def _exchange_id(exchange: Any) -> str:
    return _safe_str(getattr(exchange, "exchange_id", ""))


def _header(exchange: Any, name: str) -> str:
    try:
        value = exchange.header(name)
        return _safe_str(value)
    except Exception:
        return ""


def _same_origin(base_url: str, candidate_url: str) -> bool:
    try:
        base = urlsplit(base_url)
        candidate = urlsplit(candidate_url)

        return (
            base.scheme.lower(),
            (base.hostname or "").lower(),
            base.port,
        ) == (
            candidate.scheme.lower(),
            (candidate.hostname or "").lower(),
            candidate.port,
        )
    except ValueError:
        return False


def _bounded_confidence(value: float) -> float:
    try:
        value = float(value)
    except (TypeError, ValueError):
        return 0.0

    if not math.isfinite(value):
        return 0.0

    return max(0.0, min(1.0, value))


def _collect_exchange_ids(record: Mapping[str, Any]) -> List[str]:
    """Collect exchange identifiers from a test record recursively."""

    found: List[str] = []
    seen: set[str] = set()

    def visit(value: Any, key: str = "") -> None:
        if isinstance(value, Mapping):
            for child_key, child_value in value.items():
                visit(child_value, str(child_key))
            return

        if isinstance(value, (list, tuple)):
            for item in value:
                visit(item, key)
            return

        if not isinstance(value, str):
            return

        normalized_key = key.lower()

        if (
            "exchange_id" in normalized_key
            or normalized_key == "exchange"
        ):
            if value and value not in seen:
                seen.add(value)
                found.append(value)

    visit(record)
    return found


def _collect_evidence_ids(record: Mapping[str, Any]) -> List[str]:
    found: List[str] = []
    seen: set[str] = set()

    for key in (
        "evidence_id",
        "evidence_ids",
        "proof_evidence_id",
        "proof_evidence_ids",
    ):
        value = record.get(key)

        if isinstance(value, str) and value:
            if value not in seen:
                seen.add(value)
                found.append(value)

        elif isinstance(value, (list, tuple)):
            for item in value:
                if isinstance(item, str) and item and item not in seen:
                    seen.add(item)
                    found.append(item)

    return found


# ============================================================================
# Evidence observations
# ============================================================================


def _field_observations(
    obj: Any,
    owner_field: str,
    owner_value: Any,
    sensitive_fields: Sequence[str],
) -> Dict[str, Any]:
    """Evaluate configured ownership and sensitive-field assertions."""

    if not isinstance(obj, dict):
        return {
            "json_object": False,
            "owner_matches": False,
            "sensitive_fields_present": False,
            "present_sensitive_fields": [],
            "missing_sensitive_fields": list(sensitive_fields),
        }

    present = [
        field
        for field in sensitive_fields
        if field in obj
    ]

    missing = [
        field
        for field in sensitive_fields
        if field not in obj
    ]

    return {
        "json_object": True,
        "owner_matches": obj.get(owner_field) == owner_value,
        "sensitive_fields_present": not missing,
        "present_sensitive_fields": present,
        "missing_sensitive_fields": missing,
    }


def _stable_object_projection(
    obj: Optional[Mapping[str, Any]],
    fields: Sequence[str],
) -> Dict[str, Any]:
    """Create a deterministic comparison projection."""

    if not isinstance(obj, Mapping):
        return {}

    return {
        field: obj.get(field)
        for field in fields
    }


def _projection_equal(
    left: Optional[Mapping[str, Any]],
    right: Optional[Mapping[str, Any]],
    fields: Sequence[str],
) -> bool:
    return (
        bool(fields)
        and _stable_object_projection(left, fields)
        == _stable_object_projection(right, fields)
    )


# ============================================================================
# Verification contracts
# ============================================================================


def verification_requirements(
    vulnerability_type: str,
) -> List[EvidenceRequirement]:
    """Return the proof requirements for a vulnerability class."""

    normalized = _safe_str(vulnerability_type).lower().strip()

    required = VERIFICATION_CONTRACTS.get(
        normalized,
        frozenset(
            {
                "scope",
                "baseline",
                "control",
                "differential",
                "reproduction",
            }
        ),
    )

    descriptions = {
        "scope": "The tested request remained inside the authorized target scope.",
        "baseline": "A valid baseline response established normal application behavior.",
        "control": "A negative/benign control established that the observed behavior is test-specific.",
        "differential": "The tested condition differs from the baseline/control in the claimed security-relevant property.",
        "reproduction": "The behavior was reproduced consistently using the same controlled test.",
        "impact": "The claimed security impact was directly demonstrated or otherwise explicitly validated.",
        "identity_separation": "The owner and non-owner authentication contexts were independently verified.",
        "protected_resource": "The response contains the configured owner-bound/protected resource.",
        "external_destination": "The redirect behavior resolves to the researcher-controlled external validation destination.",
        "origin_differential": "CORS behavior changes materially based on the supplied Origin.",
        "browser_data_boundary": "The CORS behavior was shown to cross a browser-readable data boundary.",
        "database_specific_evidence": "The response provides repeatable database-specific evidence rather than generic parser errors.",
        "mass_assignment_property": (
            "The tested request contains an explicitly approved "
            "security-sensitive writable property."
        ),
    }

    return [
        EvidenceRequirement(
            name=name,
            description=descriptions.get(
                name,
                f"Required proof property: {name}",
            ),
        )
        for name in sorted(required)
    ]


def evaluate_verification_contract(
    *,
    vulnerability_type: str = "generic",
    scope_ok: bool,
    baseline_ok: bool,
    control_ok: bool = False,
    differential_ok: bool = False,
    reproduction_ok: bool = False,
    impact_ok: bool = False,
    required: Optional[Iterable[str]] = None,
    evidence: Optional[Dict[str, Any]] = None,
    evidence_ids: Optional[Iterable[str]] = None,
    exchange_ids: Optional[Iterable[str]] = None,
    confidence: Optional[float] = None,
) -> VerificationDecision:
    """Central VulnForge verification gate.

    No vulnerability module should directly decide that a finding is
    VERIFIED without passing through this function.

    `required` can override the vulnerability-specific contract when a
    module has a more precise proof definition.
    """

    normalized_type = _safe_str(vulnerability_type).lower().strip()

    if required is None:
        contract = VERIFICATION_CONTRACTS.get(
            normalized_type,
            frozenset(
                {
                    "scope",
                    "baseline",
                    "control",
                    "differential",
                    "reproduction",
                }
            ),
        )
    else:
        contract = frozenset(str(item) for item in required)

    checks: Dict[str, bool] = {
        "scope": bool(scope_ok),
        "baseline": bool(baseline_ok),
        "control": bool(control_ok),
        "differential": bool(differential_ok),
        "reproduction": bool(reproduction_ok),
        "impact": bool(impact_ok),
    }

    evidence = dict(evidence or {})

    reasons: List[str] = []
    missing: List[str] = []

    for requirement in sorted(contract):
        passed = bool(checks.get(requirement, evidence.get(requirement, False)))

        if passed:
            reasons.append(f"{requirement}: PASS")
        else:
            missing.append(requirement)
            reasons.append(f"{requirement}: FAIL")

    evidence_ids_list = [
        str(value)
        for value in (evidence_ids or [])
        if value
    ]

    exchange_ids_list = [
        str(value)
        for value in (exchange_ids or [])
        if value
    ]

    # Scope failure is fundamentally different from incomplete proof.
    if not scope_ok:
        return VerificationDecision(
            status=STATUS_UNTESTABLE,
            verified=False,
            reasons=reasons,
            missing=missing or ["scope"],
            evidence=evidence,
            evidence_ids=evidence_ids_list,
            exchange_ids=exchange_ids_list,
            confidence=0.0,
            confidence_rationale=(
                "Verification stopped because the tested request did not "
                "satisfy the authorization/scope requirement."
            ),
            contract=normalized_type,
        )

    # A valid baseline is necessary before interpreting a mutation.
    if "baseline" in contract and not baseline_ok:
        return VerificationDecision(
            status=STATUS_UNTESTABLE,
            verified=False,
            reasons=reasons,
            missing=missing or ["baseline"],
            evidence=evidence,
            evidence_ids=evidence_ids_list,
            exchange_ids=exchange_ids_list,
            confidence=0.0,
            confidence_rationale=(
                "No valid baseline was established; the observed response "
                "cannot safely be interpreted as a vulnerability proof."
            ),
            contract=normalized_type,
        )

    if missing:
        # Never manufacture confidence for incomplete proof.
        partial = 0.0

        if contract:
            passed_count = len(contract) - len(missing)
            partial = _bounded_confidence(
                passed_count / len(contract)
            )

        return VerificationDecision(
            status=STATUS_CANDIDATE,
            verified=False,
            reasons=reasons,
            missing=missing,
            evidence=evidence,
            evidence_ids=evidence_ids_list,
            exchange_ids=exchange_ids_list,
            confidence=partial,
            confidence_rationale=(
                "Verification contract is incomplete. The result remains "
                "a candidate and cannot be promoted to VERIFIED."
            ),
            contract=normalized_type,
        )

    # A caller-supplied confidence is advisory only. A complete contract
    # receives a bounded score, never > 1.
    final_confidence = (
        _bounded_confidence(confidence)
        if confidence is not None
        else 1.0
    )

    # Verified evidence should normally have traceability.
    # We deliberately do not make evidence IDs mandatory here because some
    # legacy modules create EvidenceItem objects before persistence assigns
    # normalized evidence identifiers. The finding gate below handles the
    # stronger persistence-time requirement.
    return VerificationDecision(
        status=STATUS_VERIFIED_LOCAL,
        verified=True,
        reasons=reasons,
        missing=[],
        evidence=evidence,
        evidence_ids=evidence_ids_list,
        exchange_ids=exchange_ids_list,
        confidence=final_confidence,
        confidence_rationale=(
            "All mandatory verification-contract requirements passed."
        ),
        contract=normalized_type,
    )


# ============================================================================
# Evidence gate helpers
# ============================================================================


def _decision_evidence_item(
    decision: VerificationDecision,
) -> EvidenceItem:
    """Convert gate output into reportable evidence."""

    return EvidenceItem(
        description=(
            "Central VulnForge verification gate result: "
            f"{decision.status}."
        ),
        request_summary=(
            f"Verifier contract: {decision.contract or 'generic'}"
        ),
        response_summary=(
            "; ".join(decision.reasons)
        ),
        detail={
            "verification_version": decision.verifier_version,
            "status": decision.status,
            "verified": decision.verified,
            "missing": decision.missing,
            "confidence": decision.confidence,
            "confidence_rationale": decision.confidence_rationale,
            "evidence_ids": decision.evidence_ids,
            "exchange_ids": decision.exchange_ids,
            "contract": decision.contract,
            "evidence": decision.evidence,
        },
    )


def append_verified_finding(
    ctx: Any,
    finding: Finding,
    decision: VerificationDecision,
) -> bool:
    """Final promotion gate for verified findings.

    This is intentionally strict:

        candidate → gate → verified finding

    A module calling this with an incomplete decision cannot promote the
    finding.
    """

    if not decision.verified:
        return False

    if decision.status != STATUS_VERIFIED_LOCAL:
        return False

    if not getattr(finding, "evidence", None):
        finding.evidence = []

    # Always attach the central gate decision.
    finding.evidence.append(
        _decision_evidence_item(decision)
    )

    finding.status = STATUS_VERIFIED
    finding.state = STATUS_VERIFIED
    finding.confidence = _bounded_confidence(
        decision.confidence
    )

    finding.id = (
        getattr(finding, "id", None)
        or "VF-" + uuid.uuid4().hex[:12]
    )

    ctx.findings.append(finding)

    return True


# ============================================================================
# Authorization specification expansion
# ============================================================================


def expand_authorization_specs(auth_data: Any) -> List[Dict[str, Any]]:
    """Expand multi-role `other_identities` into explicit two-identity specs.

    Example:

        other_identities:
            - user
            - manager
            - support

    becomes one independent verification specification per identity.
    """

    raw_specs = (
        auth_data.get("authorization_tests", [])
        if isinstance(auth_data, dict)
        else []
    )

    expanded: List[Dict[str, Any]] = []

    for spec in raw_specs:
        if not isinstance(spec, dict):
            continue

        # P3.2c: explicit object x identity authorization matrix.
        #
        # Each object becomes an independent authorization specification
        # for every declared identity.  The existing executor/planner can
        # therefore continue to operate on one two-identity cell at a time.
        objects = spec.get("objects")
        if isinstance(objects, list) and objects:
            matrix_identities = spec.get("identities")
            if not isinstance(matrix_identities, list) or not matrix_identities:
                matrix_identities = spec.get("other_identities")

            if not isinstance(matrix_identities, list):
                matrix_identities = []

            expected_map = spec.get("expected")
            if not isinstance(expected_map, dict):
                expected_map = {}

            for obj in objects:
                if not isinstance(obj, dict):
                    continue

                object_name = str(
                    obj.get("name")
                    or obj.get("id")
                    or obj.get("url")
                    or ""
                )
                object_url = str(
                    obj.get("url")
                    or spec.get("url")
                    or ""
                )
                object_owner = str(
                    obj.get("owner")
                    or spec.get("owner_value")
                    or ""
                )

                object_expected = obj.get("expected")
                if not isinstance(object_expected, dict):
                    object_expected = expected_map

                for identity_name in matrix_identities:
                    identity_str = str(identity_name)

                    item = dict(spec)
                    item.update(obj)

                    item["url"] = object_url
                    item["owner_identity"] = str(
                        spec.get("owner_identity", "")
                    )
                    item["other_identity"] = identity_str

                    if object_owner:
                        item["owner_value"] = object_owner

                    expected_decision = object_expected.get(
                        identity_str,
                        spec.get("expected_decision", "DENY"),
                    )
                    item["expected_decision"] = str(
                        expected_decision
                    ).upper()

                    assertion = dict(
                        spec.get("identity_assertion") or {}
                    )

                    other_values = (
                        assertion.get("other_values")
                        if isinstance(
                            assertion.get("other_values"),
                            dict,
                        )
                        else {}
                    )

                    # Resolve the identity that actually owns this
                    # specific matrix object. The parent owner_identity is
                    # only the default for the original object owner.
                    #
                    # Example:
                    #   alice -> owner
                    #   bob   -> user
                    #   admin -> admin
                    #   support -> support
                    configured_owner_identity = str(
                        spec.get("owner_identity", "")
                    )

                    configured_owner_value = str(
                        assertion.get("owner_value", "")
                    )

                    object_owner_identity = (
                        configured_owner_identity
                    )

                    if object_owner:
                        # Explicit parent-owner assertion.
                        if (
                            configured_owner_value
                            and object_owner
                            == configured_owner_value
                        ):
                            object_owner_identity = (
                                configured_owner_identity
                            )

                        # Matrix identity mapping.
                        else:
                            matching_identities = [
                                str(identity)
                                for identity, value in other_values.items()
                                if str(value) == object_owner
                            ]

                            if len(matching_identities) == 1:
                                object_owner_identity = (
                                    matching_identities[0]
                                )
                            elif len(matching_identities) > 1:
                                raise ValueError(
                                    "authorization matrix object owner "
                                    f"{object_owner!r} maps to multiple "
                                    "identities: "
                                    f"{matching_identities!r}"
                                )
                            elif not configured_owner_value:
                                # Backward-compatible legacy matrix:
                                # when no explicit owner assertion exists,
                                # the configured owner_identity remains the
                                # authoritative baseline identity.
                                object_owner_identity = (
                                    configured_owner_identity
                                )
                            else:
                                raise ValueError(
                                    "authorization matrix object owner "
                                    f"{object_owner!r} does not map to a "
                                    "configured identity"
                                )

                    role_assertion = dict(assertion)

                    # The assertion must describe the actual object owner,
                    # not the parent authorization spec's owner.
                    role_assertion["owner_value"] = (
                        object_owner
                        or configured_owner_value
                    )

                    role_assertion["other_value"] = str(
                        other_values.get(
                            identity_str,
                            identity_str,
                        )
                    )

                    item["owner_identity"] = (
                        object_owner_identity
                    )
                    item["identity_assertion"] = role_assertion

                    item["authorization_matrix"] = {
                        "object_name": object_name,
                        "owner_identity": object_owner_identity,
                        "other_identity": identity_str,
                        "expected_decision": str(
                            expected_decision
                        ).upper(),
                    }

                    expanded.append(item)

            # Matrix specs are fully expanded above; do not also process
            # them through the legacy identity expansion path.
            continue

        # P3.2c: `identities` is the preferred multi-identity form.
        # `other_identities` remains supported for backward compatibility.
        others = spec.get("identities")

        if not isinstance(others, list) or not others:
            others = spec.get("other_identities")

        if isinstance(others, list) and others:
            assertion = dict(
                spec.get("identity_assertion") or {}
            )

            other_values = (
                assertion.get("other_values")
                if isinstance(
                    assertion.get("other_values"),
                    dict,
                )
                else {}
            )

            for role_name in others:
                role_str = str(role_name)

                role_assertion = dict(assertion)

                role_assertion["other_value"] = str(
                    other_values.get(
                        role_str,
                        assertion.get(
                            "other_value",
                            role_str,
                        ),
                    )
                )

                item = dict(spec)
                item["other_identity"] = role_str
                item["identity_assertion"] = role_assertion

                # Keep the executor two-identity based while making the
                # generated matrix relationship explicit.
                item["authorization_matrix"] = {
                    "owner_identity": str(
                        spec.get("owner_identity", "")
                    ),
                    "other_identity": role_str,
                }

                expanded.append(item)

        else:
            expanded.append(spec)

    return expanded


# ============================================================================
# Phase 3 identity resolution
# ============================================================================



def _evaluate_authorization_decision(
    *,
    expected_decision: str,
    access_observed: bool,
    response_status: Optional[int],
) -> Dict[str, Any]:
    """Evaluate an observed authorization decision against policy.

    This is the single decision point for authorization matrix semantics.

    DENY + access  -> boundary violation
    DENY + denied  -> expected behavior
    ALLOW + access -> expected behavior
    ALLOW + denied -> policy mismatch

    A policy mismatch is deliberately not treated as a vulnerability.
    """

    expected = str(expected_decision or "DENY").upper()

    if expected not in {"ALLOW", "DENY"}:
        expected = "DENY"

    observed = "ALLOW" if access_observed else "DENY"

    decision_matches = (
        expected == observed
    )

    boundary_violation = (
        expected == "DENY"
        and observed == "ALLOW"
    )

    if boundary_violation:
        classification = "BOUNDARY_VIOLATION"
    elif decision_matches:
        classification = "EXPECTED"
    else:
        classification = "POLICY_MISMATCH"

    return {
        "expected_decision": expected,
        "observed_decision": observed,
        "decision_matches": decision_matches,
        "boundary_violation": boundary_violation,
        "classification": classification,
        "response_status": response_status,
    }



def _resolve_authorization_identity_headers(
    ctx: Any,
    identity_name: str,
) -> Dict[str, str]:
    """
    Resolve an authorization-test identity through the Phase 3 identity
    manager when available.

    The resolver fails closed for unknown or malformed identities.

    Runtime identity headers are copied before use so the authorization
    executor cannot accidentally mutate the registered Identity object.

    Backward compatibility is preserved for existing auth_data-based
    authorization configurations.
    """

    identity_name = str(identity_name).strip()

    if not identity_name:
        raise ValueError(
            "authorization test identity name is required"
        )

    # ------------------------------------------------------------------
    # Phase 3 IdentityManager path
    # ------------------------------------------------------------------

    manager = getattr(
        ctx,
        "identity_manager",
        None,
    )

    if manager is not None:
        try:
            identity = manager.get(
                identity_name
            )
        except Exception as exc:
            raise ValueError(
                f"authorization test identity "
                f"{identity_name!r} is not registered"
            ) from exc

        headers = getattr(
            identity,
            "headers",
            None,
        )

        if not isinstance(headers, dict):
            raise ValueError(
                f"authorization test identity "
                f"{identity_name!r} has invalid headers"
            )

        return {
            str(key): str(value)
            for key, value in headers.items()
        }

    # ------------------------------------------------------------------
    # Legacy auth_data compatibility path
    # ------------------------------------------------------------------

    auth_data = getattr(
        ctx.config,
        "auth_data",
        {},
    )

    identities = (
        auth_data.get(
            "identities",
            {},
        )
        if isinstance(auth_data, dict)
        else {}
    )

    if not isinstance(identities, dict):
        raise ValueError(
            "auth_data.identities must be a mapping"
        )

    try:
        identity = identities[
            identity_name
        ]
    except KeyError as exc:
        raise ValueError(
            f"authorization test identity "
            f"{identity_name!r} is not configured"
        ) from exc

    if not isinstance(identity, dict):
        raise ValueError(
            f"authorization test identity "
            f"{identity_name!r} has invalid configuration"
        )

    headers = identity.get(
        "headers",
        {},
    )

    if not isinstance(headers, dict):
        raise ValueError(
            f"authorization test identity "
            f"{identity_name!r} has invalid headers"
        )

    return {
        str(key): str(value)
        for key, value in headers.items()
    }


# ============================================================================
# Authorization test execution
# ============================================================================


async def execute_authorization_tests(ctx: Any) -> None:
    """Perform explicitly configured, read-only authorization comparisons.

    The execution phase does NOT create findings.

    It records:

        owner baseline
        non-owner control/test
        repeated non-owner reproduction

    The verification phase decides whether the security property is proven.
    """

    if not ctx.test_plan or ctx.stopped:
        return

    from ..core.profiles import get_profile

    profile = get_profile(
        ctx.config.profile_name
    )

    if not profile.allows_active:
        for planned in ctx.test_plan:
            planned.status = "BLOCKED"

        ctx.emit(
            "stage",
            "Authorization tests blocked: selected profile is observation-only",
        )
        return

    specs = getattr(
        ctx,
        "_authorization_test_specs",
        [],
    )

    executed_test_ids = {
        record.get("test_id")
        for record in getattr(ctx, "tests", [])
    }

    for spec in specs:
        if ctx.stopped:
            break

        # Match the planned test to an authorization test explicitly.
        # Do not depend on the ordering of unrelated CORS, redirect, or
        # SQLi plans in the shared test plan.
        authorization_hypothesis_ids = {
            str(h.hypothesis_id)
            for h in getattr(ctx, "hypotheses", [])
            if getattr(h, "category", "") == "object-level-authorization"
        }

        planned = next(
            (
                item
                for item in ctx.test_plan
                if item.status == "PLANNED"
                and item.test_id not in executed_test_ids
                and item.test_type == "cross-account-object-authorization"
                and str(item.hypothesis_id) in authorization_hypothesis_ids
            ),
            None,
        )

        if planned is None:
            break

        record: Dict[str, Any] = {
            "test_id": planned.test_id,
            "hypothesis_id": planned.hypothesis_id,
            "type": planned.test_type,
            "status": STATUS_INCOMPLETE,
            "endpoint": "",
            "started_at": time.time(),
            "verification_method": (
                "Repeated read-only identity comparison"
            ),
            "verification_version": VERIFICATION_VERSION,
        }

        # Record the beginning of the real authorization execution.
        # This is an immutable lifecycle event; final test state is still
        # reconciled through save_scan().
        ctx.emit(
            "test-start",
            f"Authorization test started: {planned.test_id}",
            test_id=planned.test_id,
            hypothesis_id=planned.hypothesis_id,
            test_type=planned.test_type,
            status="RUNNING",
        )

        try:
            url = urljoin(
                ctx.config.target,
                spec["url"],
            )

            if not _same_origin(
                ctx.config.target,
                url,
            ):
                raise ValueError(
                    "authorization test URL must be same-origin "
                    "as the scan target"
                )

            owner_name = str(
                spec["owner_identity"]
            )
            other_name = str(
                spec["other_identity"]
            )

            owner_headers = _resolve_authorization_identity_headers(
                ctx,
                owner_name,
            )

            other_headers = _resolve_authorization_identity_headers(
                ctx,
                other_name,
            )

            owner_authentication_context_id = (
                _resolve_authorization_identity_context_id(
                    ctx,
                    owner_name,
                )
            )

            other_authentication_context_id = (
                _resolve_authorization_identity_context_id(
                    ctx,
                    other_name,
                )
            )

            owner_field = str(
                spec["owner_field"]
            )

            # Matrix-expanded authorization specs carry the owner value
            # for the specific object under test. Never fall back to the
            # parent authorization spec's owner when an object-specific
            # value is present.
            owner_value = spec.get("owner_value")

            if owner_value is None:
                raise ValueError(
                    "authorization test spec is missing object-specific "
                    "owner_value"
                )

            sensitive = [
                str(value)
                for value in spec.get(
                    "sensitive_fields",
                    [],
                )
            ]

            if not sensitive:
                raise ValueError(
                    "at least one sensitive_fields entry is required"
                )

            assertion = spec["identity_assertion"]

            identity_header = str(
                assertion["header"]
            )

            if not identity_header:
                raise ValueError(
                    "identity assertion response header is required"
                )

            # ------------------------------------------------------------
            # Authentication-boundary validation
            # ------------------------------------------------------------
            #
            # Normal authorization comparisons must use distinct
            # authentication contexts.  The exception is an explicit
            # owner-self-access ALLOW control, where the tested identity
            # is also the owner of the object.
            configured_other_value = str(
                assertion.get(
                    "other_value",
                    other_name,
                )
            )

            expected_decision = str(
                spec.get(
                    "expected_decision",
                    "DENY",
                )
            ).upper()

            is_owner_self_access = (
                expected_decision == "ALLOW"
                and str(owner_value)
                == configured_other_value
            )

            if (
                owner_authentication_context_id
                and other_authentication_context_id
                and (
                    owner_authentication_context_id
                    == other_authentication_context_id
                )
                and not is_owner_self_access
            ):
                raise ValueError(
                    "authorization identities must use distinct "
                    "authentication contexts"
                )

            record["endpoint"] = url

            # Preserve the expanded matrix cell in the execution evidence.
            # This makes every authorization test traceable to:
            #   object -> owner identity -> tested identity -> policy decision
            matrix = spec.get("authorization_matrix")
            if isinstance(matrix, dict):
                matrix_record = dict(matrix)
                matrix_record["target_object"] = url
                record["authorization_matrix"] = matrix_record

            # ----------------------------------------------------------------
            # Baseline
            # ----------------------------------------------------------------

            baseline = await ctx.requester.send(
                "GET",
                url,
                headers={
                    str(k): str(v)
                    for k, v in owner_headers.items()
                },
                module="authorization-test-baseline",
                authentication_context_id=owner_authentication_context_id,
            )

            # ------------------------------------------------------------
            # Negative authorization control
            # ------------------------------------------------------------
            negative_control = spec.get("negative_control")
            negative_control_exchange = None

            if isinstance(negative_control, dict):
                negative_url = str(
                    negative_control.get("url", "")
                ).strip()

                if negative_url:
                    negative_url = urljoin(
                        ctx.config.target,
                        negative_url,
                    )

                    if not _same_origin(
                        ctx.config.target,
                        negative_url,
                    ):
                        raise ValueError(
                            "negative authorization control URL must be "
                            "same-origin as the scan target"
                        )

                    negative_control_exchange = await ctx.requester.send(
                        "GET",
                        negative_url,
                        headers={
                            str(k): str(v)
                            for k, v in other_headers.items()
                        },
                        module="authorization-test-negative-control",
                        authentication_context_id=other_authentication_context_id,
                    )

            # ----------------------------------------------------------------
            # Cross-account test/control
            # ----------------------------------------------------------------

            cross1 = await ctx.requester.send(
                "GET",
                url,
                headers={
                    str(k): str(v)
                    for k, v in other_headers.items()
                },
                module="authorization-test-cross-account",
                authentication_context_id=other_authentication_context_id,
            )

            # ----------------------------------------------------------------
            # Reproduction
            # ----------------------------------------------------------------

            cross2 = await ctx.requester.send(
                "GET",
                url,
                headers={
                    str(k): str(v)
                    for k, v in other_headers.items()
                },
                module="authorization-test-repeat",
                authentication_context_id=other_authentication_context_id,
            )

            # ----------------------------------------------------------------
            # Parse responses
            # ----------------------------------------------------------------

            baseline_data = _parse_json(baseline)
            cross_data = _parse_json(cross1)
            repeat_data = _parse_json(cross2)

            # ----------------------------------------------------------------
            # Identity assertions
            # ----------------------------------------------------------------

            owner_identity_verified = (
                _header(
                    baseline,
                    identity_header,
                )
                == str(
                    assertion["owner_value"]
                )
            )

            other_identity_verified = (
                _header(
                    cross1,
                    identity_header,
                )
                == str(
                    assertion["other_value"]
                )
                and
                _header(
                    cross2,
                    identity_header,
                )
                == str(
                    assertion["other_value"]
                )
            )

            # ----------------------------------------------------------------
            # Resource assertions
            # ----------------------------------------------------------------

            baseline_observation = _field_observations(
                baseline_data,
                owner_field,
                owner_value,
                sensitive,
            )

            cross_observation = _field_observations(
                cross_data,
                owner_field,
                owner_value,
                sensitive,
            )

            repeat_observation = _field_observations(
                repeat_data,
                owner_field,
                owner_value,
                sensitive,
            )

            # ----------------------------------------------------------------
            # Reproduction stability
            # ----------------------------------------------------------------

            stable = (
                cross_data is not None
                and repeat_data is not None
                and _projection_equal(
                    cross_data,
                    repeat_data,
                    [
                        owner_field,
                        *sensitive,
                    ],
                )
            )

            # ----------------------------------------------------------------
            # HTTP validity
            # ----------------------------------------------------------------

            exchanges_ok = all(
                _response_ok(exchange)
                for exchange in (
                    baseline,
                    cross1,
                    cross2,
                )
            )

            # ----------------------------------------------------------------
            # Differential proof
            # ----------------------------------------------------------------
            #
            # The security-relevant differential is not simply
            # "responses differ".
            #
            # The expected proof is:
            #
            # owner identity → owner resource
            # non-owner identity → same owner resource
            #
            # while the authentication identities themselves remain distinct.
            # ----------------------------------------------------------------

            identity_separation = (
                owner_identity_verified
                and other_identity_verified
                and (
                    str(assertion["owner_value"])
                    != str(assertion["other_value"])
                )
            )

            protected_resource = (
                baseline_observation["json_object"]
                and baseline_observation["owner_matches"]
                and baseline_observation[
                    "sensitive_fields_present"
                ]
            )

            unauthorized_resource_access = (
                cross_observation["json_object"]
                and cross_observation["owner_matches"]
                and cross_observation[
                    "sensitive_fields_present"
                ]
            )

            # ----------------------------------------------------------------
            # Centralized authorization decision
            # ----------------------------------------------------------------

            expected_decision = str(
                spec.get(
                    "expected_decision",
                    "DENY",
                )
            ).upper()

            authorization_decision = (
                _evaluate_authorization_decision(
                    expected_decision=expected_decision,
                    access_observed=bool(
                        unauthorized_resource_access
                    ),
                    response_status=getattr(
                        cross1,
                        "status",
                        None,
                    ),
                )
            )

            authorization_boundary_violation = (
                authorization_decision[
                    "boundary_violation"
                ]
            )

            authorization_decision_matches = (
                authorization_decision[
                    "decision_matches"
                ]
            )

            authorization_classification = (
                authorization_decision[
                    "classification"
                ]
            )

            differential_ok = (
                identity_separation
                and protected_resource
                and authorization_boundary_violation
            )

            reproduction_ok = (
                exchanges_ok
                and stable
                and repeat_observation["json_object"]
                and repeat_observation[
                    "owner_matches"
                ]
                and repeat_observation[
                    "sensitive_fields_present"
                ]
                and authorization_boundary_violation
            )

            impact_ok = (
                authorization_boundary_violation
                and bool(sensitive)
            )

            # ----------------------------------------------------------------
            # Negative-control evaluation
            # ----------------------------------------------------------------

            negative_control_configured = isinstance(
                spec.get("negative_control"),
                dict,
            )

            negative_control_status = (
                getattr(
                    negative_control_exchange,
                    "status",
                    None,
                )
                if negative_control_exchange is not None
                else None
            )

            negative_control_expected_status = None

            if negative_control_configured:
                negative_control_expected_status = (
                    spec["negative_control"].get(
                        "expected_status",
                        403,
                    )
                )

            negative_control_denied = (
                negative_control_exchange is not None
                and negative_control_expected_status is not None
                and negative_control_status
                == negative_control_expected_status
            )

            negative_control_body = (
                getattr(
                    negative_control_exchange,
                    "response_body",
                    "",
                )
                if negative_control_exchange is not None
                else ""
            )

            negative_control_resource_absent = (
                negative_control_exchange is not None
                and str(owner_value) not in negative_control_body
                and "email" not in negative_control_body.lower()
            )

            negative_control_ok = (
                not negative_control_configured
                or (
                    negative_control_denied
                    and negative_control_resource_absent
                )
            )

            # ----------------------------------------------------------------
            # Evidence identifiers
            # ----------------------------------------------------------------

            exchange_ids = [
                _exchange_id(baseline),
                _exchange_id(cross1),
                _exchange_id(cross2),
                _exchange_id(negative_control_exchange),
            ]

            exchange_ids = [
                value
                for value in exchange_ids
                if value
            ]

            # ----------------------------------------------------------------
            # Record complete test state
            # ----------------------------------------------------------------

            record.update(
                {
                    "status": (
                        "EXECUTED"
                        if exchanges_ok
                        else "INCOMPLETE"
                    ),
                    "reproduction_status": (
                        "REPRODUCED"
                        if reproduction_ok
                        else "CANDIDATE"
                    ),
                    "baseline_exchange_id": _exchange_id(
                        baseline
                    ),
                    "cross_account_exchange_id": _exchange_id(
                        cross1
                    ),
                    "repeat_exchange_id": _exchange_id(
                        cross2
                    ),
                    "exchange_ids": exchange_ids,
                    "baseline_status": getattr(
                        baseline,
                        "status",
                        None,
                    ),
                    "cross_account_status": getattr(
                        cross1,
                        "status",
                        None,
                    ),
                    "repeat_status": getattr(
                        cross2,
                        "status",
                        None,
                    ),
                    "expected_owner_field": owner_field,
                    "identity_assertion_header": identity_header,
                    "owner_identity_verified": owner_identity_verified,
                    "other_identity_verified": other_identity_verified,
                    "identity_separation": identity_separation,
                    "authorization_decision": authorization_decision,
                    "authorization_decision_matches": (
                        authorization_decision_matches
                    ),
                    "authorization_classification": (
                        authorization_classification
                    ),
                    "authorization_boundary_violation": (
                        authorization_boundary_violation
                    ),
                    "protected_resource": protected_resource,
                    "baseline_owner_matches": baseline_observation[
                        "owner_matches"
                    ],
                    "baseline_sensitive_fields_present": baseline_observation[
                        "sensitive_fields_present"
                    ],
                    "cross_owner_matches": cross_observation[
                        "owner_matches"
                    ],
                    "cross_sensitive_fields_present": cross_observation[
                        "sensitive_fields_present"
                    ],
                    "repeat_owner_matches": repeat_observation[
                        "owner_matches"
                    ],
                    "repeat_sensitive_fields_present": repeat_observation[
                        "sensitive_fields_present"
                    ],
                    "repeat_response_stable": stable,
                    "json_responses_valid": all(
                        observation["json_object"]
                        for observation in (
                            baseline_observation,
                            cross_observation,
                            repeat_observation,
                        )
                    ),
                    "differential_ok": differential_ok,
                    "reproduction_ok": reproduction_ok,
                    "impact_ok": impact_ok,
                    "sensitive_fields": sensitive,
                    "baseline_response_sha256": _sha256_text(
                        getattr(
                            baseline,
                            "response_body",
                            "",
                        )
                    ),
                    "cross_account_response_sha256": _sha256_text(
                        getattr(
                            cross1,
                            "response_body",
                            "",
                        )
                    ),
                    "repeat_response_sha256": _sha256_text(
                        getattr(
                            cross2,
                            "response_body",
                            "",
                        )
                    ),
                    "security_boundary": (
                        "object-level authorization / "
                        "cross-account ownership"
                    ),

                    # P3.2c authorization matrix evidence.
                    # Keep the existing identity labels for compatibility,
                    # while exposing the complete matrix relationship.
                    "authorization_matrix": {
                        "owner_identity": owner_name,
                        "other_identity": other_name,
                        "owner_authentication_context_id": (
                            owner_authentication_context_id
                        ),
                        "other_authentication_context_id": (
                            other_authentication_context_id
                        ),
                        "target_object": url,
                        "expected_decision": str(
                            spec.get(
                                "expected_decision",
                                "DENY",
                            )
                        ).upper(),
                        "actual_status": getattr(
                            cross1,
                            "status",
                            None,
                        ),
                    },
                    "owner_identity_label": owner_name,
                    "other_identity_label": other_name,
                    "owner_authentication_context_id": (
                        owner_authentication_context_id
                    ),
                    "other_authentication_context_id": (
                        other_authentication_context_id
                    ),
                    "scope_ok": True,
                    "baseline_ok": _response_ok(
                        baseline
                    )
                    and protected_resource,
                    "control_ok": (
                        identity_separation
                        and _response_ok(cross1)
                    ),
                    "negative_control_configured": (
                        negative_control_configured
                    ),
                    "negative_control_exchange_id": (
                        _exchange_id(negative_control_exchange)
                    ),
                    "negative_control_status": (
                        negative_control_status
                    ),
                    "negative_control_expected_status": (
                        negative_control_expected_status
                    ),
                    "negative_control_denied": (
                        negative_control_denied
                    ),
                    "negative_control_resource_absent": (
                        negative_control_resource_absent
                    ),
                    "negative_control_ok": (
                        negative_control_ok
                    ),
                }
            )

            planned.status = (
                "EXECUTED"
                if exchanges_ok
                else "INCOMPLETE"
            )

            executed_test_ids.add(
                planned.test_id
            )

        except (KeyError, TypeError, ValueError) as exc:
            record["status"] = "NOT_RUN"
            record["reason"] = str(exc)

            planned.status = "BLOCKED"

            ctx.emit(
                "stage",
                f"Authorization test not run: {exc}",
            )

        except Exception as exc:
            # Unexpected verifier errors should not silently become findings.
            record["status"] = "ERROR"
            record["reason"] = (
                f"{type(exc).__name__}: {exc}"
            )

            planned.status = "INCOMPLETE"

            ctx.emit(
                "stage",
                "Authorization verifier error: "
                f"{type(exc).__name__}: {exc}",
            )

        record["finished_at"] = time.time()

        ctx.tests.append(record)

        # Execution is complete, but verification is deliberately separate.
        # A completed test is NOT automatically a confirmed vulnerability.
        ctx.emit(
            "test-complete",
            f"Authorization test completed: {planned.test_id}",
            test_id=record.get("test_id"),
            hypothesis_id=record.get("hypothesis_id"),
            test_type=record.get("type"),
            status=record.get("status"),
            endpoint=record.get("endpoint"),
        )


# ============================================================================
# Authorization verification
# ============================================================================



def _resolve_authorization_identity_context_id(
    ctx: Any,
    identity_name: str,
) -> Optional[str]:
    """Resolve the persistent authentication context for an identity.

    IdentityManager is authoritative when available. Legacy auth_data remains
    supported, but identities without an explicit authentication context do
    not receive a fabricated one.
    """
    manager = getattr(ctx, "identity_manager", None)

    if manager is not None:
        identity = manager.get_optional(identity_name)

        if identity is not None:
            value = getattr(
                identity,
                "authentication_context_id",
                None,
            )

            if value:
                return str(value)

    auth_data = getattr(ctx.config, "auth_data", {}) or {}
    identities = auth_data.get("identities", {}) or {}

    raw = identities.get(identity_name)

    if isinstance(raw, dict):
        value = raw.get("authentication_context_id")

        if value:
            return str(value)

    return None

def verify_authorization_tests(ctx: Any) -> None:
    """Verify authorization tests through the central proof contract.

    This function is intentionally not responsible for merely noticing an
    anomaly. It must prove the declared security property.
    """

    hypotheses = {
        h.hypothesis_id: h
        for h in getattr(
            ctx,
            "hypotheses",
            [],
        )
    }

    for record in getattr(ctx, "tests", []):

        if (
            record.get("type")
            != "cross-account-object-authorization"
        ):
            continue

        if record.get("status") not in (
            "EXECUTED",
            "INCOMPLETE",
            "ERROR",
        ):
            continue

        # --------------------------------------------------------------------
        # Build evidence bundle
        # --------------------------------------------------------------------

        evidence = EvidenceBundle(
            vulnerability_type=(
                "cross-account-object-authorization"
            ),
            scope_ok=bool(
                record.get("scope_ok")
            ),
            baseline_ok=bool(
                record.get("baseline_ok")
            ),
            control_ok=bool(
                record.get("control_ok")
            ),
            differential_ok=bool(
                record.get("differential_ok")
            ),
            reproduction_ok=bool(
                record.get("reproduction_ok")
            ),
            impact_ok=bool(
                record.get("impact_ok")
            ),
            identity_separation=bool(
                record.get("identity_separation")
            ),
            protected_resource=bool(
                record.get("protected_resource")
            ),
            evidence_ids=_collect_evidence_ids(
                record
            ),
            exchange_ids=_collect_exchange_ids(
                record
            ),
            details={
                "test_id": record.get("test_id"),
                "endpoint": record.get("endpoint"),
                "owner_identity": record.get(
                    "owner_identity_label"
                ),
                "other_identity": record.get(
                    "other_identity_label"
                ),
                "owner_field": record.get(
                    "expected_owner_field"
                ),
                "sensitive_fields": record.get(
                    "sensitive_fields",
                    [],
                ),
                "baseline_sha256": record.get(
                    "baseline_response_sha256"
                ),
                "cross_account_sha256": record.get(
                    "cross_account_response_sha256"
                ),
                "repeat_sha256": record.get(
                    "repeat_response_sha256"
                ),
            },
        )

        # --------------------------------------------------------------------
        # Central verification gate
        # --------------------------------------------------------------------

        decision = evaluate_verification_contract(
            vulnerability_type=(
                "cross-account-object-authorization"
            ),
            scope_ok=evidence.scope_ok,
            baseline_ok=evidence.baseline_ok,
            control_ok=evidence.control_ok,
            differential_ok=evidence.differential_ok,
            reproduction_ok=evidence.reproduction_ok,
            impact_ok=evidence.impact_ok,
            evidence={
                **evidence.as_dict(),
                "identity_separation": (
                    evidence.identity_separation
                ),
                "protected_resource": (
                    evidence.protected_resource
                ),
            },
            evidence_ids=evidence.evidence_ids,
            exchange_ids=evidence.exchange_ids,
        )

        # --------------------------------------------------------------------
        # Store verification decision
        # --------------------------------------------------------------------

        record["verification"] = decision.as_dict()
        record["verification_status"] = decision.status
        record["verification_missing"] = list(
            decision.missing
        )
        record["verification_reasons"] = list(
            decision.reasons
        )
        record["verification_confidence"] = (
            decision.confidence
        )
        record["verification_confidence_rationale"] = (
            decision.confidence_rationale
        )

        ctx.emit(
            "verification-result",
            f"Authorization verification: {decision.status}",
            test_id=record.get("test_id"),
            hypothesis_id=record.get("hypothesis_id"),
            status=decision.status,
            verified=bool(decision.verified),
            confidence=decision.confidence,
            missing=list(decision.missing),
            reasons=list(decision.reasons),
        )

        # --------------------------------------------------------------------
        # Update hypothesis lifecycle
        # --------------------------------------------------------------------

        hypothesis = hypotheses.get(
            record.get("hypothesis_id")
        )

        if hypothesis:
            if decision.verified:
                hypothesis.status = "VERIFIED"
            elif decision.status == STATUS_UNTESTABLE:
                hypothesis.status = "BLOCKED"
            elif decision.status == STATUS_KILLED:
                hypothesis.status = "KILLED"
            else:
                hypothesis.status = "DEEPER_TESTING"

        # --------------------------------------------------------------------
        # Candidate/incomplete results never become findings.
        # --------------------------------------------------------------------

        if not decision.verified:
            continue

        # --------------------------------------------------------------------
        # Construct verified finding.
        # --------------------------------------------------------------------

        url = record.get(
            "endpoint",
            "",
        )

        lab_profile = str(
            getattr(getattr(ctx, "config", None), "test_profile", "full")
            or "full"
        ).lower().strip()

        # Lab profiles define the severity contract for the training
        # scenario.  The finding is still created only after the
        # authorization proof contract has independently verified BOLA.
        #
        # Normal/full scans retain the historical medium classification;
        # lab-specific severity is subsequently validated by the
        # LabContractValidationStage.
        finding_severity = (
            lab_profile
            if lab_profile in {"critical", "high", "medium"}
            else "medium"
        )

        finding = Finding(
            title=(
                "Cross-account object authorization failure"
            ),
            category="authorization / BOLA",
            severity=finding_severity,
            description=(
                f"The explicitly configured non-owner identity "
                f"'{record.get('other_identity_label', 'other')}' "
                f"received a repeatable owner-bound object at "
                f"{url}, including the configured sensitive fields."
            ),
            endpoint=url,
            method="GET",
            confidence=decision.confidence,
            status=STATUS_VERIFIED,
            state="VERIFIED",
            evidence=[
                EvidenceItem(
                    description=(
                        "Owner baseline and repeated non-owner reads "
                        "satisfied the declared identity, ownership, "
                        "differential, reproduction and impact assertions."
                    ),
                    request_summary=(
                        f"GET {url} using explicitly configured owner "
                        "and non-owner identities; credentials redacted."
                    ),
                    response_summary=(
                        f"HTTP {record.get('baseline_status')} baseline; "
                        f"HTTP {record.get('cross_account_status')} "
                        f"cross-account; "
                        f"HTTP {record.get('repeat_status')} reproduction."
                    ),
                    detail={
                        **record,
                        "test_id": record.get(
                            "test_id"
                        ),
                        "verification": decision.as_dict(),
                    },
                )
            ],
            remediation=(
                "Enforce object-level authorization on every read "
                "using the authenticated principal. Do not trust "
                "client-supplied object identifiers or object ownership "
                "claims."
            ),
            impact=(
                "Unauthorized cross-account access to the "
                "researcher-configured sensitive response fields."
            ),
            manual_verification=(
                "Confirm that the supplied identities and ownership "
                "mapping are valid, independent, and authorized "
                "research accounts."
            ),
        )

        # --------------------------------------------------------------------
        # FINAL CENTRAL PROMOTION GATE
        # --------------------------------------------------------------------

        promoted = append_verified_finding(
            ctx,
            finding,
            decision,
        )

        if promoted:
            # The test itself must enter VERIFIED state so downstream
            # evidence-validation/finalization stages can establish the
            # finding -> test linkage.
            record["finding_id"] = finding.id
            record["status"] = STATUS_VERIFIED
            record["verification_status"] = STATUS_VERIFIED

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
        else:
            # Defensive invariant: a failed promotion cannot leave the test
            # marked verified.
            record["verification_status"] = (
                STATUS_CANDIDATE
            )
            record["verification_missing"] = [
                "finding_promotion"
            ]


# ============================================================================
# Generic verification helpers for other engines
# ============================================================================


def verify_generic_result(
    *,
    vulnerability_type: str,
    evidence: Mapping[str, Any],
    scope_ok: bool,
    baseline_ok: bool,
    control_ok: bool,
    differential_ok: bool,
    reproduction_ok: bool,
    impact_ok: bool = False,
    evidence_ids: Optional[Iterable[str]] = None,
    exchange_ids: Optional[Iterable[str]] = None,
) -> VerificationDecision:
    """Convenience wrapper for future vulnerability verifiers.

    Modules such as open redirect, CORS and future authorization tests can
    call this rather than implementing their own proof gate.
    """

    return evaluate_verification_contract(
        vulnerability_type=vulnerability_type,
        scope_ok=scope_ok,
        baseline_ok=baseline_ok,
        control_ok=control_ok,
        differential_ok=differential_ok,
        reproduction_ok=reproduction_ok,
        impact_ok=impact_ok,
        evidence=dict(evidence),
        evidence_ids=evidence_ids,
        exchange_ids=exchange_ids,
    )


def verification_contract_for(
    vulnerability_type: str,
) -> frozenset[str]:
    """Return the mandatory proof properties for a vulnerability class."""

    normalized = _safe_str(
        vulnerability_type
    ).lower().strip()

    return VERIFICATION_CONTRACTS.get(
        normalized,
        frozenset(
            {
                "scope",
                "baseline",
                "control",
                "differential",
                "reproduction",
            }
        ),
    )


def result_is_verified(
    decision: Optional[VerificationDecision],
) -> bool:
    """Small compatibility/helper predicate."""

    return bool(
        decision is not None
        and decision.verified
        and decision.status == STATUS_VERIFIED_LOCAL
    )


def mark_candidate(
    record: Dict[str, Any],
    *,
    reason: str,
    missing: Optional[Iterable[str]] = None,
) -> None:
    """Explicitly mark a result as requiring deeper testing."""

    record["status"] = STATUS_CANDIDATE
    record["verification_status"] = STATUS_CANDIDATE
    record["verification_reasons"] = [reason]
    record["verification_missing"] = list(
        missing or []
    )


def mark_untestable(
    record: Dict[str, Any],
    *,
    reason: str,
) -> None:
    """Mark a test as untestable without turning it into a finding."""

    record["status"] = STATUS_UNTESTABLE
    record["verification_status"] = STATUS_UNTESTABLE
    record["verification_reasons"] = [reason]


# ============================================================================
# Backward compatibility
# ============================================================================

# Existing orchestrator imports this symbol.
run_authorization_tests = execute_authorization_tests
