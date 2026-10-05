"""Evidence-first Mass Assignment verification.

Only performs bounded active mutation against explicitly in-scope,
authorized state-changing endpoints.
"""

from __future__ import annotations

import json
import time
from typing import Any, Dict, Optional

from ..core.models import EvidenceItem, Finding
from .verification import (
    EvidenceBundle,
    STATUS_VERIFIED,
    STATUS_VERIFIED_LOCAL,
    append_verified_finding,
    evaluate_verification_contract,
)


SENSITIVE_FIELDS = {
    "role",
    "admin",
    "is_admin",
    "permissions",
    "privilege",
    "owner",
    "owner_id",
    "user_id",
    "account_id",
    "verified",
    "email_verified",
}


def _json_body(value: Dict[str, Any]) -> str:
    return json.dumps(value, separators=(",", ":"))


def _status(exchange: Any) -> int:
    return int(getattr(exchange, "status", 0) or 0)


def _body(exchange: Any) -> str:
    value = getattr(exchange, "body", "")
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value or "")


def _contains_admin_access(exchange: Any) -> bool:
    body = _body(exchange).lower()
    return _status(exchange) in {200, 201, 202} and (
        "admin" in body
        or "administrator" in body
        or "dashboard" in body
    )


def _pick_identity(ctx: Any) -> Optional[Any]:
    manager = getattr(ctx, "identity_manager", None)

    if manager is None:
        return None

    # Prefer the public IdentityManager API.
    if hasattr(manager, "authenticated"):
        identities = manager.authenticated()
    elif hasattr(manager, "all"):
        identities = manager.all()
    else:
        identities = getattr(manager, "identities", None)

    if isinstance(identities, dict):
        identities = identities.values()

    for identity in identities or ():
        if not getattr(identity, "is_active", False):
            continue

        role = str(getattr(identity, "role", "") or "").lower()

        # Mass-assignment testing needs a lower-privilege identity.
        if role and role not in {"admin", "administrator"}:
            return identity

    return None


def _candidate_from_specs(ctx: Any) -> Optional[Dict[str, Any]]:
    """Use only explicitly configured writable test specifications."""

    specs = getattr(ctx, "_mass_assignment_test_specs", None)

    if not specs:
        config = getattr(ctx, "config", None)
        auth_data = getattr(config, "auth_data", {}) or {}
        specs = auth_data.get("mass_assignment_tests")

    if not isinstance(specs, (list, tuple)):
        return None

    for spec in specs:
        if not isinstance(spec, dict):
            continue

        method = str(spec.get("method", "PATCH")).upper()
        url = str(spec.get("url", "")).strip()
        parameter = str(spec.get("parameter", "")).strip()

        if (
            method in {"POST", "PUT", "PATCH"}
            and url
            and parameter.lower() in SENSITIVE_FIELDS
        ):
            return spec

    return None


async def execute_mass_assignment_tests(ctx: Any) -> None:
    """Execute bounded Mass Assignment tests and record raw evidence.

    Execution does not independently finalize findings.  A successful
    security-property differential is recorded as a VERIFIED test candidate;
    downstream verification/finalization remains authoritative.
    """

    requester = getattr(ctx, "requester", None)

    specs = getattr(ctx, "_mass_assignment_test_specs", None) or []

    if requester is None or not specs:
        return

    executed_test_ids = {
        str(record.get("test_id"))
        for record in getattr(ctx, "tests", [])
        if record.get("test_id")
    }

    identity = _pick_identity(ctx)

    if identity is None:
        for spec in specs:
            test_id = str(spec.get("test_id", ""))
            if not test_id or test_id in executed_test_ids:
                continue

            ctx.tests.append({
                "test_id": test_id,
                "hypothesis_id": spec.get("hypothesis_id"),
                "type": "mass-assignment-validation",
                "status": "UNTESTABLE",
                "verification_status": "UNTESTABLE",
                "endpoint": spec.get("url", ""),
                "reason": (
                    "No active lower-privilege researcher identity "
                    "was available."
                ),
                "started_at": time.time(),
                "finished_at": time.time(),
            })
        return

    auth_context_id = getattr(
        identity,
        "authentication_context_id",
        None,
    )

    identity_headers = getattr(identity, "headers", {}) or {}

    for spec in specs:
        test_id = str(spec.get("test_id", ""))

        if not test_id or test_id in executed_test_ids:
            continue

        method = str(spec.get("method", "PATCH")).upper()
        url = str(spec.get("url", "")).strip()
        parameter = str(spec.get("parameter", "")).strip()

        if (
            method not in {"POST", "PUT", "PATCH"}
            or not url
            or parameter.lower() not in SENSITIVE_FIELDS
        ):
            continue

        started_at = time.time()

        record: Dict[str, Any] = {
            "test_id": test_id,
            "hypothesis_id": spec.get("hypothesis_id"),
            "type": "mass-assignment-validation",
            "status": "INCOMPLETE",
            "verification_status": "CANDIDATE",
            "verification_method": (
                "baseline -> benign control -> sensitive property "
                "mutation -> state reproduction"
            ),
            "verification_version": "mass-assignment-v1",
            "endpoint": url,
            "method": method,
            "parameter": parameter,
            "identity": getattr(identity, "label", "unknown"),
            "started_at": started_at,
        }

        ctx.emit(
            "test-start",
            f"Mass-assignment test started: {test_id}",
            test_id=test_id,
            hypothesis_id=spec.get("hypothesis_id"),
            test_type="mass-assignment-validation",
            status="RUNNING",
        )

        try:
            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
            headers.update(identity_headers)

            attack_value = spec.get("attack_value", "admin")

            if parameter.lower() == "is_admin":
                attack_value = True
            elif parameter.lower() in {
                "admin",
                "verified",
                "email_verified",
            }:
                attack_value = True
            elif parameter.lower() == "permissions":
                attack_value = "all"

            state_url = str(spec.get("state_url") or url)

            # -------------------------------------------------------
            # 1. Baseline
            # -------------------------------------------------------
            baseline = await requester.send(
                "GET",
                state_url,
                headers=headers,
                module="mass-assignment",
                authentication_context_id=auth_context_id,
            )

            baseline_status = _status(baseline)
            baseline_body = _body(baseline)

            # -------------------------------------------------------
            # 2. Benign control
            # -------------------------------------------------------
            control_body = dict(spec.get("control_body") or {})
            control_body.setdefault(
                "vulnforge_probe",
                "control",
            )

            control = await requester.send(
                method,
                url,
                headers=headers,
                body=_json_body(control_body),
                module="mass-assignment",
                authentication_context_id=auth_context_id,
            )

            control_status = _status(control)

            # -------------------------------------------------------
            # 3. Sensitive mutation
            # -------------------------------------------------------
            attack_body = dict(spec.get("base_body") or {})
            attack_body[parameter] = attack_value

            attack = await requester.send(
                method,
                url,
                headers=headers,
                body=_json_body(attack_body),
                module="mass-assignment",
                authentication_context_id=auth_context_id,
            )

            attack_status = _status(attack)
            attack_body_text = _body(attack)

            # -------------------------------------------------------
            # 4. Reproduce state
            # -------------------------------------------------------
            reproduction = await requester.send(
                "GET",
                state_url,
                headers=headers,
                module="mass-assignment",
                authentication_context_id=auth_context_id,
            )

            reproduction_status = _status(reproduction)
            reproduction_body = _body(reproduction)

            # -------------------------------------------------------
            # 5. Optional impact
            # -------------------------------------------------------
            impact_ok = False
            impact_status = 0

            impact_url = spec.get("impact_url")

            if impact_url:
                impact = await requester.send(
                    "GET",
                    str(impact_url),
                    headers=headers,
                    module="mass-assignment",
                    authentication_context_id=auth_context_id,
                )

                impact_status = _status(impact)
                impact_ok = _contains_admin_access(impact)

            baseline_ok = baseline_status in {200, 201}
            control_ok = control_status in {200, 201, 202}
            attack_ok = attack_status in {200, 201, 202}

            # A status change by itself is NOT proof.
            #
            # The sensitive property must appear in the reproduced state
            # and the attack response must accept the mutation.
            field_marker = parameter.lower()

            reproduction_lower = reproduction_body.lower()
            attack_lower = attack_body_text.lower()

            property_reflected = (
                f'"{field_marker}"' in reproduction_lower
                or f"'{field_marker}'" in reproduction_lower
                or field_marker in reproduction_lower
            )

            attack_accepted = (
                attack_ok
                and (
                    f'"{field_marker}"' in attack_lower
                    or f"'{field_marker}'" in attack_lower
                    or field_marker in attack_lower
                )
            )

            differential_ok = (
                baseline_ok
                and control_ok
                and attack_ok
                and property_reflected
                and attack_accepted
                and (
                    reproduction_body != baseline_body
                    or attack_body_text != _body(control)
                )
            )

            reproduction_ok = (
                reproduction_status in {200, 201}
                and property_reflected
            )

            record.update({
                "baseline_status": baseline_status,
                "control_status": control_status,
                "attack_status": attack_status,
                "reproduction_status": reproduction_status,
                "impact_status": impact_status,
                "attack_value": attack_value,
                "attack_body": {parameter: attack_value},
                "baseline_ok": baseline_ok,
                "control_ok": control_ok,
                "attack_ok": attack_ok,
                "attack_accepted": attack_accepted,
                "property_reflected": property_reflected,
                "differential_ok": differential_ok,
                "reproduction_ok": reproduction_ok,
                "impact_ok": impact_ok,
                "evidence": {
                    "baseline": {
                        "status": baseline_status,
                    },
                    "control": {
                        "status": control_status,
                    },
                    "mutation": {
                        "status": attack_status,
                        "property": parameter,
                    },
                    "reproduction": {
                        "status": reproduction_status,
                        "property_reflected": property_reflected,
                    },
                    "impact": {
                        "status": impact_status,
                        "verified": impact_ok,
                    },
                },
            })

            # The central verification contract remains authoritative.
            evidence = EvidenceBundle(
                vulnerability_type="mass_assignment",
                scope_ok=True,
                baseline_ok=baseline_ok,
                control_ok=control_ok,
                differential_ok=differential_ok,
                reproduction_ok=reproduction_ok,
                impact_ok=impact_ok,
                evidence_ids=list(
                    spec.get("evidence_ids", []) or []
                ),
                exchange_ids=[],
                details=record,
            )

            decision = evaluate_verification_contract(
                vulnerability_type="mass_assignment",
                scope_ok=True,
                baseline_ok=baseline_ok,
                control_ok=control_ok,
                differential_ok=differential_ok,
                reproduction_ok=reproduction_ok,
                impact_ok=impact_ok,
                evidence=evidence.as_dict(),
                exchange_ids=[],
            )

            record["verification_status"] = decision.status
            record["verification_confidence"] = decision.confidence
            record["verification_missing"] = list(decision.missing)
            record["verification_reasons"] = list(decision.reasons)

            if decision.verified:
                record["status"] = STATUS_VERIFIED
            else:
                record["status"] = "CANDIDATE"

            record["finished_at"] = time.time()
            ctx.tests.append(record)

            ctx.emit(
                "verification-result",
                f"Mass assignment verification: {decision.status}",
                status=decision.status,
                verified=bool(decision.verified),
                confidence=decision.confidence,
                missing=list(decision.missing),
                reasons=list(decision.reasons),
                test_id=test_id,
                hypothesis_id=spec.get("hypothesis_id"),
            )

        except Exception as exc:
            record["status"] = "ERROR"
            record["verification_status"] = "ERROR"
            record["reason"] = f"{type(exc).__name__}: {exc}"
            record["finished_at"] = time.time()
            ctx.tests.append(record)

            ctx.emit(
                "stage",
                f"Mass-assignment test error: {type(exc).__name__}: {exc}",
                test_id=test_id,
            )

        executed_test_ids.add(test_id)

        ctx.emit(
            "test-complete",
            f"Mass-assignment test completed: {test_id}",
            test_id=test_id,
            hypothesis_id=spec.get("hypothesis_id"),
            test_type="mass-assignment-validation",
            status=record.get("status"),
            endpoint=url,
        )


def verify_mass_assignment_tests(ctx: Any) -> None:
    """Promote only proof-backed Mass Assignment tests to findings.

    This stage consumes the test records produced by controlled execution.
    It never performs another network mutation.
    """

    for record in getattr(ctx, "tests", []):
        if record.get("type") != "mass-assignment-validation":
            continue

        if record.get("status") != STATUS_VERIFIED:
            continue

        if record.get("finding_id"):
            continue

        decision = evaluate_verification_contract(
            vulnerability_type="mass_assignment",
            scope_ok=True,
            baseline_ok=bool(record.get("baseline_ok")),
            control_ok=bool(record.get("control_ok")),
            differential_ok=bool(record.get("differential_ok")),
            reproduction_ok=bool(record.get("reproduction_ok")),
            impact_ok=bool(record.get("impact_ok")),
            evidence=dict(record.get("evidence") or {}),
            exchange_ids=[],
        )

        if not decision.verified:
            record["status"] = "CANDIDATE"
            record["verification_status"] = decision.status
            continue

        finding = Finding(
            title="Mass assignment allows privilege modification",
            category="mass assignment",
            severity="HIGH",
            description=(
                "An authenticated lower-privilege identity was able to "
                "submit a security-sensitive property through a writable "
                "API endpoint and the resulting state was reproduced."
            ),
            endpoint=str(record.get("endpoint", "")),
            parameter=str(record.get("parameter", "")),
            method=str(record.get("method", "PATCH")),
            confidence=decision.confidence,
            status=STATUS_VERIFIED,
            state=STATUS_VERIFIED,
            evidence=[
                EvidenceItem(
                    description=(
                        "Baseline, benign control, sensitive-property "
                        "mutation, and state reproduction were executed "
                        "through the authorized VULNFORGE requester."
                    ),
                    request_summary=(
                        f"{record.get('method')} "
                        f"{record.get('endpoint')} with controlled "
                        f"property '{record.get('parameter')}'; "
                        "authentication material redacted."
                    ),
                    response_summary=(
                        f"baseline={record.get('baseline_status')}, "
                        f"control={record.get('control_status')}, "
                        f"attack={record.get('attack_status')}, "
                        f"reproduction={record.get('reproduction_status')}, "
                        f"impact={record.get('impact_status')}."
                    ),
                    detail={
                        "test_id": record.get("test_id"),
                        "hypothesis_id": record.get("hypothesis_id"),
                        "verification": decision.as_dict(),
                        "evidence": record.get("evidence", {}),
                        "differential": {
                            "baseline_ok": record.get("baseline_ok"),
                            "control_ok": record.get("control_ok"),
                            "attack_ok": record.get("attack_ok"),
                            "differential_ok": record.get(
                                "differential_ok"
                            ),
                            "reproduction_ok": record.get(
                                "reproduction_ok"
                            ),
                        },
                    },
                )
            ],
            remediation=(
                "Allow-list writable properties and reject security-sensitive "
                "authorization, ownership, role, and privilege fields from "
                "client-controlled update requests."
            ),
            cwe="CWE-915",
            owasp="A mass assignment / Broken Access Control",
            source_plugin="mass-assignment-verification",
            impact=(
                "A lower-privilege authenticated identity modified a "
                "security-sensitive account property."
            ),
        )

        promoted = append_verified_finding(
            ctx,
            finding,
            decision,
        )

        if promoted:
            record["finding_id"] = finding.id
            record["status"] = STATUS_VERIFIED
            record["verification_status"] = STATUS_VERIFIED
            record["verification_confidence"] = decision.confidence

            planned = next(
                (
                    item
                    for item in getattr(ctx, "test_plan", [])
                    if item.test_id == record.get("test_id")
                ),
                None,
            )

            if planned is not None:
                planned.status = STATUS_VERIFIED

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

