from __future__ import annotations

import time
from typing import Any, Dict
from urllib.parse import urljoin

from .verification import (
    EvidenceItem,
    STATUS_INCOMPLETE,
    STATUS_VERIFIED,
    STATUS_VERIFIED_LOCAL,
    _exchange_id,
    _header,
    _response_ok,
    _same_origin,
    _sha256_text,
    append_verified_finding,
    evaluate_verification_contract,
)


VERIFICATION_VERSION = "VF-PRIV-1"

def _identity_headers(
    ctx: Any,
    identity_name: str,
) -> Dict[str, str]:
    identities = (ctx.config.auth_data or {}).get("identities", {})
    identity = identities.get(identity_name)

    if not isinstance(identity, dict):
        raise ValueError(
            f"privilege identity {identity_name!r} is not configured"
        )

    headers = identity.get("headers", {})

    if not isinstance(headers, dict) or not headers:
        raise ValueError(
            f"privilege identity {identity_name!r} has invalid headers"
        )

    return {
        str(key): str(value)
        for key, value in headers.items()
    }


def _identity_context_id(
    ctx: Any,
    identity_name: str,
) -> str:
    identities = (ctx.config.auth_data or {}).get("identities", {})
    identity = identities.get(identity_name)

    if not isinstance(identity, dict):
        return ""

    value = (
        identity.get("authentication_context_id")
        or identity.get("context_id")
        or identity.get("auth_context_id")
        or ""
    )

    return str(value)


def _planned_privilege_test(
    ctx: Any,
    test_id: str,
) -> Any:
    return next(
        (
            planned
            for planned in getattr(ctx, "test_plan", [])
            if planned.status == "PLANNED"
            and planned.test_id == test_id
            and planned.test_type == "privilege-escalation-validation"
        ),
        None,
    )


async def execute_privilege_escalation_tests(ctx: Any) -> None:
    """Execute explicitly configured read-only privilege-boundary tests.

    Execution never creates findings. It only records the exchanges and
    security-boundary observations used later by the verification gate.
    """

    if not getattr(ctx, "test_plan", None) or ctx.stopped:
        return

    from ..core.profiles import get_profile

    profile = get_profile(ctx.config.profile_name)

    if not profile.allows_active:
        for planned in ctx.test_plan:
            if planned.test_type == "privilege-escalation-validation":
                planned.status = "BLOCKED"

        ctx.emit(
            "stage",
            "Privilege-escalation tests blocked: selected profile "
            "is observation-only",
        )
        return

    specs = getattr(
        ctx,
        "_privilege_escalation_test_specs",
        [],
    )


    executed_test_ids = {
        record.get("test_id")
        for record in getattr(ctx, "tests", [])
    }

    for spec in specs:
        if ctx.stopped:
            break

        test_id = str(spec.get("test_id", ""))

        if not test_id or test_id in executed_test_ids:
            continue

        planned = _planned_privilege_test(ctx, test_id)

        if planned is None:
            continue

        record: Dict[str, Any] = {
            "test_id": planned.test_id,
            "hypothesis_id": planned.hypothesis_id,
            "type": planned.test_type,
            "status": STATUS_INCOMPLETE,
            "endpoint": "",
            "started_at": time.time(),
            "verification_method": (
                "Repeated read-only function authorization comparison"
            ),
            "verification_version": VERIFICATION_VERSION,
        }

        ctx.emit(
            "test-start",
            f"Privilege-escalation test started: {planned.test_id}",
            test_id=planned.test_id,
            hypothesis_id=planned.hypothesis_id,
            test_type=planned.test_type,
            status="RUNNING",
        )

        try:
            url = urljoin(
                ctx.config.target,
                str(spec["url"]),
            )

            if not _same_origin(
                ctx.config.target,
                url,
            ):
                raise ValueError(
                    "privilege-escalation test URL must be same-origin "
                    "as the scan target"
                )

            authorized_name = str(
                spec["authorized_identity"]
            )
            lower_name = str(
                spec["lower_identity"]
            )

            if authorized_name == lower_name:
                raise ValueError(
                    "privilege-escalation identities must be distinct"
                )

            authorized_headers = _identity_headers(
                ctx,
                authorized_name,
            )
            lower_headers = _identity_headers(
                ctx,
                lower_name,
            )

            authorized_context_id = _identity_context_id(
                ctx,
                authorized_name,
            )
            lower_context_id = _identity_context_id(
                ctx,
                lower_name,
            )

            if (
                authorized_context_id
                and lower_context_id
                and authorized_context_id == lower_context_id
            ):
                raise ValueError(
                    "privilege-escalation identities must use distinct "
                    "authentication contexts"
                )

            assertion = spec.get("identity_assertion", {})

            if not isinstance(assertion, dict):
                raise ValueError(
                    "identity_assertion must be configured"
                )

            identity_header = str(
                assertion.get("header", "")
            ).strip()

            authorized_expected_identity = str(
                assertion.get(
                    "authorized_value",
                    assertion.get(
                        "owner_value",
                        authorized_name,
                    ),
                )
            )

            lower_expected_identity = str(
                assertion.get(
                    "lower_value",
                    assertion.get(
                        "other_value",
                        lower_name,
                    ),
                )
            )

            if not identity_header:
                raise ValueError(
                    "identity assertion response header is required"
                )

            if (
                authorized_expected_identity
                == lower_expected_identity
            ):
                raise ValueError(
                    "authorized and lower identity assertions must differ"
                )

            record.update(
                {
                    "endpoint": url,
                    "authorized_identity_label": authorized_name,
                    "lower_identity_label": lower_name,
                    "authorized_authentication_context_id": (
                        authorized_context_id
                    ),
                    "lower_authentication_context_id": (
                        lower_context_id
                    ),
                    "identity_assertion_header": identity_header,
                }
            )

            # ------------------------------------------------------------
            # Authorized baseline
            # ------------------------------------------------------------

            baseline = await ctx.requester.send(
                "GET",
                url,
                headers=authorized_headers,
                module="privilege-escalation-authorized-baseline",
                authentication_context_id=(
                    authorized_context_id or None
                ),
            )

            # ------------------------------------------------------------
            # Lower-role boundary test
            # ------------------------------------------------------------

            lower1 = await ctx.requester.send(
                "GET",
                url,
                headers=lower_headers,
                module="privilege-escalation-lower-role-control",
                authentication_context_id=(
                    lower_context_id or None
                ),
            )

            # ------------------------------------------------------------
            # Lower-role reproduction
            # ------------------------------------------------------------

            lower2 = await ctx.requester.send(
                "GET",
                url,
                headers=lower_headers,
                module="privilege-escalation-lower-role-repeat",
                authentication_context_id=(
                    lower_context_id or None
                ),
            )

            baseline_ok = _response_ok(baseline)
            lower1_ok = _response_ok(lower1)
            lower2_ok = _response_ok(lower2)

            authorized_identity_verified = (
                _header(
                    baseline,
                    identity_header,
                )
                == authorized_expected_identity
            )

            lower_identity_verified = (
                _header(
                    lower1,
                    identity_header,
                )
                == lower_expected_identity
                and
                _header(
                    lower2,
                    identity_header,
                )
                == lower_expected_identity
            )

            role_separation = (
                authorized_name != lower_name
                and authorized_expected_identity
                != lower_expected_identity
            )

            # The protected function is known to be accessible to the
            # authorized identity. The lower identity should NOT receive
            # the same successful authorization result.
            #
            # Therefore a successful lower-role response is the actual
            # security-boundary violation.
            unauthorized_access = (
                baseline_ok
                and lower1_ok
            )

            differential_ok = (
                baseline_ok
                and lower1_ok
                and authorized_identity_verified
                and lower_identity_verified
                and role_separation
            )

            reproduction_ok = (
                differential_ok
                and lower2_ok
                and _header(
                    lower2,
                    identity_header,
                )
                == lower_expected_identity
            )

            impact_ok = (
                unauthorized_access
                and reproduction_ok
            )

            # This is intentionally named "control" from the perspective
            # of the protected-function boundary. A successful lower-role
            # request demonstrates that the expected denial control failed.
            control_ok = unauthorized_access

            exchange_ids = [
                _exchange_id(baseline),
                _exchange_id(lower1),
                _exchange_id(lower2),
            ]

            exchange_ids = [
                value
                for value in exchange_ids
                if value
            ]

            record.update(
                {
                    "status": (
                        "EXECUTED"
                        if all(
                            exchange is not None
                            for exchange in (
                                baseline,
                                lower1,
                                lower2,
                            )
                        )
                        else STATUS_INCOMPLETE
                    ),
                    "baseline_exchange_id": _exchange_id(
                        baseline
                    ),
                    "lower_role_exchange_id": _exchange_id(
                        lower1
                    ),
                    "repeat_exchange_id": _exchange_id(
                        lower2
                    ),
                    "exchange_ids": exchange_ids,
                    "baseline_status": getattr(
                        baseline,
                        "status",
                        None,
                    ),
                    "lower_role_status": getattr(
                        lower1,
                        "status",
                        None,
                    ),
                    "repeat_status": getattr(
                        lower2,
                        "status",
                        None,
                    ),
                    "authorized_identity_verified": (
                        authorized_identity_verified
                    ),
                    "lower_identity_verified": (
                        lower_identity_verified
                    ),
                    "role_separation": role_separation,
                    "baseline_ok": baseline_ok,
                    "lower_role_access_observed": lower1_ok,
                    "repeat_lower_role_access_observed": lower2_ok,
                    "authorization_boundary_violation": (
                        unauthorized_access
                    ),
                    "differential_ok": differential_ok,
                    "reproduction_ok": reproduction_ok,
                    "impact_ok": impact_ok,
                    "scope_ok": True,
                    "control_ok": control_ok,
                    "baseline_response_sha256": _sha256_text(
                        getattr(
                            baseline,
                            "response_body",
                            "",
                        )
                    ),
                    "lower_role_response_sha256": _sha256_text(
                        getattr(
                            lower1,
                            "response_body",
                            "",
                        )
                    ),
                    "repeat_response_sha256": _sha256_text(
                        getattr(
                            lower2,
                            "response_body",
                            "",
                        )
                    ),
                    "security_boundary": (
                        "function-level authorization / "
                        "vertical privilege separation"
                    ),
                    "authorization_matrix": {
                        "authorized_identity": authorized_name,
                        "lower_identity": lower_name,
                        "authorized_authentication_context_id": (
                            authorized_context_id
                        ),
                        "lower_authentication_context_id": (
                            lower_context_id
                        ),
                        "target_function": url,
                        "expected_lower_decision": "DENY",
                        "actual_lower_status": getattr(
                            lower1,
                            "status",
                            None,
                        ),
                    },
                }
            )

            evidence = {
                # Central verification contract requirements.
                "identity_separation": (
                    authorized_name != lower_name
                    and authorized_expected_identity
                    != lower_expected_identity
                    and (
                        not authorized_context_id
                        or not lower_context_id
                        or authorized_context_id
                        != lower_context_id
                    )
                ),
                "protected_resource": (
                    bool(url)
                    and baseline_ok
                    and authorized_identity_verified
                ),
                "role_separation": role_separation,

                # Additional traceable observations.
                "authorized_identity_verified": (
                    authorized_identity_verified
                ),
                "lower_identity_verified": (
                    lower_identity_verified
                ),
                "authorization_boundary_violation": (
                    unauthorized_access
                ),
            }

            decision = evaluate_verification_contract(
                vulnerability_type="privilege_escalation",
                scope_ok=True,
                baseline_ok=(
                    baseline_ok
                    and authorized_identity_verified
                ),
                control_ok=control_ok,
                differential_ok=differential_ok,
                reproduction_ok=reproduction_ok,
                impact_ok=impact_ok,
                evidence=evidence,
                exchange_ids=exchange_ids,
            )

            record["verification"] = decision.as_dict()

            if decision.status == STATUS_VERIFIED_LOCAL:
                from ..core.models import Finding

                finding = Finding(
                    title="Vertical privilege escalation",
                    category="privilege escalation",
                    severity="HIGH",
                    description=(
                        f"The lower-privilege identity "
                        f"{lower_name!r} was able to access the "
                        f"researcher-declared protected function "
                        f"{url}, despite the function being "
                        "authorized for the higher-privilege identity."
                    ),
                    endpoint=url,
                    method="GET",
                    confidence=decision.confidence,
                    status=STATUS_VERIFIED,
                    state="VERIFIED",
                    evidence=[
                        EvidenceItem(
                            description=(
                                "Authorized baseline succeeded and the "
                                "distinct lower-privilege identity received "
                                "the same protected function successfully "
                                "on repeated requests."
                            ),
                            request_summary=(
                                "Three same-origin GET requests using "
                                "explicitly configured separate identities; "
                                "credentials redacted."
                            ),
                            response_summary=(
                                f"Authorized HTTP "
                                f"{record['baseline_status']}; "
                                f"lower-role HTTP "
                                f"{record['lower_role_status']}; "
                                f"repeat HTTP "
                                f"{record['repeat_status']}."
                            ),
                            detail={
                                **record,
                                "verification": decision.as_dict(),
                            },
                        )
                    ],
                    remediation=(
                        "Enforce server-side role authorization for the "
                        "protected function on every request. Do not rely "
                        "on client-side role checks or hidden UI controls."
                    ),
                    cwe="CWE-862",
                    owasp="A01:2021 Broken Access Control",
                    source_plugin=(
                        "privilege-escalation-verification"
                    ),
                    impact=(
                        "A lower-privilege account can invoke a function "
                        "reserved for a higher-privilege role."
                    ),
                )

                promoted = append_verified_finding(
                    ctx,
                    finding,
                    decision,
                )

                if promoted:
                    record["status"] = "VERIFIED"
                    record["finding_id"] = finding.id
                    record["verification_status"] = decision.status
                    record["verification_confidence"] = decision.confidence
                    record["verification_missing"] = list(
                        decision.missing
                    )
                    record["verification_reasons"] = list(
                        decision.reasons
                    )
                    planned.status = "VERIFIED"

            executed_test_ids.add(
                planned.test_id
            )

        except (KeyError, TypeError, ValueError) as exc:
            record["status"] = "NOT_RUN"
            record["reason"] = str(exc)
            planned.status = "BLOCKED"

            ctx.emit(
                "stage",
                f"Privilege-escalation test not run: {exc}",
            )

        except Exception as exc:
            record["status"] = "ERROR"
            record["reason"] = (
                f"{type(exc).__name__}: {exc}"
            )
            planned.status = "INCOMPLETE"

            ctx.emit(
                "stage",
                "Privilege-escalation verifier error: "
                f"{type(exc).__name__}: {exc}",
            )

        record["finished_at"] = time.time()

        ctx.tests.append(record)

        ctx.emit(
            "test-complete",
            f"Privilege-escalation test completed: {planned.test_id}",
            test_id=record.get("test_id"),
            hypothesis_id=record.get("hypothesis_id"),
            test_type=record.get("type"),
            status=record.get("status"),
            endpoint=record.get("endpoint"),
        )
