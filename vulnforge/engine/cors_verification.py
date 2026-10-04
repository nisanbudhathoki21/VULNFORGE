"""Unified, bounded CORS verification.

Evidence-first:
- header behavior is never treated as impact by itself
- multiple origin classes are compared
- credential policy, preflight and cache/Vary behavior are recorded
- final promotion remains controlled by the central verification contract
"""
from __future__ import annotations

import time
from typing import Any


# Reserved researcher-controlled origins only.
TEST_ORIGINS = (
    "https://vf-a.invalid",
    "https://vf-b.invalid",
    "https://vf-c.invalid",
)

SPECIAL_ORIGINS = (
    "null",
    "https://attacker.vf-a.invalid",
    "https://vf-a.invalid.evil.invalid",
    "https://evil.invalid/vf-a.invalid",
)

CORS_METHOD = "cors-unified"

RESPONSE_HEADERS = (
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "access-control-allow-methods",
    "access-control-allow-headers",
    "access-control-expose-headers",
    "vary",
)


def _header(exchange: Any, name: str) -> str:
    return str(exchange.header(name, "") or "").strip()


def _observation(origin: str, exchange: Any) -> dict[str, Any]:
    return {
        "origin": origin,
        "exchange_id": exchange.exchange_id,
        "status": exchange.status,
        "error": exchange.error,
        "allow_origin": _header(exchange, "access-control-allow-origin"),
        "allow_credentials": _header(
            exchange, "access-control-allow-credentials"
        ).lower(),
        "allow_methods": _header(exchange, "access-control-allow-methods"),
        "allow_headers": _header(exchange, "access-control-allow-headers"),
        "expose_headers": _header(exchange, "access-control-expose-headers"),
        "vary": _header(exchange, "vary"),
    }


async def execute_cors_tests(ctx) -> None:
    """Run one bounded unified CORS policy assessment per planned surface."""
    specs = list(getattr(ctx, "_cors_test_specs", []))

    if not specs or ctx.stopped:
        return

    from ..core.profiles import get_profile

    profile = get_profile(ctx.config.profile_name)

    if not ctx.config.active_requested or not profile.allows_active:
        for planned in ctx.test_plan:
            if (
                planned.test_type == CORS_METHOD
                and planned.status == "PLANNED"
            ):
                planned.status = "BLOCKED"

        ctx.emit(
            "stage",
            "CORS checks blocked: explicit active request and active-capable safety mode are required",
        )
        return

    for spec in specs:
        if ctx.stopped:
            break

        planned = next(
            (
                p
                for p in ctx.test_plan
                if p.test_id == spec["test_id"]
            ),
            None,
        )

        record: dict[str, Any] = {
            "test_id": spec["test_id"],
            "hypothesis_id": spec["hypothesis_id"],
            "type": CORS_METHOD,
            "status": "INCOMPLETE",
            "endpoint": spec["url"],
            "method": "GET",
            "methodology_id": "VF-METHOD-CORS",
            "started_at": time.time(),
            "observations": [],
            "preflight_observations": [],
            "security_claim": "CORS trust-policy differential",
            "impact_proven": False,
            "browser_data_boundary": False,
        }

        try:
            # ---------------------------------------------------------
            # 1. Untrusted-origin differential
            # ---------------------------------------------------------
            for origin in TEST_ORIGINS:
                exchange = await ctx.requester.send(
                    "GET",
                    spec["url"],
                    headers={"Origin": origin},
                    module=CORS_METHOD,
                    follow_redirects=False,
                )

                record["observations"].append(
                    _observation(origin, exchange)
                )

                if exchange.error or exchange.status <= 0:
                    break

            # ---------------------------------------------------------
            # 2. Origin edge cases
            # ---------------------------------------------------------
            for origin in SPECIAL_ORIGINS:
                if ctx.stopped:
                    break

                exchange = await ctx.requester.send(
                    "GET",
                    spec["url"],
                    headers={"Origin": origin},
                    module=CORS_METHOD,
                    follow_redirects=False,
                )

                record["observations"].append(
                    _observation(origin, exchange)
                )

                if exchange.error or exchange.status <= 0:
                    break

            # ---------------------------------------------------------
            # 3. Preflight observation
            # ---------------------------------------------------------
            if not ctx.stopped:
                exchange = await ctx.requester.send(
                    "OPTIONS",
                    spec["url"],
                    headers={
                        "Origin": "https://vf-a.invalid",
                        "Access-Control-Request-Method": "PUT",
                        "Access-Control-Request-Headers": (
                            "Authorization, Content-Type"
                        ),
                    },
                    module=CORS_METHOD,
                    follow_redirects=False,
                )

                record["preflight_observations"].append(
                    {
                        "exchange_id": exchange.exchange_id,
                        "status": exchange.status,
                        "error": exchange.error,
                        "allow_origin": _header(
                            exchange,
                            "access-control-allow-origin",
                        ),
                        "allow_credentials": _header(
                            exchange,
                            "access-control-allow-credentials",
                        ).lower(),
                        "allow_methods": _header(
                            exchange,
                            "access-control-allow-methods",
                        ),
                        "allow_headers": _header(
                            exchange,
                            "access-control-allow-headers",
                        ),
                        "vary": _header(exchange, "vary"),
                    }
                )

            completed = (
                len(record["observations"])
                == len(TEST_ORIGINS) + len(SPECIAL_ORIGINS)
            )

            record["status"] = (
                "EXECUTED" if completed else "INCOMPLETE"
            )

            record["finished_at"] = time.time()

            if planned:
                planned.status = (
                    "EXECUTED" if completed else "INCOMPLETE"
                )

            ctx.tests.append(record)

        except Exception as exc:
            record["status"] = "INCOMPLETE"
            record["reason"] = (
                f"{type(exc).__name__}: bounded CORS assessment "
                "did not complete"
            )
            record["finished_at"] = time.time()

            if planned:
                planned.status = "INCOMPLETE"

            ctx.tests.append(record)

            if type(exc).__name__ in {
                "ScanAborted",
                "CancelledError",
            }:
                raise

    ctx.emit(
        "stage",
        "Unified CORS assessments collected: "
        + str(
            sum(
                t.get("type") == CORS_METHOD
                for t in ctx.tests
            )
        ),
    )


def _successful(item: dict[str, Any]) -> bool:
    try:
        status = int(item.get("status", 0))
    except (TypeError, ValueError):
        return False

    return (
        200 <= status < 300
        and not item.get("error")
    )


def verify_cors_tests(ctx) -> None:
    """Evaluate the unified CORS evidence without overstating impact."""

    hypotheses = {
        h.hypothesis_id: h
        for h in ctx.hypotheses
    }

    for record in ctx.tests:
        if record.get("type") != CORS_METHOD:
            continue

        if record.get("status") != "EXECUTED":
            continue

        observations = record.get("observations", [])

        primary = observations[: len(TEST_ORIGINS)]

        reflection = (
            len(primary) == len(TEST_ORIGINS)
            and all(
                _successful(item)
                and item.get("allow_origin") == item.get("origin")
                for item in primary
            )
        )

        credentialed = (
            reflection
            and all(
                item.get("allow_credentials") == "true"
                for item in primary
            )
        )

        distinct_origins = len(
            {
                item.get("origin")
                for item in primary
            }
        ) == len(TEST_ORIGINS)

        null_item = next(
            (
                item
                for item in observations
                if item.get("origin") == "null"
            ),
            None,
        )

        subdomain_item = next(
            (
                item
                for item in observations
                if item.get("origin")
                == "https://attacker.vf-a.invalid"
            ),
            None,
        )

        suffix_confusion = next(
            (
                item
                for item in observations
                if item.get("origin")
                == "https://vf-a.invalid.evil.invalid"
            ),
            None,
        )

        path_confusion = next(
            (
                item
                for item in observations
                if item.get("origin")
                == "https://evil.invalid/vf-a.invalid"
            ),
            None,
        )

        edge_reflections = {
            "null_origin_reflected": bool(
                null_item
                and null_item.get("allow_origin") == "null"
            ),
            "subdomain_reflected": bool(
                subdomain_item
                and subdomain_item.get("allow_origin")
                == "https://attacker.vf-a.invalid"
            ),
            "suffix_confusion_reflected": bool(
                suffix_confusion
                and suffix_confusion.get("allow_origin")
                == "https://vf-a.invalid.evil.invalid"
            ),
            "path_confusion_reflected": bool(
                path_confusion
                and path_confusion.get("allow_origin")
                == "https://evil.invalid/vf-a.invalid"
            ),
        }

        preflight = record.get(
            "preflight_observations", []
        )

        preflight_item = (
            preflight[0] if preflight else {}
        )

        preflight_allowed = bool(
            preflight_item
            and _successful(preflight_item)
            and (
                "PUT"
                in str(
                    preflight_item.get(
                        "allow_methods", ""
                    )
                ).upper()
            )
        )

        vary_values = [
            str(item.get("vary", "")).lower()
            for item in primary
        ]

        vary_origin_present = all(
            "origin" in value
            for value in vary_values
            if value
        )

        record["status"] = "CANDIDATE"
        record["claim_status"] = (
            "CORS_POLICY_DIFFERENTIAL"
        )

        record["evidence_summary"] = {
            "three_origin_reflection": reflection,
            "credentialed_policy": credentialed,
            "distinct_test_origins": distinct_origins,
            "edge_cases": edge_reflections,
            "preflight_put_allowed": preflight_allowed,
            "vary_origin_present": vary_origin_present,
        }

        record["reproduction_status"] = (
            "REPRODUCED"
            if reflection and distinct_origins
            else "CANDIDATE"
        )

        record["impact_proven"] = False
        record["browser_data_boundary"] = False

        if credentialed:
            record["candidate_reason"] = (
                "Multiple reserved untrusted origins were reflected "
                "with credential allowance. This establishes a "
                "credentialed CORS policy differential, but does not "
                "by itself prove browser-readable authenticated data."
            )
        elif reflection:
            record["candidate_reason"] = (
                "Multiple reserved untrusted origins were reflected. "
                "Browser-readable sensitive-data impact is not proven."
            )
        else:
            record["candidate_reason"] = (
                "The bounded unified CORS reflection condition was "
                "not reproduced."
            )

        record["required_follow_up"] = (
            "Only with explicit authorization: verify browser "
            "credential behavior and perform a data-boundary "
            "validation against synthetic researcher-controlled "
            "data. Never use real user data."
        )

        hypothesis = hypotheses.get(
            record.get("hypothesis_id")
        )

        if hypothesis:
            hypothesis.status = (
                "DEEPER_TESTING"
                if reflection
                else "KILL"
            )
