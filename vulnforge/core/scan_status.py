"""Central scan lifecycle and assessment-status classification."""

from __future__ import annotations

from typing import Any


def target_unreachable(context: Any) -> bool:
    """Return True only when the target could not be meaningfully reached.

    A request error by itself does not make a scan unreachable because a real
    application can have an individual failed request while other endpoints
    remain assessable.

    We require:
      - no pages discovered
      - no endpoints discovered
      - at least one crawl error/timeout
      - transport evidence indicating DEAD or TIMEOUT
    """

    stats = getattr(context, "stats", None)

    pages = int(getattr(stats, "pages_crawled", 0) or 0)
    endpoints = len(getattr(context, "endpoints", {}) or {})
    crawl_errors = int(getattr(stats, "crawl_errors", 0) or 0)
    crawl_timeouts = int(getattr(stats, "crawl_timeouts", 0) or 0)

    live_counts = getattr(context, "live_state_counts", {}) or {}
    dead = int(live_counts.get("DEAD", 0) or 0)
    timeouts = int(live_counts.get("TIMEOUT", 0) or 0)

    transport_failures = dead + timeouts

    return (
        pages == 0
        and endpoints == 0
        and (crawl_errors > 0 or crawl_timeouts > 0)
        and transport_failures > 0
    )


def scan_status(scan: Any) -> str:
    """Return the canonical persisted scan status."""

    context = scan.context

    if bool(getattr(scan, "aborted", False)):
        return "aborted"

    if target_unreachable(context):
        return "target_unreachable"

    if getattr(context, "stop_reason", ""):
        return "partial"

    return "completed"


def assessment_status(scan: Any) -> str:
    """Return whether a security assessment was actually performed."""

    status = scan_status(scan)

    if status == "target_unreachable":
        return "not_assessed"

    if status == "aborted":
        return "interrupted"

    if status == "partial":
        return "partial"

    return "assessed"


def status_reason(context: Any) -> str:
    """Return a safe human-readable reason for target-unreachable state."""

    live_counts = getattr(context, "live_state_counts", {}) or {}

    if int(live_counts.get("DEAD", 0) or 0) > 0:
        return "Connection refused"

    if int(live_counts.get("TIMEOUT", 0) or 0) > 0:
        return "Target connection timed out"

    return "Target could not be reached"
