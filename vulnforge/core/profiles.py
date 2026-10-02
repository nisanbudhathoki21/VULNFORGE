"""
VulnForge — scan profiles (spec §4).

Profiles bound how aggressive a scan may be. They are displayed to the user
and never switched silently. Active testing classes are only reachable in
the profiles that explicitly list them.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import List


@dataclass(frozen=True)
class Profile:
    name: str
    description: str
    requests_per_second: float
    max_concurrency: int
    max_requests: int
    max_depth: int
    max_pages: int
    scan_timeout_s: int
    max_response_bytes: int
    allows_active: bool
    allows_private_targets: bool
    active_check_classes: List[str] = field(default_factory=list)


PROFILES = {
    "passive": Profile(
        name="passive",
        description="Observation only: crawl, map, fingerprint, passive analysis. No test payloads.",
        requests_per_second=5.0, max_concurrency=4, max_requests=500,
        max_depth=3, max_pages=150, scan_timeout_s=600,
        max_response_bytes=2_000_000, allows_active=False, allows_private_targets=True,
    ),
    "quick": Profile(
        name="quick",
        description="Quick bounded passive mapping; active checks require --active and an implemented module.",
        requests_per_second=8.0, max_concurrency=6, max_requests=1500,
        max_depth=3, max_pages=200, scan_timeout_s=1200,
        max_response_bytes=2_000_000, allows_active=True, allows_private_targets=True,
        active_check_classes=["configured_authorization","cors_origin_reflection","open_redirect_validation","sql_injection_validation"],
    ),
    "standard": Profile(
        name="standard",
        description="Standard bounded passive discovery; controlled verification is opt-in and module-specific.",
        requests_per_second=10.0, max_concurrency=8, max_requests=5000,
        max_depth=4, max_pages=400, scan_timeout_s=2400,
        max_response_bytes=3_000_000, allows_active=True, allows_private_targets=True,
        active_check_classes=["configured_authorization","cors_origin_reflection","open_redirect_validation","sql_injection_validation"],
    ),
    "deep": Profile(
        name="deep",
        description="Deeper bounded discovery; only explicitly implemented read-only checks run, with no blind/timing SQLi or data extraction.",
        requests_per_second=15.0, max_concurrency=10, max_requests=15000,
        max_depth=5, max_pages=800, scan_timeout_s=5400,
        max_response_bytes=4_000_000, allows_active=True, allows_private_targets=True,
        active_check_classes=["configured_authorization","cors_origin_reflection","open_redirect_validation","sql_injection_validation"],
    ),
    "lab": Profile(
        name="lab",
        description="Local regression targets; only explicitly configured, implemented read-only checks run.",
        requests_per_second=25.0, max_concurrency=12, max_requests=30000,
        max_depth=6, max_pages=1500, scan_timeout_s=10800,
        max_response_bytes=6_000_000, allows_active=True, allows_private_targets=True,
        active_check_classes=["configured_authorization","cors_origin_reflection","open_redirect_validation","sql_injection_validation"],
    ),
}

# Explicit safety modes are aliases with conservative limits, not broader check sets.
from dataclasses import replace
PROFILES["safe-active"] = replace(PROFILES["standard"], name="safe-active",
    description="Opt-in, low-rate active mode; only configured supported modules run.",
    requests_per_second=2.0, max_requests=1000, active_check_classes=["configured_authorization","cors_origin_reflection","open_redirect_validation","sql_injection_validation"])
PROFILES["controlled-active"] = replace(PROFILES["standard"], name="controlled-active",
    description="Opt-in controlled mode; tests must be explicitly configured and supported.",
    requests_per_second=2.0, max_requests=1000, active_check_classes=["configured_authorization","cors_origin_reflection","open_redirect_validation","sql_injection_validation"])

DEFAULT_PROFILE = "standard"


def get_profile(name: str) -> Profile:
    p = PROFILES.get((name or "").lower())
    if not p:
        raise ValueError(f"Unknown profile '{name}'. Available: {', '.join(PROFILES)}")
    return p
