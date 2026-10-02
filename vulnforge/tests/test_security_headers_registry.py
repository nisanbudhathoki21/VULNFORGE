"""
Phase 3: security_headers / cookie_session are now a supported, confirmable
class backed by the passive header/cookie-flag plugins — this was previously
mis-registered as UNSUPPORTED even though a real detector existed.
"""
from __future__ import annotations

from types import SimpleNamespace

from vulnforge.engine.vulnerability_registry import (
    VULNERABILITY_CLASSES, build_vulnerability_matrix,
)
from vulnforge.core.models import Finding, STATUS_VERIFIED


def _ctx(findings=None, pages_ok=1):
    pages = [SimpleNamespace(ok=True) for _ in range(pages_ok)]
    return SimpleNamespace(
        findings=findings or [], pages=pages, test_plan=[], tests=[], hypotheses=[],
        config=SimpleNamespace(auth_data={}, active_requested=False, profile_name="standard"),
    )


def test_security_headers_class_is_registered_supported():
    definition = VULNERABILITY_CLASSES["security_headers"]
    assert definition["supported"] is True
    assert definition["can_confirm"] is True
    assert definition["verification_level"] == "DETERMINISTIC_PASSIVE_OBSERVATION"


def test_cookie_session_class_is_registered_supported():
    definition = VULNERABILITY_CLASSES["cookie_session"]
    assert definition["supported"] is True
    assert definition["can_confirm"] is True


def test_matrix_confirms_when_plugin_findings_present():
    finding = Finding(title="x", category="y", severity="low", description="d", status=STATUS_VERIFIED,
                       source_plugin="vf2-passive-security-headers")
    rows = build_vulnerability_matrix(_ctx(findings=[finding]), "full")
    row = next(r for r in rows if r["class_id"] == "security_headers")
    assert row["status"] == "CONFIRMED"


def test_matrix_tested_clean_when_no_findings_but_pages_crawled():
    rows = build_vulnerability_matrix(_ctx(findings=[]), "full")
    row = next(r for r in rows if r["class_id"] == "security_headers")
    assert row["status"] == "TESTED_CLEAN"


def test_matrix_no_test_surface_when_nothing_crawled():
    rows = build_vulnerability_matrix(_ctx(findings=[], pages_ok=0), "full")
    row = next(r for r in rows if r["class_id"] == "security_headers")
    assert row["status"] == "NO_TEST_SURFACE"
