"""Crawler + orchestrator end-to-end tests against the local mock app."""
import asyncio
import pytest

from vulnforge.core.authorization import AuthorizationContext
from vulnforge.engine.orchestrator import ScanConfig, run_scan
from vulnforge.engine.crawler import Crawler
from vulnforge.core.profiles import get_profile
from vulnforge.http.client import Requester


def _auth(base, profile="passive"):
    return AuthorizationContext(
        allowed_hosts=["127.0.0.1"], profile_name=profile,
        allow_private=True, confirmed=True)


def _config(base, profile="passive"):
    return ScanConfig(target=base, profile_name=profile,
                      allowed_hosts=["127.0.0.1"], authorization_confirmed=True)


def test_crawler_discovers_and_stays_in_scope(mock_server):
    async def go():
        auth = _auth(mock_server)
        requester = Requester(auth, get_profile("passive"))
        try:
            crawler = Crawler(requester, auth, get_profile("passive"))
            result = await crawler.run([mock_server])
            urls = {p.url for p in result.pages}
            assert mock_server + "/" in urls
            assert any(u.startswith(mock_server + "/user/") for u in urls)
            # out-of-scope external link must never have been requested
            assert all("out-of-scope.example" not in u for u in urls)
            assert any("app.js" in u for u in result.js_assets)
            # shape dedup: /user/1 and /user/2 are the same endpoint shape
            assert any(u.endswith("/user/1") for u in urls) or any(u.endswith("/user/2") for u in urls)
            return result
        finally:
            await requester.close()
    result = asyncio.run(go())
    assert result is not None


def test_requester_blocks_out_of_scope(mock_server):
    async def go():
        auth = _auth(mock_server)
        requester = Requester(auth, get_profile("passive"))
        try:
            ex = await requester.send("GET", "http://out-of-scope.example/x", module="test")
            assert ex.error and "scope-denied" in ex.error
            assert requester.budget.sent == 0  # denied requests are not budget requests
        finally:
            await requester.close()
    asyncio.run(go())


def test_full_passive_pipeline(mock_server):
    result = run_scan(_config(mock_server, "passive"), _auth(mock_server))
    ctx = result.context
    # pipeline stages completed in order
    for stage in ("auth", "http", "recon", "crawl", "js", "inventory", "tech", "passive-checks"):
        assert stage in result.stage_timings, f"missing stage {stage}"
    # discovery worked
    assert len(ctx.endpoints) >= 4
    assert ctx.stats.pages_crawled >= 2
    # endpoint & parameter intelligence
    params = list(ctx.parameters.values())
    assert any(p.name == "q" for p in params)
    # forms produce state-changing surface even in passive mode
    assert any(ep.source == "form" for ep in ctx.endpoints.values())
    # JS signals fired (secret-like must be redacted)
    kinds = {s.kind for s in ctx.signals}
    assert "secret_like" in kinds
    assert "AKIAIOSFODNN7EXAMPLE" not in str([s.detail for s in ctx.signals])
    # tech detection (meta generator WordPress)
    assert "WordPress" in ctx.technologies
    # passive plugins produced configuration findings, NOT 'critical vulns'
    assert ctx.findings, "expected passive findings"
    assert all(f.severity in ("info", "low", "medium", "high") for f in ctx.findings)
    assert any("Security header" in f.title for f in ctx.findings)
    # info disclosure: stack trace page flagged
    assert any("stack trace" in f.title.lower() for f in ctx.findings)
    # audit trail present
    assert ctx.authorization.audit_dump()
    assert ctx.stats.requests_sent > 0


def test_scan_refuses_out_of_scope_target():
    with pytest.raises(PermissionError):
        run_scan(
            ScanConfig(target="https://unauthorized.example/",
                       profile_name="passive",
                       allowed_hosts=["127.0.0.1"], authorization_confirmed=True),
            AuthorizationContext(allowed_hosts=["127.0.0.1"], confirmed=True,
                                 allow_private=True))


def test_budget_ceiling_stops_network_but_finishes_offline_phases(mock_server):
    cfg = _config(mock_server, "passive")
    cfg.request_budget=3
    cfg.request_rate=100
    result = run_scan(cfg, _auth(mock_server))
    ctx=result.context
    assert ctx.stats.requests_sent == 3
    assert ctx.stop_reason == "request budget exhausted"
    assert not result.aborted  # network stopped; offline analysis and reporting may continue
    assert all(stage in result.stage_timings for stage in ("inventory","tech","passive-checks","intelligence","verification"))
    assert ctx.stats.endpoints_discovered >= 1
