import asyncio
from types import SimpleNamespace

from vulnforge.core.authorization import AuthorizationContext
from vulnforge.core.models import HypothesisRecord, PlannedTest, ScanContext
from vulnforge.core.profiles import get_profile
from vulnforge.engine.cors_verification import execute_cors_tests, verify_cors_tests
from vulnforge.engine.methodology import build_test_methodology
from vulnforge.http.client import Requester


def _context(url, hypothesis_id="hyp-cors"):
    from urllib.parse import urlsplit
    parsed=urlsplit(url)
    port=parsed.port
    auth=AuthorizationContext(allowed_hosts=[parsed.hostname],allowed_ports=[port],
        allowed_methods=["GET"],profile_name="lab",allow_private=True,confirmed=True)
    config=SimpleNamespace(profile_name="lab",active_requested=True)
    ctx=ScanContext("scan-cors",config,auth)
    ctx.requester=Requester(auth,get_profile("lab"),timeout=3)
    card=build_test_methodology("cors-origin-reflection",url)
    ctx.test_plan=[PlannedTest("test-cors",hypothesis_id,"cors-origin-reflection",url,
        "GET",3,"LOW_READ_ONLY",True,"PLANNED",methodology=card)]
    ctx.hypotheses=[HypothesisRecord(hypothesis_id,"cors-policy-review","KEEP",endpoint=url,
        reason="Observed in-scope GET surface; no CORS behavior inferred in advance.")]
    ctx._cors_test_specs=[{"url":url,"test_id":"test-cors","hypothesis_id":hypothesis_id}]
    return ctx


def test_cors_method_card_is_auditable_and_limits_claims():
    card=build_test_methodology("cors-origin-reflection","http://127.0.0.1/x")
    assert card["methodology_id"]=="VF-METHOD-CORS-1"
    assert card["permitted_methods"]==["GET"]
    assert card["request_cost"]==3
    assert any("does not prove" in item for item in card["limitations"])
    assert "three distinct reserved .invalid origins" in card["rationale"]


def test_credentialed_origin_reflection_remains_candidate_without_browser_impact(mock_server):
    ctx=_context(mock_server+"/cors/reflect")
    async def run():
        try:
            await execute_cors_tests(ctx)
            verify_cors_tests(ctx)
        finally:
            await ctx.requester.close()
    asyncio.run(run())
    assert len(ctx.tests)==1
    test=ctx.tests[0]
    assert test["status"]=="CANDIDATE"
    assert test["reproduction_status"]=="REPRODUCED"
    assert len(test["observations"])==3
    assert len({item["origin"] for item in test["observations"]})==3
    assert all(item["exchange_id"] for item in test["observations"])
    assert test["impact_proven"] is False
    assert "browser credential behavior" in test["required_follow_up"]
    assert ctx.findings==[]
    assert ctx.hypotheses[0].status=="DEEPER_TESTING"


def test_medium_portfolio_runs_only_bounded_cors_and_redirect_checks_in_full_pipeline(mock_server):
    from vulnforge.engine.orchestrator import ScanConfig, run_scan
    auth=AuthorizationContext(allowed_hosts=["127.0.0.1"],profile_name="lab",
        allowed_methods=["GET","HEAD","OPTIONS"],allow_private=True,confirmed=True)
    config=ScanConfig(target=mock_server,profile_name="lab",
        allowed_hosts=["127.0.0.1"],allowed_methods=["GET","HEAD","OPTIONS"],
        allow_private=True,authorization_confirmed=True,active_requested=True,
        test_profile="medium",test_profile_explicit=True)
    result=run_scan(config,auth)
    cors_tests=[item for item in result.context.tests if item.get("type")=="cors-origin-reflection"]
    assert 1<=len(cors_tests)<=3
    assert all(len(item["observations"])<=3 for item in cors_tests)
    assert sum(len(item["observations"]) for item in cors_tests)<=9
    assert any(item["status"]=="CANDIDATE" and item["reproduction_status"]=="REPRODUCED" for item in cors_tests)
    assert not any(finding.category=="cors / configuration" for finding in result.context.verified_findings)
    assert any(item["class_id"]=="cors" and item["supported"] for item in result.context.vulnerability_matrix)
    redirect_tests=[item for item in result.context.tests if item.get("type")=="open-redirect-validation"]
    assert 1<=len(redirect_tests)<=3
    assert any("/open-redirect?" in item["endpoint"] and item["status"]=="VERIFIED" for item in redirect_tests)
    assert any("/safe-redirect?" in item["endpoint"] and item["status"]=="CANDIDATE" for item in redirect_tests)
    assert all(obs["resolved_location"].startswith(mock_server) or "vf-redirect.invalid" in obs["resolved_location"]
               for item in redirect_tests for obs in item["observations"])
    assert any(item["class_id"]=="open_redirect" and item["supported"] for item in result.context.vulnerability_matrix)
    assert result.context.requester.budget.sent<=result.context.requester.budget.max_requests


def test_fixed_allowlist_cors_response_does_not_verify_reflection(mock_server):
    ctx=_context(mock_server+"/cors/allowlist")
    async def run():
        try:
            await execute_cors_tests(ctx)
            verify_cors_tests(ctx)
        finally:
            await ctx.requester.close()
    asyncio.run(run())
    assert ctx.tests[0]["status"]=="CANDIDATE"
    assert ctx.findings==[]


def test_cors_executor_does_nothing_without_explicit_active_request(mock_server):
    ctx=_context(mock_server+"/cors/reflect")
    ctx.config.active_requested=False
    async def run():
        try: await execute_cors_tests(ctx)
        finally: await ctx.requester.close()
    asyncio.run(run())
    assert ctx.tests==[]
    assert ctx.test_plan[0].status=="BLOCKED"
