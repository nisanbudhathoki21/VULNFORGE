import asyncio
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

from vulnforge.core.authorization import AuthorizationContext
from vulnforge.core.models import HypothesisRecord, PlannedTest, ScanContext
from vulnforge.core.profiles import get_profile
from vulnforge.engine.methodology import build_test_methodology
from vulnforge.engine.open_redirect_verification import (
    EXTERNAL_MARKER, execute_open_redirect_tests, replace_query_value, verify_open_redirect_tests,
)
from vulnforge.http.client import Requester


def _context(url, hypothesis_id="hyp-redirect"):
    parsed=urlsplit(url)
    auth=AuthorizationContext(allowed_hosts=[parsed.hostname],allowed_ports=[parsed.port],
        allowed_methods=["GET"],profile_name="lab",allow_private=True,confirmed=True)
    config=SimpleNamespace(profile_name="lab",active_requested=True)
    ctx=ScanContext("scan-redirect",config,auth)
    ctx.requester=Requester(auth,get_profile("lab"),timeout=3)
    ctx.test_plan=[PlannedTest("test-redirect",hypothesis_id,"open-redirect-validation",url,
        "GET",2,"LOW_READ_ONLY",True,"PLANNED",
        methodology=build_test_methodology("open-redirect-validation",url))]
    ctx.hypotheses=[HypothesisRecord(hypothesis_id,"open-redirect-review","KEEP",endpoint=url,
        parameter="next",reason="Observed redirect-like query parameter; not yet tested.")]
    ctx._open_redirect_test_specs=[{"url":url,"parameter":"next","test_id":"test-redirect",
                                    "hypothesis_id":hypothesis_id}]
    return ctx


def test_redirect_test_card_and_query_mutation_are_narrow():
    url="https://local.example/path?x=1&next=%2Fhome&next=%2Fother"
    changed=replace_query_value(url,"next",EXTERNAL_MARKER)
    assert parse_qs(urlsplit(changed).query)=={"x":["1"],"next":[EXTERNAL_MARKER,EXTERNAL_MARKER]}
    card=build_test_methodology("open-redirect-validation",url)
    assert card["request_cost"]==2
    assert card["permitted_methods"]==["GET"]
    assert any("Does not follow" in text for text in card["limitations"])


def test_open_redirect_positive_and_same_origin_negative_control_are_verified_without_following(mock_server):
    ctx=_context(mock_server+"/open-redirect?next=%2Fabout")
    async def run():
        try:
            await execute_open_redirect_tests(ctx)
            verify_open_redirect_tests(ctx)
        finally:
            await ctx.requester.close()
    asyncio.run(run())
    record=ctx.tests[0]
    assert record["status"]=="VERIFIED"
    assert record["observations"][0]["resolved_location"]==EXTERNAL_MARKER
    assert record["observations"][1]["resolved_location"]==mock_server+"/vf-internal-validation"
    assert all(urlsplit(exchange.url).hostname=="127.0.0.1" for exchange in ctx.requester.exchanges)
    assert len(ctx.findings)==1 and ctx.findings[0].status=="VERIFIED"
    assert ctx.findings[0].evidence[0].detail["test_id"]=="test-redirect"


def test_fixed_same_origin_redirect_does_not_verify(mock_server):
    ctx=_context(mock_server+"/safe-redirect?next=%2Fabout")
    async def run():
        try:
            await execute_open_redirect_tests(ctx)
            verify_open_redirect_tests(ctx)
        finally:
            await ctx.requester.close()
    asyncio.run(run())
    assert ctx.tests[0]["status"]=="CANDIDATE"
    assert ctx.findings==[]


def test_redirect_executor_does_not_send_without_active_mode(mock_server):
    ctx=_context(mock_server+"/open-redirect?next=%2Fabout")
    ctx.config.active_requested=False
    async def run():
        try: await execute_open_redirect_tests(ctx)
        finally: await ctx.requester.close()
    asyncio.run(run())
    assert ctx.tests==[]
    assert ctx.test_plan[0].status=="BLOCKED"
