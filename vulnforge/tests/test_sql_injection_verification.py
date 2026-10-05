import asyncio
from types import SimpleNamespace
from urllib.parse import urlsplit

from vulnforge.core.authorization import AuthorizationContext
from vulnforge.core.models import Endpoint, HttpExchange, Parameter, ScanContext, HypothesisRecord, PlannedTest
from vulnforge.core.profiles import get_profile
from vulnforge.core.store import Store
from vulnforge.engine.methodology import build_test_methodology
from vulnforge.engine.sql_injection_verification import (
    collect_sql_injection_candidates, execute_sql_injection_tests, verify_sql_injection_tests,
)
from vulnforge.engine.orchestrator import ScanConfig, ScanResult, run_scan
from vulnforge.http.client import Requester


def _auth(url, excluded=()):
    parsed=urlsplit(url)
    return AuthorizationContext(allowed_hosts=[parsed.hostname],allowed_ports=[parsed.port or (443 if parsed.scheme=="https" else 80)],
        allowed_methods=["GET"],excluded_params=list(excluded),profile_name="lab",
        allow_private=True,confirmed=True)


def _context(url):
    auth=_auth(url)
    config=SimpleNamespace(profile_name="lab",active_requested=True)
    ctx=ScanContext("scan-sqli",config,auth)
    ctx.requester=Requester(auth,get_profile("lab"),timeout=3)
    hypothesis_id="hyp-sqli"
    endpoint=urlsplit(url)
    safe_endpoint=f"{endpoint.scheme}://{endpoint.netloc}{endpoint.path}"
    ctx.hypotheses=[HypothesisRecord(hypothesis_id,"sql-injection-review","KEEP",
        endpoint=safe_endpoint,parameter="q",reason="Observed non-sensitive query parameter.")]
    ctx.test_plan=[PlannedTest("test-sqli",hypothesis_id,"sql-injection-validation",safe_endpoint,
        "GET",6,"LOW_READ_ONLY",True,"PLANNED",
        methodology=build_test_methodology("sql-injection-validation",safe_endpoint))]
    ctx._sql_injection_test_specs=[{"test_id":"test-sqli","hypothesis_id":hypothesis_id,
        "url":url,"parameter":"q","value":"shoe"}]
    return ctx


def test_sqli_candidate_selection_is_limited_to_scoped_non_sensitive_get_parameters():
    good=Endpoint("http://127.0.0.1/search?q=shoe","http://127.0.0.1/search?q",method="GET",status=200,scope_status="IN_SCOPE")
    good.params=[Parameter("q","query",good.url,method="GET",example="shoe")]
    token=Endpoint("http://127.0.0.1/search?access_token=abc","http://127.0.0.1/search?access_token",method="GET",status=200,scope_status="IN_SCOPE")
    token.params=[Parameter("access_token","query",token.url,method="GET",example="abc")]
    logout=Endpoint("http://127.0.0.1/logout?next=x","http://127.0.0.1/logout?next",method="GET",status=200,scope_status="IN_SCOPE")
    logout.params=[Parameter("next","query",logout.url,method="GET",example="x")]
    denied=_auth(good.url,excluded=("q",))
    assert collect_sql_injection_candidates(SimpleNamespace(endpoints={"good":good,"token":token,"logout":logout},authorization=denied))==[]
    allowed=_auth(good.url)
    candidates=collect_sql_injection_candidates(SimpleNamespace(endpoints={"good":good,"token":token,"logout":logout},authorization=allowed))
    assert len(candidates)==1 and candidates[0]["parameter"]=="q"
    assert candidates[0]["value"]=="shoe"


def test_sql_error_positive_requires_baseline_benign_control_and_repeatable_parser_error(mock_server):
    ctx=_context(mock_server+"/sqli/search?q=shoe")
    async def run():
        try:
            await execute_sql_injection_tests(ctx)
            verify_sql_injection_tests(ctx)
        finally:
            await ctx.requester.close()
    asyncio.run(run())
    record=ctx.tests[0]
    assert record["status"]=="CANDIDATE"
    # A parser error alone is insufficient for the new semantic verifier.
    # The fixture deliberately has no true/false query-result differential.
    assert record["reproduction_status"]=="CANDIDATE"
    assert record["impact_proven"] is False
    assert record["candidate_reason"] == "The bounded semantic verification contract was not satisfied."
    assert [item["kind"] for item in record["observations"]]==[
        "baseline",
        "benign-control",
        "boolean-true",
        "boolean-false",
        "boolean-true-repeat",
        "single-quote-probe",
    ]
    assert len(ctx.requester.exchanges)==6 and ctx.requester.budget.sent==6
    assert all(item.module=="sql-injection-validation" for item in ctx.requester.exchanges)
    assert ctx.findings==[]
    assert record["data_extraction_attempted"] is False and record["state_changes_attempted"] is False
    assert "shoe" not in str(record)


def test_generic_error_or_single_unrepeatable_database_error_does_not_verify(mock_server):
    ctx=_context(mock_server+"/sqli/safe?q=shoe")
    async def run():
        try:
            await execute_sql_injection_tests(ctx)
            verify_sql_injection_tests(ctx)
        finally:
            await ctx.requester.close()
    asyncio.run(run())
    assert ctx.tests[0]["status"]=="CANDIDATE"
    assert ctx.findings==[]


def test_sql_checks_do_not_send_without_explicit_active_mode(mock_server):
    ctx=_context(mock_server+"/sqli/search?q=shoe")
    ctx.config.active_requested=False
    async def run():
        try: await execute_sql_injection_tests(ctx)
        finally: await ctx.requester.close()
    asyncio.run(run())
    assert ctx.tests==[] and ctx.requester.budget.sent==0
    assert ctx.test_plan[0].status=="BLOCKED"


def test_sql_probe_exchange_bodies_and_query_values_are_never_persisted_with_plaintext_opt_in(tmp_path):
    config=ScanConfig(target="http://127.0.0.1/",profile_name="lab",store_sensitive_http=True)
    auth=AuthorizationContext(allowed_hosts=["127.0.0.1"],allowed_methods=["GET"],profile_name="lab",
        allow_private=True,confirmed=True)
    ctx=ScanContext("scan-sqli-redact",config,auth)
    exchange=HttpExchange(method="GET",url="http://127.0.0.1/search?q=original-secret",
        request_body="probe-secret",response_body="SQLSTATE[42000] confidential database detail",
        response_headers={"X-Client-Credential":"secret"},status=500,module="sql-injection-validation")
    ctx.requester=SimpleNamespace(exchanges=[exchange])
    store=Store(str(tmp_path/"sqli.db")); store.save_scan(ScanResult(context=ctx))
    saved=store.get_exchange(exchange.exchange_id)
    assert saved["request_body"]==saved["response_body"]==""
    assert "original-secret" not in str(saved) and "probe-secret" not in str(saved)
    assert "confidential database detail" not in str(saved)
    assert saved["sql_probe_bodies_stored"] is False and saved["sensitive_values_stored"] is False

    live=HttpExchange(method="GET",url="http://127.0.0.1/search?q=live-secret",
        request_body="live-probe",response_body="backend diagnostic",status=500,module="sql-injection-validation")
    store.record_exchange(ctx.scan_id,live.to_dict(),redact=False)
    live_saved=store.get_exchange(live.exchange_id)
    assert live_saved["request_body"]==live_saved["response_body"]==""
    assert "live-secret" not in str(live_saved) and "live-probe" not in str(live_saved)


def test_full_scan_validates_sqli_against_loopback_vulnerable_lab():
    from http.server import ThreadingHTTPServer
    from threading import Thread
    from labs.runtime import create_server

    server=create_server("high", host="127.0.0.1", port=0, patched=False)
    server.daemon_threads=True
    thread=Thread(target=server.serve_forever,daemon=True); thread.start()
    base=f"http://127.0.0.1:{server.server_port}"
    try:
        config=ScanConfig(target=base,profile_name="lab",test_profile="full",test_profile_explicit=True,
            active_requested=True,allowed_hosts=["127.0.0.1"],allowed_ports=[server.server_port],
            allow_private=True,authorization_confirmed=True,request_rate=20,request_budget=500)
        result=run_scan(config,_auth(base))
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=2)
    ctx=result.context
    plans=[plan for plan in ctx.test_plan if plan.test_type=="sql-injection-validation"]
    assert plans and all(plan.request_cost==6 for plan in plans)
    assert len(plans)<=3
    records=[test for test in ctx.tests if test.get("type")=="sql-injection-validation"]
    assert records and any(test["reproduction_status"]=="REPRODUCED" for test in records)
    assert any(test["status"]=="VERIFIED" for test in records)
    matrix=next(item for item in ctx.vulnerability_matrix if item["class_id"]=="sqli")
    assert matrix["supported"] and matrix["selected"]
    assert any(f.category=="sql-injection" and f.status=="VERIFIED" for f in ctx.findings)
