import asyncio
from types import SimpleNamespace

from vulnforge.core.authorization import AuthorizationContext
from vulnforge.core.models import HttpExchange
from vulnforge.core.profiles import get_profile
from vulnforge.core.store import Store
from vulnforge.engine.browser_workflow import BrowserWorkflowRunner, plan_browser_workflows
from vulnforge.engine.orchestrator import ScanConfig, ScanResult


class _Request:
    def __init__(self,url,method="GET",resource_type="document"):
        self.url=url; self.method=method; self.resource_type=resource_type
    async def all_headers(self): return {"accept":"text/html"}


class _Route:
    def __init__(self,request): self.request=request; self.fulfilled=None; self.aborted=False
    async def abort(self): self.aborted=True
    async def fulfill(self,**kwargs): self.fulfilled=kwargs


def _auth(host="127.0.0.1",methods=("GET",)):
    return AuthorizationContext(allowed_hosts=[host],allowed_methods=list(methods),profile_name="lab",
        allow_private=True,confirmed=True)


def test_browser_workflow_planning_is_bounded_scoped_and_dependency_gated():
    auth=_auth()
    specs=[{"workflow_id":"settings","start_url":"/","max_requests":5,
        "steps":[{"action":"navigate","url":"/settings"},{"action":"assert_selector","selector":"main"}]},
        {"workflow_id":"outside","start_url":"https://outside.example/","max_requests":2,"steps":[]}]
    plans,runnable,reserved,errors=plan_browser_workflows(specs,"http://127.0.0.1/",auth,
        can_run=True,available_requests=10,browser_available=False)
    assert not runnable and reserved==0 and not errors
    assert [item.status for item in plans]==["BLOCKED","BLOCKED"]
    assert all("Playwright" in item.methodology["planning_note"] for item in plans[:1])
    available,good,used,_=plan_browser_workflows(specs[:1],"http://127.0.0.1/",auth,
        can_run=True,available_requests=10,browser_available=True)
    assert available[0].status=="PLANNED" and len(good)==1 and used==5
    too_large=[{"workflow_id":"bad","start_url":"/","max_requests":21,"steps":[]}]
    assert plan_browser_workflows(too_large,"http://127.0.0.1/",auth,
        can_run=True,available_requests=30,browser_available=True)[3]


def test_browser_http_route_uses_requester_and_blocks_writes_and_external_targets(mock_server):
    auth=_auth()
    from vulnforge.http.client import Requester
    requester=Requester(auth,get_profile("lab"),timeout=3)
    runner=BrowserWorkflowRunner(requester,auth,{"workflow_id":"route-test","max_requests":6})
    async def run():
        try:
            in_scope=_Route(_Request(mock_server+"/about"))
            await runner.handle_route(in_scope)
            post=_Route(_Request(mock_server+"/about","POST"))
            await runner.handle_route(post)
            outside=_Route(_Request("https://outside.example/"))
            await runner.handle_route(outside)
            redirect=_Route(_Request(mock_server+"/external-redirect"))
            await runner.handle_route(redirect)
            redirected=_Route(_Request("https://out-of-scope.example/"))
            await runner.handle_route(redirected)
            return in_scope,post,outside,redirect,redirected,runner
        finally:
            await requester.close()
    in_scope,post,outside,redirect,redirected,runner=asyncio.run(run())
    assert in_scope.fulfilled["status"]==200
    assert post.aborted and outside.aborted and redirected.aborted
    assert redirect.fulfilled["status"]==302
    assert all(ex.module=="browser-workflow" for ex in requester.exchanges)
    denied=[ex for ex in requester.exchanges if ex.error and "scope-denied" in ex.error]
    assert len(denied)==2 # requests were rejected by Requester before network transmission
    assert requester.budget.sent==2
    assert any(item["method"]=="POST" for item in runner.blocked)


def test_browser_route_aborts_binary_assets_and_attachment_downloads():
    auth=_auth()
    from vulnforge.http.client import Requester
    requester=Requester(auth,get_profile("lab"),timeout=1)
    async def fake_send(method,url,**kwargs):
        if "/asset" in url:
            return HttpExchange(method=method,url=url,status=200,
                response_headers={"Content-Type":"application/octet-stream"},response_body="binary",
                module="browser-workflow")
        return HttpExchange(method=method,url=url,status=200,
            response_headers={"Content-Type":"text/html","Content-Disposition":"attachment; filename=x.zip"},
            response_body="download",module="browser-workflow")
    requester.send=fake_send
    runner=BrowserWorkflowRunner(requester,auth,{"workflow_id":"asset-test","max_requests":3})
    async def run():
        asset=_Route(_Request("http://127.0.0.1/asset"))
        download=_Route(_Request("http://127.0.0.1/download"))
        await runner.handle_route(asset); await runner.handle_route(download)
        return asset,download
    asset,download=asyncio.run(run())
    assert asset.aborted and download.aborted
    assert [item["reason"] for item in runner.blocked]==["binary response blocked","download response blocked"]
    assert not runner.exchange_ids


def test_browser_workflow_exchanges_force_redaction_and_body_omission_even_when_opted_out(tmp_path):
    from vulnforge.core.models import ScanContext

    config=ScanConfig(target="http://127.0.0.1/",profile_name="lab",store_sensitive_http=True)
    auth=AuthorizationContext(allowed_hosts=["127.0.0.1"],allowed_methods=["GET"],profile_name="lab",
        allow_private=True,confirmed=True)
    ctx=ScanContext("scan-browser-redact",config,auth)
    exchange=HttpExchange(method="GET",url="http://127.0.0.1/?workflow_ticket=plaintext-secret#session-fragment",
        request_headers={"Cookie":"session=plaintext-secret","X-Custom-Auth":"plaintext-secret"},
        response_headers={"Set-Cookie":"sid=plaintext-secret","X-Session-Key":"plaintext-secret","X-Client-Credential":"plaintext-secret"},
        request_body="token=plaintext-secret",response_body="account-private-data",status=200,module="browser-workflow")
    ctx.requester=SimpleNamespace(exchanges=[exchange])
    store=Store(str(tmp_path/"browser.db")); store.save_scan(ScanResult(context=ctx))
    saved=store.get_exchange(exchange.exchange_id)
    encoded=str(saved)
    assert saved["request_body"]==saved["response_body"]==""
    assert saved["request_headers"]["Cookie"]=="[REDACTED]"
    assert saved["request_headers"]["X-Custom-Auth"]=="[REDACTED]"
    assert saved["response_headers"]["Set-Cookie"]=="[REDACTED]"
    assert saved["response_headers"]["X-Session-Key"]=="[REDACTED]"
    assert saved["response_headers"]["X-Client-Credential"]=="[REDACTED]"
    assert saved["sensitive_values_stored"] is False
    assert "plaintext-secret" not in encoded and "session-fragment" not in encoded and "account-private-data" not in encoded

    live=HttpExchange(method="GET",url="http://127.0.0.1/live?flow=plaintext-secret#browser-session",
        request_headers={"X-Session-Token":"plaintext-secret"},response_headers={"X-Client-Credential":"plaintext-secret"},
        request_body="plaintext-secret",response_body="account-private-data",status=200,module="browser-workflow")
    store.record_exchange(ctx.scan_id,live.to_dict(),redact=False)
    live_saved=store.get_exchange(live.exchange_id)
    assert live_saved["request_body"]==live_saved["response_body"]==""
    assert live_saved["request_headers"]["X-Session-Token"]=="[REDACTED]"
    assert live_saved["response_headers"]["X-Client-Credential"]=="[REDACTED]"
    assert "plaintext-secret" not in str(live_saved) and "account-private-data" not in str(live_saved)
