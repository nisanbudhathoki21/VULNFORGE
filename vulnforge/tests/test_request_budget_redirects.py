import asyncio
from dataclasses import replace
from vulnforge.core.authorization import AuthorizationContext
from vulnforge.core.profiles import get_profile
from vulnforge.http.client import Requester


def test_redirect_each_hop_gated_and_budgeted(mock_server):
    async def run():
        auth=AuthorizationContext(allowed_hosts=["127.0.0.1"],profile_name="passive",allow_private=True,confirmed=True)
        req=Requester(auth,get_profile("passive"))
        try:
            ex=await req.send("GET",mock_server+"/redirect")
            assert ex.status==200 and len(ex.redirect_chain)==1
            assert ex.redirect_chain[0]["redirect_type"]=="IN-SCOPE REDIRECT"
            assert req.budget.sent==2
            blocked=await req.send("GET",mock_server+"/external-redirect")
            assert blocked.status==302 and "redirect blocked" in (blocked.error or "")
            assert blocked.redirect_chain[0]["scope_status"].startswith("BLOCKED")
            assert req.budget.sent==3 # out-of-scope destination never consumes a request
        finally: await req.close()
    asyncio.run(run())


def test_requester_enforces_method_scope_before_consuming_budget(mock_server):
    async def run():
        auth=AuthorizationContext(allowed_hosts=["127.0.0.1"],profile_name="controlled-active",allow_private=True,confirmed=True)
        req=Requester(auth,get_profile("controlled-active"))
        try:
            refused=await req.send("POST",mock_server+"/authz/orders",body="{}")
            assert refused.status==0 and "allowed_methods" in refused.error
            assert req.budget.sent==0
            auth.allowed_methods.append("POST")
            allowed=await req.send("POST",mock_server+"/authz/orders",body="{}")
            assert allowed.status==501  # local fixture does not implement POST
            assert req.budget.sent==1
        finally: await req.close()
    asyncio.run(run())


def test_scope_expiry_while_waiting_at_limiter_blocks_before_network(mock_server,monkeypatch):
    import time
    async def run():
        auth=AuthorizationContext(allowed_hosts=["127.0.0.1"],profile_name="passive",allow_private=True,confirmed=True,
                                 expires_at=time.time()+60)
        req=Requester(auth,get_profile("passive"))
        original_acquire=req.limiter.acquire
        async def expire_after_acquire():
            await original_acquire()
            auth.expires_at=time.time()-1
        monkeypatch.setattr(req.limiter,"acquire",expire_after_acquire)
        try:
            exchange=await req.send("GET",mock_server+"/about")
            assert exchange.status==0 and "expired" in exchange.error
            assert req.budget.sent==0
        finally: await req.close()
    asyncio.run(run())


def test_response_body_is_streamed_under_configured_cap(mock_server):
    async def run():
        auth=AuthorizationContext(allowed_hosts=["127.0.0.1"],profile_name="passive",allow_private=True,confirmed=True)
        profile=replace(get_profile("passive"),max_response_bytes=1024)
        req=Requester(auth,profile)
        try:
            exchange=await req.send("GET",mock_server+"/large")
            assert exchange.status==200
            assert next((v for k,v in exchange.request_headers.items() if k.lower()=="accept-encoding"),"")=="identity"
            assert len(exchange.response_body.encode("utf-8")) < 1100
            assert "[response body truncated at 1024 bytes]" in exchange.response_body
        finally: await req.close()
    asyncio.run(run())
