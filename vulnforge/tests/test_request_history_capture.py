import asyncio

from vulnforge.core.authorization import AuthorizationContext
from vulnforge.core.profiles import get_profile
from vulnforge.core.store import Store
from vulnforge.http.client import Requester


def test_history_contains_prepared_headers_cookies_and_full_redirect_hops(mock_server):
    async def run():
        auth=AuthorizationContext(allowed_hosts=["127.0.0.1"],profile_name="passive",allow_private=True,confirmed=True)
        requester=Requester(auth,get_profile("passive"))
        try:
            final=await requester.send("GET",mock_server+"/redirect",headers={
                "Cookie":"session=local-test-cookie","Authorization":"Bearer local-test-token"})
            assert final.status==200
            assert len(requester.exchanges)==2
            first,second=requester.exchanges
            assert first.status in (301,302,303,307,308)
            assert second.status==200
            names=[name.lower() for name,_ in first.request_header_items]
            assert {"host","user-agent","accept","cookie","authorization"}.issubset(set(names))
            assert any(name.lower()=="cookie" and value=="session=local-test-cookie"
                       for name,value in first.request_header_items)
            assert first.request_version.startswith("HTTP/")
            assert first.reason_phrase
            assert first.response_header_items
        finally:
            await requester.close()
    asyncio.run(run())


def test_plaintext_http_opt_in_is_explicit_and_default_redacts(tmp_path):
    store=Store(str(tmp_path/"history.db"))
    store.start_scan_record("scan-redacted","https://safe.example/","standard",1.0)
    store.start_scan_record("scan-plaintext","https://safe.example/","standard",2.0)
    exchange={"exchange_id":"exchange-redacted","method":"GET","url":"https://safe.example/",
        "request_headers":{"Cookie":"sid=secret-cookie","Authorization":"Bearer secret-token"},
        "request_header_items":[["Cookie","sid=secret-cookie"],["Authorization","Bearer secret-token"]],
        "request_body":"","status":200,"response_headers":{"set-cookie":"sid=secret-cookie"},
        "response_header_items":[["Set-Cookie","sid=secret-cookie"]],"response_body":"ok"}
    store.record_exchange("scan-redacted",exchange)
    raw=dict(exchange,exchange_id="exchange-plaintext")
    store.record_exchange("scan-plaintext",raw,redact=False)
    masked=store.get_exchange("exchange-redacted")
    revealed=store.get_exchange("exchange-plaintext")
    assert masked["request_headers"]["Cookie"]=="[REDACTED]"
    assert "secret-cookie" not in str(masked)
    assert revealed["request_headers"]["Cookie"]=="sid=secret-cookie"
    assert revealed["request_headers"]["Authorization"]=="Bearer secret-token"
    assert revealed["sensitive_values_stored"] is True
