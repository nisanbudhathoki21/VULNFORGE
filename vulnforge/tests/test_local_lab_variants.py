from http.server import ThreadingHTTPServer
import threading

import httpx
import pytest

from vulnforge.tests.lab_fixture import Handler


@pytest.fixture
def local_lab():
    server=ThreadingHTTPServer(("127.0.0.1",0),Handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown();server.server_close();thread.join(timeout=2)


def test_authorization_vulnerable_and_patched_fixtures_are_distinct(local_lab):
    vulnerable=httpx.get(local_lab+"/api/orders?id=1001",headers={"X-Lab-User":"bob"})
    patched=httpx.get(local_lab+"/api/orders-isolated?id=1001",headers={"X-Lab-User":"bob"})
    own=httpx.get(local_lab+"/api/orders-isolated?id=1001",headers={"X-Lab-User":"alice"})
    assert vulnerable.status_code==200 and vulnerable.json()["owner"]=="alice"
    assert patched.status_code==403 and patched.json()=={"error":"forbidden"}
    assert own.status_code==200 and own.json()["owner"]=="alice"


def test_sql_parser_error_vulnerable_and_patched_controls(local_lab):
    vulnerable=httpx.get(local_lab+"/search",params={"q":"probe'"})
    patched=httpx.get(local_lab+"/search-safe",params={"q":"probe'"})
    assert vulnerable.status_code==500 and "syntax error" in vulnerable.text
    assert patched.status_code==200 and "syntax error" not in patched.text


def test_cors_reflection_vulnerable_and_allowlist_control(local_lab):
    origin="https://research-marker.invalid"
    vulnerable=httpx.get(local_lab+"/cors/reflect",headers={"Origin":origin})
    patched=httpx.get(local_lab+"/cors/allowlist",headers={"Origin":origin})
    assert vulnerable.headers["access-control-allow-origin"]==origin
    assert vulnerable.headers["access-control-allow-credentials"]=="true"
    assert patched.headers["access-control-allow-origin"]=="https://trusted.example"
    assert patched.headers["access-control-allow-origin"]!=origin


def test_redirect_vulnerable_and_patched_control_do_not_follow_marker(local_lab):
    marker="https://research-marker.invalid/landing"
    vulnerable=httpx.get(local_lab+"/redirect",params={"next":marker},follow_redirects=False)
    patched=httpx.get(local_lab+"/safe-redirect",params={"next":marker},follow_redirects=False)
    assert vulnerable.status_code==302 and vulnerable.headers["location"]==marker
    assert patched.status_code==302 and patched.headers["location"]=="/"
