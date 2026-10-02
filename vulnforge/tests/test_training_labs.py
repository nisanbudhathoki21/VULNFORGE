from __future__ import annotations

import http.client
import json
import threading
from urllib.parse import urlencode

import pytest

from labs.runtime import LEVELS, create_server


@pytest.fixture
def lab_server(request):
    level, patched = request.param
    server = create_server(level, "127.0.0.1", 0, patched)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def fetch(server, path, headers=None, method="GET", body=None):
    conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=2)
    payload = urlencode(body or {}) if isinstance(body, dict) else body
    request_headers = dict(headers or {})
    if isinstance(body, dict):
        request_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
    conn.request(method, path, body=payload, headers=request_headers)
    response = conn.getresponse()
    data = response.read()
    result = (response.status, dict(response.getheaders()), data)
    conn.close()
    return result


@pytest.mark.parametrize("lab_server", [("critical", False)], indirect=True)
def test_critical_lab_has_local_synthetic_scenarios_and_no_real_execution(lab_server):
    status, _, body = fetch(lab_server, "/api/password-reset?email=alice%40example.test")
    token = json.loads(body)["token"]
    status, _, body = fetch(lab_server, "/api/reset-password", method="POST", body={"token": token, "password": "new-local-only"})
    assert status == 200 and json.loads(body)["password_updated_in_memory"] is True
    status, headers, _ = fetch(lab_server, "/login", method="POST", body={"email": "alice@example.test", "password": "new-local-only"})
    assert status == 303 and "lab_session=" in headers["Set-Cookie"]

    status, _, body = fetch(lab_server, "/api/admin/settings")
    assert status == 200
    assert json.loads(body)["owner"] == "admin"

    status, _, body = fetch(lab_server, "/api/runner?task=health%3Bwhoami")
    payload = json.loads(body)
    assert status == 200
    assert payload["os_process_started"] is False
    assert "no command was run" in payload["output"]

    status, _, body = fetch(lab_server, "/api/fetch?url=http%3A%2F%2Finternal.mock%2Fmetadata")
    payload = json.loads(body)
    assert status == 200
    assert payload["network_access"] is False

    status, _, body = fetch(lab_server, "/api/fetch?url=http%3A%2F%2F127.0.0.1%3A1%2F")
    assert status == 403
    assert "no network request" in json.loads(body)["error"]


@pytest.mark.parametrize("lab_server", [("critical", True)], indirect=True)
def test_critical_patched_control_blocks_anonymous_admin_and_hides_reset_token(lab_server):
    status, _, _ = fetch(lab_server, "/api/admin/settings")
    assert status == 403
    status, _, body = fetch(lab_server, "/api/password-reset?email=alice%40example.test")
    assert status == 202
    assert "token" not in json.loads(body)
    status, _, body = fetch(lab_server, "/api/reset-password", method="POST", body={"token": "local-reset-alice", "password": "attacker-local"})
    assert status == 400
    status, _, _ = fetch(lab_server, "/login", method="POST", body={"email": "alice@example.test", "password": "alice-lab-only"})
    assert status == 303


@pytest.mark.parametrize("lab_server", [("high", False)], indirect=True)
def test_high_lab_models_cross_tenant_objects_and_bounded_sqli(lab_server):
    status, headers, body = fetch(lab_server, "/api/orders?id=1001", {"X-Lab-User": "alice"})
    assert status == 200 and json.loads(body)["owner"] == "alice"
    status, _, body = fetch(lab_server, "/api/orders?id=1002", {"X-Lab-User": "bob"})
    assert status == 200 and json.loads(body)["owner"] == "bob"
    status, _, body = fetch(lab_server, "/api/orders?id=1002", {"X-Lab-User": "alice"})
    assert status == 200 and json.loads(body)["tenant"] == "globex"
    status, _, body = fetch(lab_server, "/api/orders?id=1001", {"X-Lab-User": "bob"})
    assert status == 200 and json.loads(body)["tenant"] == "acme"
    assert headers["X-Lab-Principal"] == "alice"

    status, _, body = fetch(lab_server, "/api/documents/D-ACME-01", {"X-Lab-User": "bob"})
    assert status == 200 and json.loads(body)["tenant"] == "acme"
    status, _, body = fetch(lab_server, "/api/search?q=%27")
    assert status == 500 and "parser" in json.loads(body)["error"]
    status, _, body = fetch(lab_server, "/api/file?name=..%2F..%2Fetc%2Fpasswd")
    assert status == 200 and "Synthetic" in json.loads(body)["file"]


@pytest.mark.parametrize("lab_server", [("high", True)], indirect=True)
def test_high_patched_control_enforces_tenant_role_and_query_boundaries(lab_server):
    status, _, _ = fetch(lab_server, "/api/orders?id=1001", {"X-Lab-User": "bob"})
    assert status == 403
    status, _, _ = fetch(lab_server, "/api/documents/D-ACME-01", {"X-Lab-User": "bob"})
    assert status == 403
    status, _, _ = fetch(lab_server, "/api/admin/users", {"X-Lab-User": "alice"})
    assert status == 403
    status, _, body = fetch(lab_server, "/api/search?q=%27")
    assert status == 200 and json.loads(body)["results"] == []
    status, _, _ = fetch(lab_server, "/api/file?name=..%2F..%2Fetc%2Fpasswd")
    assert status == 404


@pytest.mark.parametrize("lab_server", [("medium", False)], indirect=True)
def test_medium_lab_has_bounded_cors_redirect_xss_and_csrf_scenarios(lab_server):
    status, headers, _ = fetch(lab_server, "/api/public", {"Origin": "https://attacker.invalid"})
    assert status == 200
    assert headers["Access-Control-Allow-Origin"] == "https://attacker.invalid"
    assert headers["Access-Control-Allow-Credentials"] == "true"

    status, headers, _ = fetch(lab_server, "/redirect?next=https%3A%2F%2Fexample.invalid%2Flanding")
    assert status == 302 and headers["Location"] == "https://example.invalid/landing"

    status, _, body = fetch(lab_server, "/search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E")
    assert status == 200 and b"<script>alert(1)</script>" in body

    status, login_headers, _ = fetch(lab_server, "/login", method="POST", body={"email": "alice@example.test", "password": "alice-lab-only"})
    assert status == 303
    session_cookie = login_headers["Set-Cookie"].split(";", 1)[0]
    status, _, payload = fetch(lab_server, "/api/settings/email", {"Cookie": session_cookie}, method="POST", body={"email": "new@example.test"})
    assert status == 200 and json.loads(payload)["persisted"] is False


@pytest.mark.parametrize("lab_server", [("medium", True)], indirect=True)
def test_medium_patched_control_escapes_and_enforces_boundaries(lab_server):
    status, headers, _ = fetch(lab_server, "/api/public", {"Origin": "https://attacker.invalid"})
    assert status == 200 and "Access-Control-Allow-Origin" not in headers
    status, headers, _ = fetch(lab_server, "/redirect?next=https%3A%2F%2Fexample.invalid%2Flanding")
    assert status == 302 and headers["Location"] == "/dashboard"
    status, _, body = fetch(lab_server, "/search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E")
    assert status == 200 and b"&lt;script&gt;" in body

    status, headers, _ = fetch(lab_server, "/login", method="POST", body={"email": "alice@example.test", "password": "alice-lab-only"})
    assert status == 303
    session_cookie = headers["Set-Cookie"].split(";", 1)[0]
    status, page_headers, body = fetch(lab_server, "/", {"Cookie": session_cookie})
    assert status == 200 and page_headers["X-Frame-Options"] == "DENY"
    status, _, settings_page = fetch(lab_server, "/settings", {"Cookie": session_cookie})
    assert status == 200
    import re
    csrf = re.search(rb"name='csrf_token' value='([^']+)'", settings_page).group(1).decode()
    status, _, _ = fetch(lab_server, "/api/settings/email", {"Cookie": session_cookie}, method="POST", body={"email": "new@example.test"})
    assert status == 403
    status, _, payload = fetch(lab_server, "/api/settings/email", {"Cookie": session_cookie}, method="POST", body={"email": "new@example.test", "csrf_token": csrf})
    assert status == 200 and json.loads(payload)["persisted"] is False


def test_lab_ports_and_bind_policy():
    assert {name: info["port"] for name, info in LEVELS.items()} == {"critical": 9001, "high": 9002, "medium": 9003}
    with pytest.raises(ValueError, match="loopback"):
        create_server("critical", "0.0.0.0", 0)
