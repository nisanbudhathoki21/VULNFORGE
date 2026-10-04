"""
Tests for engine.login_flow using httpx.MockTransport — no real network
calls, no running lab server required. Follows the project convention
(asyncio.run inside a plain sync test) rather than pytest-asyncio, since
that dependency isn't part of this project.
"""
from __future__ import annotations

import asyncio

import pytest
import httpx

from vulnforge.engine.login_flow import LoginFlowConfig, LoginFlowError, perform_login

LOGIN_PAGE = """
<html><body>
<form method="post" action="/login">
  <input type="hidden" name="csrf_token" value="tok-abc123">
  <input name="username">
  <input name="password" type="password">
</form>
</body></html>
"""


def _handler_factory(expect_csrf=True, succeed=True):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/login":
            return httpx.Response(200, text=LOGIN_PAGE)
        if request.method == "POST" and request.url.path == "/login":
            form = dict(httpx.QueryParams(request.content.decode()))
            if expect_csrf and form.get("csrf_token") != "tok-abc123":
                return httpx.Response(400, text="missing or bad csrf token")
            if form.get("username") == "alice" and form.get("password") == "correct-horse":
                if succeed:
                    return httpx.Response(
                        302, headers={"Location": "/dashboard",
                                      "Set-Cookie": "session=sess-xyz; HttpOnly"},
                        text="",
                    )
            return httpx.Response(200, text="Invalid username or password")
        return httpx.Response(404)
    return handler


def test_login_success_extracts_csrf_and_session_cookie():
    async def go():
        transport = httpx.MockTransport(_handler_factory())
        config = LoginFlowConfig(
            login_url="https://target.example/login",
            username="alice",
            password="correct-horse",
            success_status=302,
        )
        async with httpx.AsyncClient(transport=transport) as client:
            return await perform_login(client, config)
    headers = asyncio.run(go())
    assert "session=sess-xyz" in headers["Cookie"]


def test_login_wrong_password_raises():
    async def go():
        transport = httpx.MockTransport(_handler_factory())
        config = LoginFlowConfig(
            login_url="https://target.example/login",
            username="alice",
            password="wrong-password",
            success_status=302,
        )
        async with httpx.AsyncClient(transport=transport) as client:
            await perform_login(client, config)
    with pytest.raises(LoginFlowError):
        asyncio.run(go())


def test_login_failure_text_takes_precedence():
    async def go():
        transport = httpx.MockTransport(_handler_factory())
        config = LoginFlowConfig(
            login_url="https://target.example/login",
            username="alice",
            password="wrong-password",
            failure_text="Invalid username or password",
        )
        async with httpx.AsyncClient(transport=transport) as client:
            await perform_login(client, config)
    with pytest.raises(LoginFlowError, match="failure_text"):
        asyncio.run(go())


def test_missing_csrf_rejected_by_server_surfaces_as_login_error():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, text="<html><body>no csrf field here</body></html>")
        return httpx.Response(400, text="missing or bad csrf token")

    async def go():
        transport = httpx.MockTransport(handler)
        config = LoginFlowConfig(
            login_url="https://target.example/login",
            username="alice",
            password="correct-horse",
        )
        async with httpx.AsyncClient(transport=transport) as client:
            await perform_login(client, config)
    with pytest.raises(LoginFlowError):
        asyncio.run(go())


def test_config_from_mapping_requires_fields():
    with pytest.raises(ValueError):
        LoginFlowConfig.from_mapping({"login_url": "https://x/login"})


def test_login_extracts_meta_csrf_and_xsrf_cookie():
    meta_page = '<html><head><meta name="csrf-token" content="meta-tok-999"></head><body></body></html>'

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, text=meta_page)
        if request.headers.get("X-CSRF-Token") != "meta-tok-999":
            return httpx.Response(403, text="missing meta csrf")
        return httpx.Response(
            302,
            headers=[
                ("Location", "/app"),
                ("Set-Cookie", "session=s1; Path=/; HttpOnly"),
                ("Set-Cookie", "XSRF-TOKEN=xsrf-cookie-777; Path=/"),
            ],
        )

    async def go():
        transport = httpx.MockTransport(handler)
        config = LoginFlowConfig(
            login_url="https://target.example/login",
            username="alice",
            password="correct-horse",
            success_status=302,
        )
        async with httpx.AsyncClient(transport=transport) as client:
            return await perform_login(client, config)

    headers = asyncio.run(go())
    assert "session=s1" in headers["Cookie"]
    assert headers["X-CSRF-Token"] == "xsrf-cookie-777"


def test_expand_authorization_specs_supports_multi_role_identities():
    from vulnforge.engine.verification import expand_authorization_specs

    auth_data = {
        "identities": {
            "owner": {"headers": {"X-Role": "owner"}},
            "manager": {"headers": {"X-Role": "manager"}},
            "auditor": {"headers": {"X-Role": "auditor"}},
            "guest": {"headers": {"X-Role": "guest"}},
        },
        "authorization_tests": [
            {
                "url": "/api/records/1",
                "owner_identity": "owner",
                "other_identities": ["manager", "auditor", "guest"],
                "owner_field": "owner",
                "owner_value": "owner",
                "identity_assertion": {
                    "header": "X-Principal",
                    "owner_value": "owner",
                    "other_values": {"manager": "manager", "auditor": "auditor", "guest": "guest"},
                },
                "sensitive_fields": ["secret"],
            }
        ],
    }
    expanded = expand_authorization_specs(auth_data)
    assert [item["other_identity"] for item in expanded] == ["manager", "auditor", "guest"]
    assert [item["identity_assertion"]["other_value"] for item in expanded] == ["manager", "auditor", "guest"]



def test_authorization_identity_resolver_prefers_identity_manager():
    from types import SimpleNamespace

    from vulnforge.auth.manager import IdentityManager
    from vulnforge.auth.models import Identity
    from vulnforge.engine.verification import (
        _resolve_authorization_identity_headers,
    )

    manager = IdentityManager()

    manager.register(
        Identity(
            identity_id="owner",
            label="owner",
            actor="alice",
            role="owner",
            headers={
                "X-Role": "manager-backed-owner",
                "X-Principal": "alice",
            },
        )
    )

    ctx = SimpleNamespace(
        identity_manager=manager,
        config=SimpleNamespace(
            auth_data={
                "identities": {
                    "owner": {
                        "headers": {
                            "X-Role": "legacy-owner",
                        }
                    }
                }
            }
        ),
    )

    headers = _resolve_authorization_identity_headers(ctx, "owner")

    assert headers == {
        "X-Role": "manager-backed-owner",
        "X-Principal": "alice",
    }

    # Returned headers must be a copy, not the registered Identity mapping.
    headers["X-Role"] = "mutated"

    registered = manager.get("owner")
    assert registered.headers["X-Role"] == "manager-backed-owner"
