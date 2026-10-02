"""
VulnForge — pre-scan authenticated login flow (Phase 2).

Most real targets gate everything behind a session cookie obtained from a
POST'd login form, not a static bearer header. This module performs exactly
one bounded login attempt — GET the login page (to pick up a CSRF token if
the form has one), POST the credentials, confirm success — and returns the
resulting session as headers that the existing `identity_headers` mechanism
(ScanConfig.identity_headers → Requester) already knows how to carry on
every subsequent request for the rest of the scan.

This does not add a new trust boundary: it only ever talks to a URL that has
already passed the same scope/authorization gate as everything else
(the caller is responsible for validating `login_url` against the active
AuthorizationContext before calling `perform_login`, exactly like any other
in-scope URL).

Design constraints (consistent with the rest of the engine):
  * exactly one GET + one POST — no retry storms, no credential spraying
  * response bodies are size-capped before being parsed for a CSRF token
  * credentials are never logged; only redacted summaries are returned
  * failure raises LoginFlowError with a safe, non-credential-leaking reason
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Optional

import httpx

from ..core.redaction import redact_headers

MAX_LOGIN_PAGE_BYTES = 512_000

# Looks for a hidden input carrying a CSRF/anti-forgery token. Covers the
# common name variants without trying to be a full HTML parser.
_CSRF_INPUT_RE = re.compile(
    r"""<input[^>]+name=["'](?P<name>[^"']*(?:csrf|_token|authenticity_token|anti-?forgery)[^"']*)["'][^>]+value=["'](?P<value>[^"']*)["']""",
    re.IGNORECASE,
)
_CSRF_INPUT_RE_SWAPPED = re.compile(
    r"""<input[^>]+value=["'](?P<value>[^"']*)["'][^>]+name=["'](?P<name>[^"']*(?:csrf|_token|authenticity_token|anti-?forgery)[^"']*)["']""",
    re.IGNORECASE,
)
_CSRF_META_RE = re.compile(
    r"""<meta[^>]+name=["'](?P<name>csrf-token|_csrf|xsrf-token)["'][^>]+content=["'](?P<value>[^"']+)["']""",
    re.IGNORECASE,
)
_CSRF_META_RE_SWAPPED = re.compile(
    r"""<meta[^>]+content=["'](?P<value>[^"']+)["'][^>]+name=["'](?P<name>csrf-token|_csrf|xsrf-token)["']""",
    re.IGNORECASE,
)


class LoginFlowError(Exception):
    """Raised when the configured login attempt did not succeed."""


@dataclass
class LoginFlowConfig:
    login_url: str
    username: str
    password: str
    username_field: str = "username"
    password_field: str = "password"
    method: str = "POST"
    csrf_field: Optional[str] = None          # explicit field name, skips auto-detection
    extra_fields: Dict[str, str] = field(default_factory=dict)
    success_status: Optional[int] = None       # e.g. 302
    success_text: Optional[str] = None         # substring expected in the response on success
    failure_text: Optional[str] = None         # substring that, if present, means failure
    extra_headers: Dict[str, str] = field(default_factory=dict)

    @staticmethod
    def from_mapping(d: dict) -> "LoginFlowConfig":
        required = {"login_url", "username", "password"}
        missing = required - d.keys()
        if missing:
            raise ValueError(f"login flow config missing required field(s): {sorted(missing)}")
        return LoginFlowConfig(
            login_url=str(d["login_url"]),
            username=str(d["username"]),
            password=str(d["password"]),
            username_field=str(d.get("username_field", "username")),
            password_field=str(d.get("password_field", "password")),
            method=str(d.get("method", "POST")).upper(),
            csrf_field=(str(d["csrf_field"]) if d.get("csrf_field") else None),
            extra_fields={str(k): str(v) for k, v in dict(d.get("extra_fields", {})).items()},
            success_status=(int(d["success_status"]) if d.get("success_status") is not None else None),
            success_text=(str(d["success_text"]) if d.get("success_text") else None),
            failure_text=(str(d["failure_text"]) if d.get("failure_text") else None),
            extra_headers={str(k): str(v) for k, v in dict(d.get("extra_headers", {})).items()},
        )


def _find_csrf_token(html: str) -> Optional[str]:
    for rx in (_CSRF_INPUT_RE, _CSRF_INPUT_RE_SWAPPED, _CSRF_META_RE, _CSRF_META_RE_SWAPPED):
        m = rx.search(html)
        if m:
            return m.group("value")
    return None


async def perform_login(client: httpx.AsyncClient, config: LoginFlowConfig) -> Dict[str, str]:
    """
    Run one GET + one POST login attempt on an already-scope-approved URL.

    Returns a headers dict (e.g. `Cookie` and optional `X-CSRF-Token` header
    reflecting the session established on `client`'s cookie jar) suitable for
    merging into ScanConfig.identity_headers / Requester extra_headers.

    Raises LoginFlowError on any failure. Never raises on invalid credentials
    vs. network error differently — both are reported the same bounded way
    so the caller can't be used to oracle valid usernames.
    """
    csrf_value = None
    csrf_name = config.csrf_field
    meta_csrf_value = None

    try:
        get_resp = await client.get(config.login_url, headers=config.extra_headers)
    except httpx.HTTPError as ex:
        raise LoginFlowError(f"could not reach login page: {type(ex).__name__}") from ex

    body = get_resp.text[:MAX_LOGIN_PAGE_BYTES] if get_resp.content else ""
    if csrf_name is None:
        for rx in (_CSRF_INPUT_RE, _CSRF_INPUT_RE_SWAPPED):
            m = rx.search(body)
            if m:
                csrf_name, csrf_value = m.group("name"), m.group("value")
                break
        if csrf_value is None:
            for rx in (_CSRF_META_RE, _CSRF_META_RE_SWAPPED):
                m = rx.search(body)
                if m:
                    meta_csrf_value = m.group("value")
                    break
    else:
        m = re.search(
            rf"""name=["']{re.escape(csrf_name)}["'][^>]+value=["']([^"']*)["']""", body, re.IGNORECASE
        )
        if m:
            csrf_value = m.group(1)

    form: Dict[str, str] = {
        config.username_field: config.username,
        config.password_field: config.password,
        **config.extra_fields,
    }
    if csrf_name and csrf_value is not None:
        form[csrf_name] = csrf_value

    post_headers = dict(config.extra_headers)
    if meta_csrf_value and "X-CSRF-Token" not in post_headers:
        post_headers["X-CSRF-Token"] = meta_csrf_value

    try:
        if config.method == "POST":
            post_resp = await client.post(config.login_url, data=form, headers=post_headers)
        else:
            post_resp = await client.request(config.method, config.login_url, params=form, headers=post_headers)
    except httpx.HTTPError as ex:
        raise LoginFlowError(f"login request failed: {type(ex).__name__}") from ex

    _verify_success(post_resp, config)

    cookie_header = "; ".join(f"{c.name}={c.value}" for c in client.cookies.jar)
    if not cookie_header:
        raise LoginFlowError("login appeared to succeed but no session cookie was set")
    out: Dict[str, str] = {"Cookie": cookie_header}
    for c in client.cookies.jar:
        if c.name.lower() in {"xsrf-token", "csrftoken", "_csrf"}:
            out["X-CSRF-Token"] = c.value
            break
    if meta_csrf_value and "X-CSRF-Token" not in out:
        out["X-CSRF-Token"] = meta_csrf_value
    return out


def _verify_success(resp: httpx.Response, config: LoginFlowConfig) -> None:
    body = resp.text[:MAX_LOGIN_PAGE_BYTES] if resp.content else ""
    if config.failure_text and config.failure_text in body:
        raise LoginFlowError("login response matched the configured failure_text")
    if config.success_status is not None and resp.status_code != config.success_status:
        raise LoginFlowError(f"expected status {config.success_status}, got {resp.status_code}")
    if config.success_text is not None and config.success_text not in body:
        raise LoginFlowError("login response did not contain the configured success_text")
    if config.success_status is None and config.success_text is None:
        # No explicit success signal configured — fall back to "not an
        # obvious failure": 2xx/3xx and no failure_text match (checked above).
        if resp.status_code >= 400:
            raise LoginFlowError(f"login returned {resp.status_code} and no success criteria matched")


def describe(config: LoginFlowConfig, result_headers: Dict[str, str]) -> Dict[str, object]:
    """A redacted, loggable summary — never include raw credentials or cookie values."""
    return {
        "login_url": config.login_url,
        "username_field": config.username_field,
        "method": config.method,
        "csrf_detected": config.csrf_field is not None,
        "session_headers": redact_headers(result_headers),
    }
