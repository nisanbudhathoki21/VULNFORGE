"""Normalization, classification, redaction, rate-budget tests."""
import asyncio
import pytest

from vulnforge.engine.normalize import canonicalize, shape
from vulnforge.engine.classify import classify_parameter
from vulnforge.core.redaction import redact_headers, redact_text, redact_url, REDACTED
from vulnforge.core.ratelimit import RateLimiter, RequestBudget


# ---------------- normalize ----------------
def test_canonicalize_basics():
    assert canonicalize("HTTP://Example.COM:80/a/../b?b=2&a=1#frag") == \
        "http://example.com/b?a=1&b=2"


def test_canonicalize_drops_tracking():
    assert "utm_source" not in canonicalize("https://x.com/?a=1&utm_source=t&b=2")


def test_shape_dynamic_segments():
    assert shape("https://x.com/user/1") == shape("https://x.com/user/999")
    assert shape("https://x.com/user/1") != shape("https://x.com/user/alice")
    assert "{uuid}" in shape("https://x.com/d/550e8400-e29b-41d4-a716-446655440000")


def test_shape_query_names_not_values():
    assert shape("https://x.com/s?q=a") == shape("https://x.com/s?q=zzz")
    assert shape("https://x.com/s?q=a") != shape("https://x.com/s?p=a")


# ---------------- classify ----------------
def test_classification_roles():
    assert "redirect" in classify_parameter("next", "/home")
    assert "object_reference" in classify_parameter("user_id", "42")
    assert "identifier" in classify_parameter("order_id", "1007")
    assert "price_like" in classify_parameter("total_price", "19.99")
    assert "token_like" in classify_parameter("csrf_token", "abc")
    assert "tenant_id" in classify_parameter("workspace_id", "5")
    assert "url_value" in classify_parameter("callback", "https://x.example/hook")
    assert "filename" in classify_parameter("file", "report.pdf")


# ---------------- redaction ----------------
def test_redact_headers():
    out = redact_headers({"Authorization": "Bearer abc", "X-Test": "ok"})
    assert out["Authorization"] == REDACTED and out["X-Test"] == "ok"


def test_redact_jwt_in_text():
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c"
    assert jwt not in redact_text(f"token: {jwt}")
    assert REDACTED in redact_text(f"token: {jwt}")


def test_redact_url_params_and_creds():
    u = redact_url("https://user:pass@x.com/login?password=hunter2&q=shoes")
    assert "hunter2" not in u and "user:pass" not in u and "q=shoes" in u


# ---------------- budget ----------------
def test_request_budget_hard_ceiling():
    b = RequestBudget(2)
    assert b.consume()
    assert b.consume()
    assert not b.consume()


def test_rate_limiter_never_exceeds_a_sub_one_configured_rate():
    limiter=RateLimiter(requests_per_second=0.1,max_concurrency=2)
    assert limiter.current_rps==0.1
    limiter.report_status(429)
    assert 0.01<=limiter.current_rps<=0.1
    limiter.report_status(200)
    assert limiter.current_rps<=0.1
    with pytest.raises(ValueError,match="finite positive"):
        RateLimiter(requests_per_second=0)
    with pytest.raises(ValueError,match="max_concurrency"):
        RateLimiter(requests_per_second=1,max_concurrency=0)
