"""HTTP response-derived live-service classification.

A received HTTP response demonstrates a responding endpoint regardless of its
status. Missing HTTP responses are classified conservatively: only an explicit
connection refusal is labeled DEAD; other transport failures remain UNKNOWN.
"""
from __future__ import annotations

from typing import Any, Iterable

_REDIRECTS = {301, 302, 303, 307, 308}


def classify_live_state(status: Any, error: str = "", redirect_chain: Iterable[Any] = ()) -> str:
    try:
        code = int(status or 0)
    except (TypeError, ValueError):
        code = 0
    if list(redirect_chain or ()) or code in _REDIRECTS:
        return "REDIRECT"
    if code == 401:
        return "LIVE_AUTH_REQUIRED"
    if code == 403:
        return "LIVE_FORBIDDEN"
    if code == 429:
        return "LIVE_RATE_LIMITED"
    if 500 <= code <= 599:
        return "LIVE_SERVER_ERROR"
    if 100 <= code <= 599:
        # Includes 404/405: an HTTP response proves a service answered.
        return "LIVE"
    low = str(error or "").lower()
    if "timeout" in low or "timed out" in low:
        return "TIMEOUT"
    if "connection refused" in low or "connect call failed" in low and "111" in low:
        return "DEAD"
    return "UNKNOWN"
