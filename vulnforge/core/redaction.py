"""
VulnForge — automatic secret redaction (spec §45, §61).

Applied before anything is logged, persisted, or rendered: credentials,
tokens, session cookies, and key material are replaced with [REDACTED].
"""
from __future__ import annotations

import re
from typing import Any, Dict

REDACTED = "[REDACTED]"

# header names whose values are always sensitive
SENSITIVE_HEADERS = {
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "api-key", "x-auth-token", "x-access-token",
    "x-csrf-token", "x-xsrf-token", "x-session-token",
    "x-authenticated-principal", "x-lab-principal",
}

# query/body parameter names whose values are sensitive
SENSITIVE_PARAMS = re.compile(
    r"(passw(or)?d|passwd|secret|token|api[-_]?key|apikey|access[-_]?token|"
    r"refresh[-_]?token|auth|jwt|session[-_]?id|sess|private[-_]?key|client[-_]?secret|"
    r"email|phone|address|account[-_]?number|ssn|social[-_]?security)",
    re.I,
)

# value patterns that always look like secrets regardless of key name
_SECRET_VALUE_RES = [
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b"),      # JWT
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),                                                   # AWS access key
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),                                         # GitHub tokens
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),                                                # OpenAI-style keys
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[^-]*-----END", re.S),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{12,}\b", re.I),
]


def redact_headers(headers: Dict[str, str]) -> Dict[str, str]:
    out = {}
    for k, v in (headers or {}).items():
        out[k] = REDACTED if k.lower() in SENSITIVE_HEADERS else redact_text(str(v))
    return out


def redact_text(text: str) -> str:
    if not text:
        return text
    out = str(text)
    # Structured JSON is common in APIs; redact sensitive fields recursively.
    if out.lstrip().startswith(("{", "[")):
        try:
            import json
            parsed=json.loads(out)
            def scrub(value):
                if isinstance(value, dict):
                    return {k:(REDACTED if SENSITIVE_PARAMS.search(str(k)) or str(k).lower() in SENSITIVE_HEADERS else scrub(v)) for k,v in value.items()}
                if isinstance(value, list): return [scrub(v) for v in value]
                return value
            out=json.dumps(scrub(parsed),ensure_ascii=False,separators=(",",":"))
        except (ValueError,TypeError):
            pass
    for rx in _SECRET_VALUE_RES:
        out = rx.sub(REDACTED, out)
    # key=value /
    out = re.sub(
        r"(?i)\b(" + SENSITIVE_PARAMS.pattern + r")\s*[=:]\s*[^\s&;'\"<>]{1,512}",
        lambda m: f"{m.group(1)}={REDACTED}",
        out,
    )
    return out


def redact_url_query_values(url: str) -> str:
    """Mask every query value and fragment where browser state may ride in URLs."""
    if not url: return url
    from urllib.parse import urlsplit,urlunsplit,parse_qsl,urlencode
    try:
        parts=urlsplit(url)
        netloc=parts.netloc.rsplit("@",1)[-1]
        query=urlencode([(key,REDACTED) for key,_ in parse_qsl(parts.query,keep_blank_values=True)])
        fragment=REDACTED if parts.fragment else ""
        return urlunsplit((parts.scheme,netloc,parts.path,query,fragment))
    except Exception:
        return REDACTED


def redact_url(url: str) -> str:
    """Mask credentials and sensitive query parameters in a URL."""
    if not url:
        return url
    from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
    try:
        parts = urlsplit(url)
    except Exception:
        return redact_text(url)
    netloc = parts.hostname or ""
    if parts.port:
        netloc += f":{parts.port}"
    if parts.username or parts.password:
        netloc = f"{REDACTED}@{netloc}"
    try:
        q = parse_qsl(parts.query, keep_blank_values=True)
        q = [(k, REDACTED if SENSITIVE_PARAMS.search(k) else v) for k, v in q]
        query = urlencode(q)
    except Exception:
        query = parts.query
    return urlunsplit((parts.scheme, netloc, parts.path, query, parts.fragment))


def redact_any(value: Any) -> Any:
    """Recursively redact strings inside dicts/lists for safe persistence."""
    if isinstance(value, str):
        return redact_text(redact_url(value)) if "://" in value else redact_text(value)
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if isinstance(v, str) and (SENSITIVE_PARAMS.search(str(k)) or str(k).lower() in SENSITIVE_HEADERS):
                out[k] = REDACTED
            else:
                out[k] = redact_any(v)
        return out
    if isinstance(value, (list, tuple)):
        return [redact_any(v) for v in value]
    return value
