"""
VulnForge — JavaScript research engine (spec §11).

Static analysis of JS bundles for discovery signals:
  absolute/relative URLs, /api paths, fetch()/XHR/axios/WebSocket/GraphQL
  usage, route-like strings, source-map references, config blobs, and
  secret-*looking* strings (emitted as SIGNALS with redacted values —
  a string is never a confirmed vulnerability; spec §11, §63).

Findings from this engine are discovery signals; plugins may later turn a
subset into verified findings (e.g. an actually-exposed .git directory).
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Set, Tuple
from urllib.parse import urljoin

from ..core.models import Signal
from ..core.redaction import REDACTED

_URL_RE = re.compile(r"""https?://[^\s"'`<>\\)]+""", re.I)
_ABS_PATH_RE = re.compile(r"""(?<![\w/.-])(/[A-Za-z0-9._~/-]{2,120})(?![\w/.-])""")
_FETCH_RE = re.compile(r"""\bfetch\s*\(\s*['"`]([^'"`]+)['"`]""")
_XHR_RE = re.compile(r"""\.open\s*\(\s*['"`](GET|POST|PUT|PATCH|DELETE|HEAD)['"`]\s*,\s*['"`]([^'"`]+)['"`]""", re.I)
_AXIOS_RE = re.compile(r"""axios\s*\.\s*(get|post|put|patch|delete)\s*\(\s*['"`]([^'"`]+)['"`]""", re.I)
_WS_RE = re.compile(r"""(wss?://[^\s"'`<>]+)""", re.I)
_GRAPHQL_RE = re.compile(r"""(/[A-Za-z0-9._~-]*graphql[A-Za-z0-9._~/-]*)""", re.I)
_SOURCEMAP_RE = re.compile(r"sourceMappingURL=([^\s*]+)")
_ROUTE_RE = re.compile(r"""(?:path|route|url)\s*[:=]\s*['"](/[A-Za-z0-9._~:{}-]{1,120})['"]""")
_SPA_NAV_RE = re.compile(
    r"""(?:<Route[^>]+path\s*=\s*|(?:router\.push|router\.replace|navigate|history\.(?:push|replace)State)\s*\([^)]*?)['"](/[A-Za-z0-9._~:/\[\]-]{1,120})['"]""",
    re.I,
)
_GQL_OP_RE = re.compile(
    r"""\b(?:query|mutation)\s+([A-Za-z_][A-Za-z0-9_]{1,63})\b|operationName\s*[:=]\s*['"]([A-Za-z_][A-Za-z0-9_]{1,63})['"]"""
)
_JS_PARAM_GET_RE = re.compile(
    r"""(?:searchParams|urlParams|params|query)\.(?:get|getAll|has|set|append)\s*\(\s*['"]([A-Za-z0-9_.-]{1,64})['"]\s*\)"""
)
_JS_PARAMS_OBJ_RE = re.compile(
    r"""\b(?:params|query|searchParams)\s*:\s*\{([^{}]{1,400})\}"""
)
_JS_OBJ_KEY_RE = re.compile(r"""(?:['"]([A-Za-z_][A-Za-z0-9_.-]{1,48})['"]|([A-Za-z_][A-Za-z0-9_]{1,48}))\s*:""")


def extract_js_parameters(code: str) -> Set[str]:
    """Mine query/API parameter names referenced in JavaScript bundles."""
    names: Set[str] = set()
    for m in _JS_PARAM_GET_RE.finditer(code):
        names.add(m.group(1))
    for m in _JS_PARAMS_OBJ_RE.finditer(code):
        block = m.group(1)
        for km in _JS_OBJ_KEY_RE.finditer(block):
            key = km.group(1) or km.group(2)
            if key and key not in {"true", "false", "null", "undefined", "http", "https"}:
                names.add(key)
    return names

_INTERESTING = re.compile(
    r"(/api/|/graphql|/admin|/internal|/debug|/upload|/export|/download|/user|/account|/payment|/auth)",
    re.I,
)

_SECRETISH = [
    ("aws_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("private_key_block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("generic_assignment", re.compile(
        r"""(?:api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|secret|password)\s*[:=]\s*['"]([A-Za-z0-9/_+\-.]{8,})['"]""", re.I)),
]

_PATH_NOISE = re.compile(
    r"^/(assets?|static|dist|node_modules|img|images|css|fonts?|js)/.*\.(css|png|jpe?g|gif|svg|ico|woff2?|ttf|map)$",
    re.I,
)


def analyze_js(source_name: str, code: str, page_url: str = "") -> Tuple[List[Signal], Set[str]]:
    """Returns (signals, endpoint_candidates)."""
    signals: List[Signal] = []
    candidates: Set[str] = set()

    for m in _URL_RE.finditer(code):
        u = m.group(0).rstrip(".,;]\"'")
        candidates.add(u)
        if _INTERESTING.search(u):
            signals.append(Signal("js_endpoint", f"interesting URL in JS: {u}",
                                  source=source_name, url=u))

    path_hits: Set[str] = set()
    for rx, kind in ((_FETCH_RE, "fetch"), (_XHR_RE, "xhr"), (_AXIOS_RE, "axios")):
        for m in rx.finditer(code):
            target = m.group(m.lastindex)  # path is the last group
            path_hits.add(target)
    for m in _ABS_PATH_RE.finditer(code):
        p = m.group(1)
        if _PATH_NOISE.match(p):
            continue
        if _INTERESTING.search(p) or p.startswith(("/api", "/v1", "/v2", "/graphql")):
            path_hits.add(p)
    for m in _ROUTE_RE.finditer(code):
        path_hits.add(m.group(1))
    for m in _SPA_NAV_RE.finditer(code):
        raw_route = m.group(1)
        clean_route = re.sub(r":([A-Za-z0-9_]+)|\[([A-Za-z0-9_]+)\]", "1", raw_route)
        path_hits.add(clean_route)
        signals.append(Signal("spa_route", f"SPA client route in JS: {raw_route}",
                              source=source_name, severity_hint="info"))
    for m in _GRAPHQL_RE.finditer(code):
        path_hits.add(m.group(1))
        signals.append(Signal("graphql_hint", f"GraphQL endpoint hint: {m.group(1)}",
                              source=source_name, severity_hint="medium"))
    for m in _GQL_OP_RE.finditer(code):
        op_name = m.group(1) or m.group(2)
        if op_name:
            signals.append(Signal("graphql_operation", f"GraphQL operation in JS: {op_name}",
                                  source=source_name, severity_hint="info"))
    for param_name in sorted(extract_js_parameters(code)):
        signals.append(Signal("js_parameter", f"parameter mined from JS: {param_name}",
                              source=source_name, severity_hint="info"))

    for p in sorted(path_hits):
        if page_url:
            candidates.add(urljoin(page_url, p))
        if _INTERESTING.search(p):
            signals.append(Signal("js_path", f"interesting path in JS: {p}", source=source_name))

    for m in _WS_RE.finditer(code):
        signals.append(Signal("websocket_hint", f"WebSocket URL: {m.group(1)}",
                              source=source_name, severity_hint="medium"))

    for m in _SOURCEMAP_RE.finditer(code):
        signals.append(Signal("source_map", f"source map reference: {m.group(1)}",
                              source=source_name, severity_hint="low"))

    for name, rx in _SECRETISH:
        for m in rx.finditer(code):
            # Never echo the secret itself — contextual proof only.
            line_start = code.rfind("\n", 0, m.start()) + 1
            line_end = code.find("\n", m.end())
            if line_end == -1:
                line_end = len(code)
            line = code[line_start:line_end].strip()
            secret_span = m.group(1) if (m.groups() and m.group(1)) else m.group(0)
            line = line.replace(secret_span, REDACTED)
            line = re.sub(r"['\"][A-Za-z0-9/_+\-.=]{8,}['\"]", f"'{REDACTED}'", line)
            signals.append(Signal(
                "secret_like",
                f"secret-looking {name} in JS (value redacted): `{line[:140]}`",
                source=source_name, severity_hint="high"))

    return signals, candidates
