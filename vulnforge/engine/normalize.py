"""
VulnForge — URL canonicalization & endpoint normalization (spec §3, §9).

Two jobs:
  canonicalize(url)  — one true form per resource (scheme/host/port/path/query)
  shape(url)         — dynamic-segment-normalized form so /user/1 and /user/2
                       deduplicate into /user/{id} (spec §9)
"""
from __future__ import annotations

import re
from typing import Dict
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

_TRACKING_PARAMS = re.compile(
    r"^(utm_[a-z]+|fbclid|gclid|mc_cid|mc_eid|igshid|ref|_ga|_gl|yclid|dclid|wbraid|gbraid)$",
    re.I,
)

_DYNAMIC_RES = [
    (re.compile(r"^\d+$"), "{int}"),
    (re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I), "{uuid}"),
    (re.compile(r"^[0-9a-f]{24,64}$", re.I), "{hex}"),
    (re.compile(r"^\d{4}-\d{2}(-\d{2})?$"), "{date}"),
    (re.compile(r"^[A-Za-z0-9_-]{32,}$"), "{token}"),
]

_DEFAULT_PORTS = {"http": 80, "https": 443}


def canonicalize(url: str, drop_tracking: bool = True) -> str:
    """Deterministic canonical form used for dedup and scope display."""
    parts = urlsplit(url.strip())
    scheme = (parts.scheme or "http").lower()
    host = (parts.hostname or "").lower()
    if not host:
        return url.strip()
    port = parts.port
    netloc = host
    if port and port != _DEFAULT_PORTS.get(scheme):
        netloc = f"{host}:{port}"
    # path: collapse //, remove trailing slash except root, resolve . / ..
    path = parts.path or "/"
    segments = []
    for seg in path.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if segments:
                segments.pop()
            continue
        segments.append(seg)
    path = "/" + "/".join(segments)
    if parts.path.endswith("/") and path != "/":
        path += "/"
    # query: drop tracking params, sort
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    if drop_tracking:
        pairs = [(k, v) for k, v in pairs if not _TRACKING_PARAMS.match(k)]
    pairs.sort(key=lambda kv: (kv[0], kv[1]))
    query = urlencode(pairs)
    return urlunsplit((scheme, netloc, path, query, ""))  # fragment never sent


def normalize_dynamic_segment(seg: str) -> str:
    for rx, token in _DYNAMIC_RES:
        if rx.match(seg):
            return token
    return seg


def shape(url: str) -> str:
    """Endpoint-shape key: dynamic path segments replaced by type tokens,
    query reduced to sorted parameter NAMES (values ignored)."""
    c = canonicalize(url)
    parts = urlsplit(c)
    segs = [normalize_dynamic_segment(s) for s in (parts.path or "/").split("/") if s]
    path = "/" + "/".join(segs)
    names = sorted({k for k, _v in parse_qsl(parts.query, keep_blank_values=True)})
    query = "&".join(names)
    port_str = f":{parts.port}" if parts.port and parts.port != _DEFAULT_PORTS.get(parts.scheme) else ""
    return urlunsplit((parts.scheme, (parts.hostname or "") + port_str, path, query, ""))
