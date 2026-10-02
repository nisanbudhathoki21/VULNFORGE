"""
VulnForge — endpoint & parameter inventory builder (spec §8, §13, §14).

Consumes crawler output + robots/sitemap + JS-analysis signals and builds
the canonical Endpoint/Parameter model with dedup by endpoint *shape*.

Also computes endpoint intelligence hints:
  state_changing   — POST/PUT/PATCH/DELETE or a form
  auth_hint        — looks like a login/session surface
  interesting      — functionality worth a researcher's attention
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit, parse_qsl

from ..core.models import Endpoint, Parameter, HttpExchange
from .classify import classify_parameter
from .normalize import canonicalize, shape

_INTERESTING_PATH = re.compile(
    r"(/admin|/internal|/debug|/config|/manage|/console|/actuator|/api/|/graphql|"
    r"/upload|/import|/export|/download|/backup|/user|/account|/payment|/checkout|"
    r"/order|/invoice|/auth|/login|/register|/reset|/token|/oauth|/webhook|/callback)",
    re.I,
)
_AUTH_PATH = re.compile(r"(/login|/signin|/sign-in|/auth|/sso|/oauth|/session|/token)", re.I)
_STATE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def _param_from_entry(name: str, example: str, location: str, endpoint_url: str,
                      method: str, content_type: str, source: str) -> Parameter:
    classifications = classify_parameter(name, example, location)
    return Parameter(
        name=name, location=location, endpoint_url=endpoint_url, method=method,
        content_type=content_type, example=str(example)[:200],
        type_hint=_type_hint(example), classifications=classifications, source=source,
    )


def _type_hint(example: str) -> str:
    e = str(example).strip()
    if re.fullmatch(r"-?\d+", e):
        return "numeric"
    if e.lower() in ("true", "false"):
        return "boolean"
    if e.startswith("{") or e.startswith("["):
        return "json"
    return "string"


def make_endpoint(url: str, method: str = "GET", source: str = "crawl",
                  depth: int = 0, exchange: Optional[HttpExchange] = None) -> Endpoint:
    c = canonicalize(url)
    parts = urlsplit(c)
    ep = Endpoint(url=c, normalized=shape(c), method=method.upper(), path=parts.path or "/",
                  source=source, depth=depth)
    if exchange is not None:
        ep.status = exchange.status
        ep.content_type = exchange.header("content-type")
        ep.response_length = exchange.body_length
        ep.evidence_ids = [exchange.exchange_id]
        ep.response_hash = hashlib.sha256(
            (exchange.response_body or "")[:8192].encode("utf-8", "replace")).hexdigest()[:16]
    if parts.query:
        for k, v in parse_qsl(parts.query, keep_blank_values=True):
            ep.params.append(_param_from_entry(k, v, "query", ep.normalized, ep.method,
                                               ep.content_type, source))
    ep.state_changing = ep.method in _STATE_METHODS
    if _AUTH_PATH.search(ep.path):
        ep.auth_hint = "login-surface"
    return ep


def interesting_reason(path: str) -> str:
    m = _INTERESTING_PATH.search(path or "")
    return m.group(1) if m else ""


class InventoryBuilder:
    """Merges all discovery sources into one deduplicated inventory."""

    def __init__(self):
        self._by_key: Dict[str, Endpoint] = {}

    def add(self, ep: Endpoint) -> Endpoint:
        key = ep.key()
        if key in self._by_key:
            existing = self._by_key[key]
            known = {(p.name, p.location) for p in existing.params}
            for p in ep.params:
                if (p.name, p.location) not in known:
                    existing.params.append(p)
                    known.add((p.name, p.location))
            existing.evidence_ids=sorted(set(existing.evidence_ids+ep.evidence_ids))
            return existing
        self._by_key[key] = ep
        return ep

    # ------------------------------------------------------------------
    def from_crawler(self, crawl_result) -> List[Endpoint]:
        out = []
        for ex, parser in crawl_result.parsed:
            ep = make_endpoint(ex.url, ex.method or "GET", "crawl", exchange=ex)
            ep.title = (parser.title or "")[:200]
            out.append(self.add(ep))
            for form in parser.forms:
                fep = self._endpoint_from_form(ex.url, form)
                fep.evidence_ids = [ex.exchange_id]
                out.append(self.add(fep))
        # Inventory every successful in-scope crawler HTTP exchange, not only HTML
        # pages. JSON APIs, plain-text endpoints, and redirects are real observed
        # surfaces too; status/body differences remain observations, not findings.
        for outcome in getattr(crawl_result, "outcomes", []):
            ex = getattr(outcome, "exchange", None)
            if ex is None or getattr(ex, "error", "") or int(getattr(ex, "status", 0) or 0) <= 0:
                continue
            ep = make_endpoint(ex.url, ex.method or "GET", "crawl", exchange=ex)
            out.append(self.add(ep))
        return out

    def _endpoint_from_form(self, page_url: str, form: Dict[str, Any]) -> Endpoint:
        from urllib.parse import urljoin
        action = urljoin(page_url, form.get("action") or page_url)
        method = (form.get("method") or "GET").upper()
        ep = make_endpoint(action, method, "form", exchange=None)
        ep.state_changing = True
        ctype = form.get("enctype", "")
        location = "multipart" if "multipart" in ctype else (
            "json" if "json" in ctype else "form")
        if method == "GET":
            location = "query"
        for fld in form.get("fields", []):
            if (fld.get("type") or "").lower() in ("submit", "button", "image"):
                continue
            ep.params.append(_param_from_entry(
                fld["name"], fld.get("value", ""), location, ep.normalized,
                ep.method, ctype, "html-form"))
        return ep

    def from_url_list(self, urls: List[str], source: str) -> List[Endpoint]:
        return [self.add(make_endpoint(u, "GET", source)) for u in urls]

    # ------------------------------------------------------------------
    @property
    def endpoints(self) -> List[Endpoint]:
        return list(self._by_key.values())
