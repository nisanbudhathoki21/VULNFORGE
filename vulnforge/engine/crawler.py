"""Bounded, scope-aware asynchronous HTTP crawler.

Each scheduled URL ends in an explicit state. Expected network, parser,
scope, budget, timeout, and cancellation outcomes are recorded without
mistaking BaseException (notably asyncio.CancelledError) for a page tuple.
Unexpected programming errors are re-raised rather than hidden.
"""
from __future__ import annotations

import asyncio
import re
from collections import deque
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlsplit

from ..core.models import HttpExchange
from ..http.client import ScanAborted
from .normalize import canonicalize, shape

_ASSET_EXT = re.compile(r"\.(png|jpe?g|gif|webp|svg|ico|css|woff2?|ttf|eot|mp[34]|webm|avi|mov|zip|gz|tar|pdf)(\?|$)", re.I)
_JS_EXT = re.compile(r"\.m?js(\?|$|#)", re.I)
_NON_WEB_EXT = re.compile(r"\.(?:py|md|rst|log|jsonl|toml|ya?ml|ini|cfg|conf|lock|db|sqlite3?|bak|old|pem|key|crt|map)(?:\?|$)",re.I)
_SENSITIVE_PATH = re.compile(r"(?:^|/)(?:\.(?:git|svn|hg|env|aws|ssh|config|pytest_cache|cache)|__pycache__|node_modules)(?:/|$)",re.I)

SUCCESS = "SUCCESS"
REQUEST_ERROR = "REQUEST_ERROR"
PARSER_ERROR = "PARSER_ERROR"
TIMEOUT = "TIMEOUT"
CANCELLED = "CANCELLED"
SCOPE_REJECTED = "SCOPE_REJECTED"
BUDGET_REJECTED = "BUDGET_REJECTED"
STATUSES = (SUCCESS, REQUEST_ERROR, PARSER_ERROR, TIMEOUT, CANCELLED, SCOPE_REJECTED, BUDGET_REJECTED)


class PageParser(HTMLParser):
    """Streaming HTML extractor — links, forms, scripts, title."""
    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.links: Set[str] = set()
        self.assets: Set[str] = set()
        self.forms: List[Dict[str, Any]] = []
        self.title = ""
        self._in_title = False
        self._current_form: Optional[Dict[str, Any]] = None
        self.meta: Dict[str, str] = {}
        self.generator = ""

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]):
        a = {k.lower(): (v or "") for k, v in attrs}
        tag = tag.lower()
        if tag == "title":
            self._in_title = True
        elif tag in ("a", "area", "link") and a.get("href"):
            self._add_link(a["href"])
        elif tag in ("iframe", "frame") and a.get("src"):
            self._add_link(a["src"])
        elif tag in ("script", "img", "source", "embed") and a.get("src"):
            self.assets.add(urljoin(self.base_url, a["src"]))
        elif tag == "meta":
            name = (a.get("name") or a.get("property") or "").lower()
            if name:
                self.meta[name] = a.get("content", "")
            if name == "generator":
                self.generator = a.get("content", "")
        elif tag == "form":
            self._current_form = {"action": a.get("action", ""), "method": (a.get("method") or "GET").upper(),
                                  "enctype": a.get("enctype", "application/x-www-form-urlencoded"), "fields": []}
        elif self._current_form is not None and tag in ("input", "textarea", "select", "button"):
            name = a.get("name")
            if name:
                self._current_form["fields"].append({"name": name, "type": (a.get("type") or ("textarea" if tag == "textarea" else "text")).lower(), "value": a.get("value", "")})
        elif tag == "base" and a.get("href"):
            self.base_url = urljoin(self.base_url, a["href"])

    def handle_endtag(self, tag: str):
        tag = tag.lower()
        if tag == "title":
            self._in_title = False
        elif tag == "form" and self._current_form is not None:
            if not self._current_form["action"]:
                self._current_form["action"] = self.base_url
            self.forms.append(self._current_form)
            self._current_form = None

    def handle_data(self, data: str):
        if self._in_title:
            self.title += data.strip()

    def _add_link(self, href: str):
        href = href.strip()
        if not href or href.startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
            return
        self.links.add(urljoin(self.base_url, href))


@dataclass
class CrawlTaskResult:
    url: str
    depth: int
    status: str
    exchange: Optional[HttpExchange] = None
    parser: Optional[PageParser] = None
    error: str = ""


class CrawlResult:
    def __init__(self):
        self.pages: List[HttpExchange] = []
        self.parsed: List[Tuple[HttpExchange, PageParser]] = []
        self.js_assets: Set[str] = set()
        self.queue_overflow = 0
        self.errors = 0
        self.outcomes: List[CrawlTaskResult] = []
        self.status_counts: Dict[str, int] = {s: 0 for s in STATUSES}
        self.cancelled = 0
        self.timeouts = 0
        self.scope_rejected = 0
        self.budget_rejected = 0

    def record(self, outcome: CrawlTaskResult) -> None:
        self.outcomes.append(outcome)
        self.status_counts[outcome.status] = self.status_counts.get(outcome.status, 0) + 1
        if outcome.status in (REQUEST_ERROR, PARSER_ERROR, TIMEOUT):
            self.errors += 1
        if outcome.status == CANCELLED:
            self.cancelled += 1
        elif outcome.status == TIMEOUT:
            self.timeouts += 1
        elif outcome.status == SCOPE_REJECTED:
            self.scope_rejected += 1
        elif outcome.status == BUDGET_REJECTED:
            self.budget_rejected += 1


class Crawler:
    def __init__(self, requester, authorization, profile, emit=None):
        self.requester = requester
        self.auth = authorization
        self.profile = profile
        self.emit = emit or (lambda *a, **k: None)
        self._seen_shapes: Set[str] = set()
        self._queued: Set[str] = set()
        self.result = CrawlResult()

    def _should_fetch(self, url: str) -> bool:
        path=urlsplit(url).path
        # Avoid crawling repository metadata, local secrets, and source/config
        # files commonly exposed by directory-listing fixtures. .well-known is
        # intentionally not blocked.
        if _SENSITIVE_PATH.search(path) or _NON_WEB_EXT.search(path):
            return False
        return not _ASSET_EXT.search(path)

    def _enqueue(self, url: str, depth: int, queue: deque) -> bool:
        c = canonicalize(url)
        s = shape(c)
        if s in self._seen_shapes or c in self._queued:
            return False
        allowed, reason = self.auth.check(c, purpose="crawl-enqueue")
        if not allowed:
            self.result.record(CrawlTaskResult(c, depth, SCOPE_REJECTED, error=reason))
            return False
        self._queued.add(c)
        queue.append((c, depth))
        return True

    async def run(self, seed_urls: List[str]) -> CrawlResult:
        queue: deque = deque()
        for u in seed_urls:
            self._enqueue(u, 0, queue)
        pages_budget = self.profile.max_pages
        self.emit("crawl", f"Crawl started ({len(queue)} seeds, depth≤{self.profile.max_depth}, pages≤{pages_budget})")

        while queue and not self.auth.stopped:
            wave: List[Tuple[str, int]] = []
            while queue and len(wave) < self.profile.max_concurrency:
                url, depth = queue.popleft()
                s = shape(url)
                if s in self._seen_shapes:
                    continue
                self._seen_shapes.add(s)
                wave.append((url, depth))
            if not wave:
                break

            results = await asyncio.gather(
                *(self._fetch(url, depth) for url, depth in wave),
                return_exceptions=True,
            )
            # gather(return_exceptions=True) returns child CancelledError objects
            # because CancelledError is a BaseException (not Exception).
            for (url, depth), item in zip(wave, results):
                if isinstance(item, asyncio.CancelledError):
                    outcome = CrawlTaskResult(url, depth, CANCELLED, error="crawl task cancelled")
                    self.result.record(outcome)
                    self.emit("crawl-error", f"Cancelled crawl task: {url}", status=CANCELLED, url=url)
                    continue
                if isinstance(item, BaseException):
                    # Expected request failures are normalized in _fetch. Reaching
                    # this path means an unexpected error; record its state and fail
                    # loudly rather than hiding a programming defect.
                    self.result.record(CrawlTaskResult(url, depth, REQUEST_ERROR,
                                                       error=f"unexpected {type(item).__name__}: {item}"))
                    raise item
                if not isinstance(item, CrawlTaskResult):
                    raise TypeError(f"crawler worker returned {type(item).__name__}, expected CrawlTaskResult")
                self.result.record(item)
                if item.status not in (SUCCESS, PARSER_ERROR):
                    continue
                parser = item.parser
                if parser is not None and depth + 1 <= self.profile.max_depth:
                    if len(self._seen_shapes) + len(queue) >= pages_budget:
                        self.result.queue_overflow += 1
                        continue
                    for link in sorted(parser.links):
                        if _JS_EXT.search(link):
                            allowed, reason = self.auth.check(link, purpose="crawl-js-asset")
                            if allowed:
                                self.result.js_assets.add(canonicalize(link))
                            else:
                                self.result.record(CrawlTaskResult(canonicalize(link), depth + 1,
                                                                   SCOPE_REJECTED, error=reason))
                            continue
                        if self._should_fetch(link):
                            self._enqueue(link, depth + 1, queue)
                self.emit("crawl-progress",
                          f"{len(self.result.pages)} pages · {len(queue)} queued · {len(self._seen_shapes)} unique shapes",
                          pages=len(self.result.pages), queued=len(queue),
                          cancelled=self.result.cancelled, errors=self.result.errors)
        return self.result

    async def _fetch(self, url: str, depth: int) -> CrawlTaskResult:
        if not self._should_fetch(url):
            return CrawlTaskResult(url, depth, SUCCESS)
        try:
            ex = await self.requester.send("GET", url, module="crawler")
        except ScanAborted as exc:
            reason = str(exc).lower()
            status = BUDGET_REJECTED if "budget" in reason else CANCELLED
            return CrawlTaskResult(url, depth, status, error=str(exc))
        if ex.error and ("scope-denied" in ex.error or "redirect blocked" in ex.error):
            return CrawlTaskResult(url, depth, SCOPE_REJECTED, exchange=ex, error=ex.error)
        if ex.error:
            timed_out = "timeout" in ex.error.lower()
            return CrawlTaskResult(url, depth, TIMEOUT if timed_out else REQUEST_ERROR,
                                  exchange=ex, error=ex.error)

        ctype = (ex.header("content-type") or "").lower()
        if ex.ok and "text/html" in ctype:
            parser = PageParser(ex.url)
            try:
                parser.feed(ex.response_body)
                parser.close()
            except (ValueError, UnicodeError, RecursionError) as exc:
                # Keep the fetched response even when its document is malformed.
                self.result.pages.append(ex)
                return CrawlTaskResult(url, depth, PARSER_ERROR, exchange=ex, error=f"{type(exc).__name__}: {exc}")
            self.result.pages.append(ex)
            self.result.parsed.append((ex, parser))
            for src in parser.assets:
                if _JS_EXT.search(src):
                    allowed, reason = self.auth.check(src, purpose="crawl-js-asset")
                    if allowed:
                        self.result.js_assets.add(canonicalize(src))
                    else:
                        self.result.record(CrawlTaskResult(canonicalize(src), depth + 1,
                                                           SCOPE_REJECTED, error=reason))
            return CrawlTaskResult(url, depth, SUCCESS, exchange=ex, parser=parser)
        if ex.ok and (_JS_EXT.search(urlsplit(url).path) or "javascript" in ctype):
            self.result.js_assets.add(ex.url)
        return CrawlTaskResult(url, depth, SUCCESS, exchange=ex)
