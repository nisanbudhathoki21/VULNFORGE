"""
VulnForge — scoped, budgeted, rate-limited async HTTP requester.

Every request in the platform (crawl, baseline, probe, verification) goes
through Requester.send(), which enforces, in order (ARCHITECTURE §4):

  1. SCOPE CHECK   — authorization gate approves the URL (else: not sent)
  2. BUDGET CHECK  — max_requests ceiling (else: scan aborts)
  3. RATE LIMIT    — global rps token bucket + concurrency semaphore
  4. STOP CHECK    — emergency stop / scan timeout
  5. SEND          — httpx with redirects validated against scope
  6. MEASURE       — status/headers/size-capped body/duration
  7. RECORD        — redacted metadata to scan stats/audit

Response bodies are capped (max_response_bytes) — memory exhaustion from a
hostile target is not possible through this path.
"""
from __future__ import annotations

import asyncio
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlsplit

import httpx

from ..core.models import HttpExchange
from ..core.ratelimit import RateLimiter, RequestBudget
from ..core.redaction import redact_headers

USER_AGENT = "VulnForge/0.4 (+authorized-security-assessment)"


class ScanAborted(Exception):
    """Raised when the scan must stop (budget exhausted or user stop)."""


class Requester:
    def __init__(
        self,
        authorization,
        profile,
        verify_tls: bool = True,
        timeout: float = 10.0,
        extra_headers: Optional[Dict[str, str]] = None,
        identity_headers: Optional[Dict[str, str]] = None,
    ):
        self.authorization = authorization
        self.profile = profile
        self.limiter = RateLimiter(
            requests_per_second=profile.requests_per_second,
            max_concurrency=profile.max_concurrency,
            stop_check=lambda: self.authorization.stopped,
        )
        self.budget = RequestBudget(profile.max_requests)
        self.timeout = timeout
        self.deadline = time.monotonic() + profile.scan_timeout_s
        headers = {"User-Agent": USER_AGENT,
                   "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,application/json;q=0.8,*/*;q=0.5",
            # Keep transport-level decompression from allocating an unbounded body;
            # bodies are read as raw chunks and capped before parsing/persistence.
            "Accept-Encoding": "identity"}
        if extra_headers:
            headers.update(extra_headers)
        if identity_headers:  # researcher-provided session/profile headers
            headers.update(identity_headers)
        self._client = httpx.AsyncClient(
            verify=verify_tls,
            timeout=httpx.Timeout(timeout, connect=5.0),
            follow_redirects=False,                     # redirects handled manually (scope!)
            headers=headers,
            limits=httpx.Limits(max_keepalive_connections=profile.max_concurrency * 2,
                                max_connections=profile.max_concurrency * 3),
        )
        self.exchanges: List[HttpExchange] = []
        self.on_exchange = None
        self._errors = 0

    async def close(self) -> None:
        await self._client.aclose()

    # ------------------------------------------------------------------
    def _check_guards(self, url: str, module: str, method: str) -> Optional[HttpExchange]:
        """Steps 1–4. Returns an HttpExchange describing the refusal, or None."""
        from pathlib import Path
        if Path(".vulnforge-stop").exists() and not self.authorization.stopped:
            self.authorization.stop(".vulnforge-stop detected")
        if self.authorization.stopped:
            raise ScanAborted("stopped by user")
        if time.monotonic() > self.deadline:
            self.authorization.stop("scan timeout reached")
            raise ScanAborted("scan timeout")
        allowed, reason = self.authorization.check(url, purpose=module, method=method)
        if not allowed:
            return HttpExchange(method=method, url=url, status=0, error=f"scope-denied: {reason}", module=module)
        if self.budget.sent >= self.budget.max_requests:
            self.authorization.stop("request budget exhausted")
            raise ScanAborted("request budget exhausted")
        return None

    # ------------------------------------------------------------------
    async def send(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        module: str = "core",
        follow_redirects: bool = True,
        max_redirects: int = 5,
    ) -> HttpExchange:
        current_url = url
        current_method = method
        current_body = body
        redirects = 0
        redirect_chain: List[Dict[str, Any]] = []
        t0 = time.perf_counter()
        req_headers: Dict[str, str] = dict(headers or {})

        while True:
            refusal = self._check_guards(current_url, module, current_method)
            if refusal is not None:
                refusal.method = current_method
                refusal.redirect_chain = list(redirect_chain)
                self._record(refusal)
                return refusal
            await self.limiter.acquire()
            try:
                await self.limiter.respect_retry_after()
                # Scope windows, cancellation, deadline, and concurrent budget
                # state may change while the limiter waits. Recheck immediately
                # before consuming budget and creating the outbound attempt.
                late_refusal=self._check_guards(current_url,module,current_method)
                if late_refusal is not None:
                    late_refusal.method=current_method
                    late_refusal.redirect_chain=list(redirect_chain)
                    self._record(late_refusal)
                    return late_refusal
                # Count only immediately before a real outbound HTTP attempt.
                if not self.budget.consume():
                    self.authorization.stop("request budget exhausted")
                    raise ScanAborted("request budget exhausted")
                prepared_request = self._client.build_request(
                    current_method, current_url,
                    headers=req_headers or None,
                    content=current_body.encode("utf-8", "replace") if current_body else None,
                )
                try:
                    resp = await self._client.send(prepared_request, follow_redirects=False, stream=True)
                except (httpx.TimeoutException, httpx.ConnectError, httpx.ReadError,
                        httpx.RemoteProtocolError) as e:
                    self._errors += 1
                    ex = self._request_error_exchange(prepared_request, e, module,
                        (time.perf_counter() - t0) * 1000)
                    ex.redirect_chain = list(redirect_chain)
                    self._record(ex)
                    return ex

                try:
                    try:
                        raw_body, truncated = await self._read_bounded_body(resp)
                    except (httpx.TimeoutException, httpx.ConnectError, httpx.ReadError,
                            httpx.RemoteProtocolError) as e:
                        self._errors += 1
                        ex = self._request_error_exchange(prepared_request, e, module,
                            (time.perf_counter() - t0) * 1000)
                        ex.status = resp.status_code
                        ex.reason_phrase = resp.reason_phrase
                        ex.response_headers = dict(resp.headers)
                        ex.redirect_chain = list(redirect_chain)
                        self._record(ex)
                        return ex

                    duration_ms = (time.perf_counter() - t0) * 1000
                    retry_after = self._parse_retry_after(resp.headers.get("retry-after", ""))
                    self.limiter.report_status(resp.status_code, retry_after)

                    # Record every redirect hop; validate the effective next method before following.
                    if follow_redirects and resp.status_code in (301, 302, 303, 307, 308) and resp.headers.get("location"):
                        dest = urljoin(current_url, resp.headers["location"])
                        next_method = current_method
                        next_body = current_body
                        if resp.status_code == 303 or (resp.status_code in (301, 302) and current_method.upper() == "POST"):
                            next_method, next_body = "GET", None
                        allowed, reason = self.authorization.check_redirect(current_url, dest, method=next_method)
                        source_parts, dest_parts = urlsplit(current_url), urlsplit(dest)
                        redirect_chain.append({"source": current_url, "destination": dest,
                            "status_code": resp.status_code, "host_change": source_parts.hostname != dest_parts.hostname,
                            "scheme_change": source_parts.scheme != dest_parts.scheme,
                            "redirect_type": ("EXTERNAL REDIRECT" if source_parts.hostname != dest_parts.hostname and not allowed else
                                              "CROSS-HOST REDIRECT" if source_parts.hostname != dest_parts.hostname else
                                              "HTTPS UPGRADE" if source_parts.scheme == "http" and dest_parts.scheme == "https" else "IN-SCOPE REDIRECT"),
                            "scope_status": "IN-SCOPE" if allowed else "BLOCKED: " + reason})
                        error = (f"redirect blocked: {reason}" if not allowed else
                                 "redirect limit reached" if redirects >= max_redirects else None)
                        hop = self._to_exchange(current_method,current_url,req_headers,current_body,
                                                resp,duration_ms,module,error=error,
                                                response_body=raw_body,response_truncated=truncated)
                        hop.redirect_chain=list(redirect_chain)
                        self._record(hop)
                        if not allowed or redirects >= max_redirects:
                            return hop
                        redirects += 1
                        current_method, current_body = next_method, next_body
                        current_url = dest
                        continue

                    ex = self._to_exchange(current_method, current_url, req_headers, current_body,
                                           resp, duration_ms, module,
                                           response_body=raw_body,response_truncated=truncated)
                    ex.redirect_chain = list(redirect_chain)
                    self._record(ex)
                    return ex
                finally:
                    await resp.aclose()
            finally:
                self.limiter.release()

    @staticmethod
    def _prepared_request_parts(request):
        items=[[str(name),str(value)] for name,value in request.headers.multi_items()]
        headers={}
        for name,value in items:
            headers[name]=value
        try: body=request.content.decode("utf-8",errors="replace")
        except Exception: body=""
        return headers,items,body

    async def _read_bounded_body(self, response: httpx.Response):
        """Read at most max_response_bytes plus one sentinel byte, without buffering the full body."""
        cap = max(0, int(self.profile.max_response_bytes))
        collected = bytearray()
        async for chunk in response.aiter_raw():
            remaining = cap + 1 - len(collected)
            if remaining <= 0:
                return bytes(collected[:cap]), True
            collected.extend(chunk[:remaining])
            if len(collected) > cap:
                return bytes(collected[:cap]), True
        return bytes(collected[:cap]), False

    @staticmethod
    def _parse_retry_after(value: str):
        if not value:
            return None
        try:
            return max(0.0, float(value))
        except (TypeError, ValueError):
            try:
                from email.utils import parsedate_to_datetime
                parsed = parsedate_to_datetime(value)
                if parsed.tzinfo is None:
                    from datetime import timezone
                    parsed = parsed.replace(tzinfo=timezone.utc)
                from datetime import datetime, timezone
                return max(0.0, (parsed - datetime.now(timezone.utc)).total_seconds())
            except (TypeError, ValueError, OverflowError):
                return None

    def _request_error_exchange(self, request, error, module, duration_ms):
        headers,items,body=self._prepared_request_parts(request)
        return HttpExchange(method=request.method,url=str(request.url),request_headers=headers,
            request_header_items=items,request_body=body,status=0,error=f"{type(error).__name__}: {error}",
            duration_ms=round(duration_ms,2),module=module)

    def _to_exchange(self, method: str, url: str, req_headers: Dict[str, str],
                     req_body: Optional[str], resp: httpx.Response,
                     duration_ms: float, module: str, error: Optional[str] = None,
                     response_body: bytes = b"", response_truncated: bool = False) -> HttpExchange:
        cap = self.profile.max_response_bytes
        raw = response_body[:cap]
        truncated = response_truncated
        try:
            body_text = raw.decode(resp.encoding or "utf-8", errors="replace")
        except Exception:
            body_text = raw.decode("utf-8", errors="replace")
        note = f"\n[response body truncated at {cap} bytes]" if truncated else ""
        request=resp.request
        request_headers,request_items,request_body=self._prepared_request_parts(request)
        response_items=[[str(name),str(value)] for name,value in resp.headers.multi_items()]
        response_headers={}
        for name,value in response_items:
            response_headers[name]=value
        version=getattr(resp,"http_version","HTTP/1.1") or "HTTP/1.1"
        return HttpExchange(
            method=method, url=str(request.url or resp.url or url),
            request_headers=request_headers,request_header_items=request_items,
            request_version=version,request_body=request_body,
            status=resp.status_code,reason_phrase=resp.reason_phrase,
            response_headers=response_headers,response_header_items=response_items,
            response_version=version,response_body=body_text+note,
            duration_ms=round(duration_ms, 2),error=error,module=module,
        )

    def _record(self, ex: HttpExchange) -> None:
        self.exchanges.append(ex)
        if self.on_exchange:
            try:
                self.on_exchange(ex)
            except Exception:
                # Telemetry consumers must not change request/test outcomes.
                pass

    # ------------------------------------------------------------------
    def stats(self) -> Dict[str, Any]:
        return {
            "requests_sent": self.budget.sent,
            "errors": self._errors,
            "current_rps": round(self.limiter.current_rps, 2),
        }
