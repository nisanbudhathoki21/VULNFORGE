"""
VulnForge — adaptive async rate limiting (spec §53).

• global token bucket (requests/second across all workers)
• per-scan async semaphore (concurrency ceiling)
• adaptive backoff: 429 / Retry-After / repeated 5xx halve the rate,
  sustained success restores it
• cooperative cancellation via the authorization stop event
"""
from __future__ import annotations

import asyncio
import time
from typing import Optional


class RateLimiter:
    def __init__(self, requests_per_second: float = 10.0, max_concurrency: int = 8,
                 stop_check=None):
        self._base_rps = float(requests_per_second)
        if not 0.0 < self._base_rps < float("inf"):
            raise ValueError("requests_per_second must be a finite positive number")
        self._max_concurrency = int(max_concurrency)
        if self._max_concurrency <= 0:
            raise ValueError("max_concurrency must be positive")
        self._rps = self._base_rps
        self._capacity = max(1.0, self._base_rps)
        self._tokens = self._capacity
        self._last = time.monotonic()
        self._lock = asyncio.Lock()
        self._semaphore = asyncio.Semaphore(self._max_concurrency)
        self._stop_check = stop_check or (lambda: False)
        self._penalty_until = 0.0

    @property
    def current_rps(self) -> float:
        return self._rps

    async def acquire(self) -> None:
        """Wait until one request is allowed. Raises asyncio.CancelledError on stop."""
        await self._semaphore.acquire()
        try:
            while True:
                if self._stop_check():
                    raise asyncio.CancelledError("scan stopped")
                async with self._lock:
                    now = time.monotonic()
                    self._tokens = min(self._capacity, self._tokens + (now - self._last) * self._rps)
                    self._last = now
                    if self._tokens >= 1.0:
                        self._tokens -= 1.0
                        return
                    deficit = 1.0 - self._tokens
                    wait = deficit / self._rps
                await asyncio.sleep(min(wait, 1.0))
        except BaseException:
            self._semaphore.release()
            raise

    def release(self) -> None:
        self._semaphore.release()

    # ------------------------------------------------------------------
    # adaptive feedback
    # ------------------------------------------------------------------
    def report_status(self, status: int, retry_after: Optional[float] = None) -> None:
        """Adjust pacing from server feedback. Severe signals slow us down."""
        if status == 429 or status >= 500:
            self._rps = max(min(0.01,self._base_rps), self._rps / 2.0)
            self._rps = min(self._rps,self._base_rps)
            self._capacity = max(1.0, self._rps)
            if retry_after:
                self._penalty_until = time.monotonic() + min(float(retry_after), 60.0)
        elif status and 200 <= status < 400:
            self._rps = min(self._base_rps, self._rps * 1.1 + 0.1)
            self._capacity = max(1.0, self._rps)

    async def respect_retry_after(self) -> None:
        remaining = self._penalty_until - time.monotonic()
        if remaining > 0:
            await asyncio.sleep(remaining)


class RequestBudget:
    """Hard request ceiling — the scan aborts rather than exceed it."""

    def __init__(self, max_requests: int):
        self.max_requests = int(max_requests)
        self.sent = 0

    def consume(self) -> bool:
        if self.sent >= self.max_requests:
            return False
        self.sent += 1
        return True
