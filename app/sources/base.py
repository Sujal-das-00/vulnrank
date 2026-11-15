"""Shared plumbing for upstream sources: allow-listed HTTP, retries, breaker, rate limiter."""
from __future__ import annotations

import asyncio
import random
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable
from urllib.parse import urlparse

import httpx

# SSRF guard: the service only ever talks to these hosts, never to caller-supplied URLs.
ALLOWED_HOSTS = frozenset(
    {
        "services.nvd.nist.gov",
        "www.cisa.gov",
        "api.first.org",
        "cvedb.shodan.io",
        "api.osv.dev",
    }
)

# Source status vocabulary (blueprint section 6):
#   available | not_found | unavailable | stale | not_applicable | conflicting
AVAILABLE, NOT_FOUND, UNAVAILABLE, STALE, NOT_APPLICABLE = (
    "available",
    "not_found",
    "unavailable",
    "stale",
    "not_applicable",
)


@dataclass
class SourceResult:
    source: str
    status: str
    data: dict[str, Any] | None = None
    retrieved_at: str | None = None
    source_url: str | None = None
    source_updated_at: str | None = None
    note: str | None = None

    @property
    def usable(self) -> bool:
        """True when `data` may be used as evidence (fresh or explicitly-stale)."""
        return self.status in (AVAILABLE, STALE) and self.data is not None


class SourceError(Exception):
    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind  # timeout | rate_limited | http_error | malformed | circuit_open | blocked


@dataclass
class _Breaker:
    failures: int = 0
    open_until: float = 0.0


class Fetcher:
    """GET-JSON with timeouts, bounded retries (backoff + jitter, honours Retry-After)
    and a per-host circuit breaker. A timeout is NEVER interpreted as a negative result."""

    RETRY_STATUS = {403, 408, 425, 429, 500, 502, 503, 504}

    def __init__(
        self,
        client: httpx.AsyncClient,
        *,
        retries: int = 2,
        backoff_base: float = 0.4,
        breaker_threshold: int = 5,
        breaker_cooldown: float = 30.0,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ):
        self.client = client
        self.retries = retries
        self.backoff_base = backoff_base
        self.threshold = breaker_threshold
        self.cooldown = breaker_cooldown
        self._sleep = sleep
        self._mono = monotonic
        self._breakers: dict[str, _Breaker] = {}

    def breaker_state(self, host: str) -> str:
        b = self._breakers.get(host)
        return "open" if b and b.open_until > self._mono() else "closed"

    def _record(self, host: str, ok: bool) -> None:
        b = self._breakers.setdefault(host, _Breaker())
        if ok:
            b.failures = 0
            b.open_until = 0.0
        else:
            b.failures += 1
            if b.failures >= self.threshold:
                b.open_until = self._mono() + self.cooldown

    async def get_json(
        self,
        url: str,
        params: dict[str, Any] | None = None,
        *,
        headers: dict[str, str] | None = None,
        timeout: float = 6.0,
        deadline: float | None = None,
        json_body: Any = None,
    ) -> tuple[int, Any]:
        """Returns (status, parsed_json). 404 returns (404, None). Raises SourceError otherwise.
        With `json_body` the call is a POST (used for read-only batch queries such as OSV)."""
        parsed = urlparse(url)
        host = parsed.hostname or ""
        if parsed.scheme != "https" or host not in ALLOWED_HOSTS:
            raise SourceError("blocked", f"host not allow-listed: {host}")
        if self.breaker_state(host) == "open":
            raise SourceError("circuit_open", f"{host} cooling down after repeated failures")

        last: SourceError | None = None
        for attempt in range(self.retries + 1):
            remaining = None if deadline is None else deadline - self._mono()
            if remaining is not None and remaining <= 0.05:
                last = last or SourceError("timeout", "request deadline exhausted")
                break
            eff_timeout = timeout if remaining is None else max(0.1, min(timeout, remaining))
            retry_after: float | None = None
            try:
                if json_body is not None:
                    resp = await self.client.post(url, json=json_body, headers=headers, timeout=eff_timeout, follow_redirects=False)
                else:
                    resp = await self.client.get(
                        url, params=params, headers=headers, timeout=eff_timeout, follow_redirects=False
                    )
                if resp.status_code == 404:
                    self._record(host, True)
                    return 404, None
                if resp.status_code in self.RETRY_STATUS:
                    ra = resp.headers.get("Retry-After")
                    if ra and ra.strip().isdigit():
                        retry_after = float(ra)
                    kind = "rate_limited" if resp.status_code in (403, 429) else "http_error"
                    last = SourceError(kind, f"{host} returned HTTP {resp.status_code}")
                elif resp.status_code >= 400:
                    self._record(host, False)
                    raise SourceError("http_error", f"{host} returned HTTP {resp.status_code}")
                else:
                    try:
                        data = resp.json()
                    except ValueError:
                        self._record(host, False)
                        raise SourceError("malformed", f"{host} returned non-JSON body")
                    self._record(host, True)
                    return resp.status_code, data
            except (httpx.TimeoutException, httpx.TransportError) as e:
                last = SourceError("timeout", f"{host}: {type(e).__name__}")
            # transient failure: back off, honouring Retry-After if it fits the deadline
            if attempt < self.retries:
                delay = self.backoff_base * (2**attempt) * (0.5 + random.random() / 2)
                if retry_after is not None:
                    delay = max(delay, retry_after)
                if deadline is not None and self._mono() + delay >= deadline:
                    break
                await self._sleep(delay)
        self._record(host, False)
        assert last is not None
        raise last


class RateLimiter:
    """Sliding-window limiter. acquire() returns False instead of blocking past `timeout`."""

    def __init__(self, calls: int, period: float, monotonic: Callable[[], float] = time.monotonic):
        self.calls, self.period, self._mono = calls, period, monotonic
        self._stamps: deque[float] = deque()
        self._lock = asyncio.Lock()

    async def acquire(self, timeout: float) -> bool:
        end = self._mono() + max(0.0, timeout)
        while True:
            async with self._lock:
                now = self._mono()
                while self._stamps and now - self._stamps[0] >= self.period:
                    self._stamps.popleft()
                if len(self._stamps) < self.calls:
                    self._stamps.append(now)
                    return True
                wait = self.period - (now - self._stamps[0])
            if self._mono() + wait > end:
                return False
            await asyncio.sleep(wait + 0.01)
