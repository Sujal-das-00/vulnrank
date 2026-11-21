"""Shared plumbing for upstream sources: allow-listed HTTP, retries, breaker, rate limiter."""
from __future__ import annotations

import asyncio
import random
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable
from urllib.parse import urljoin, urlparse

import httpx

# SSRF guard: the service only ever talks to these hosts, never to caller-supplied URLs.
ALLOWED_HOSTS = frozenset(
    {
        "services.nvd.nist.gov",
        "www.cisa.gov",
        "api.first.org",
        "cvedb.shodan.io",
        "api.osv.dev",
        # extra intents (app/intents): prices, weather, DNS-over-HTTPS and public JSON-RPC endpoints
        "api.coinbase.com", "api.kraken.com",
        "api.open-meteo.com", "geocoding-api.open-meteo.com",
        "dns.google", "cloudflare-dns.com",
        "ethereum-rpc.publicnode.com", "1rpc.io", "mainnet.base.org", "base-rpc.publicnode.com",
        "arb1.arbitrum.io", "arbitrum-one-rpc.publicnode.com", "polygon-bor-rpc.publicnode.com", "polygon.drpc.org",
        "mainnet.optimism.io", "optimism-rpc.publicnode.com",
        # legal / compliance and NLP intents: sanctions lists, legal-entity and VAT registers, SEC EDGAR, translation
        "www.treasury.gov", "sanctionslistservice.ofac.treas.gov", "wc2h-sls-prod-public-published.s3.us-gov-west-1.amazonaws.com",
        "scsanctions.un.org", "unsolprodfiles.blob.core.windows.net", "api.gleif.org", "ec.europa.eu", "www.sec.gov", "data.sec.gov",
        "api.mymemory.translated.net",
        # blockchain data (DefiLlama TVL and yield pools)
        "api.llama.fi", "yields.llama.fi",
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
        soft_statuses: frozenset[int] = frozenset(),
    ) -> tuple[int, Any]:
        """Returns (status, parsed_json). 404 (and any status in `soft_statuses`, e.g. an API that answers 400 for an unknown id)
        returns (status, None) without counting against the circuit breaker. Raises SourceError otherwise.
        With `json_body` the call is a POST (used for read-only batch queries such as OSV)."""
        return await self._request(url, params, headers, timeout, deadline, json_body, "json", soft_statuses=soft_statuses)

    async def get_text(
        self,
        url: str,
        params: dict[str, Any] | None = None,
        *,
        headers: dict[str, str] | None = None,
        timeout: float = 6.0,
        deadline: float | None = None,
        max_bytes: int = 25_000_000,
    ) -> tuple[int, str | None]:
        """Same guarantees as get_json for non-JSON bodies (CSV/XML sanctions lists). Oversized bodies are rejected."""
        status, text = await self._request(url, params, headers, timeout, deadline, None, "text", redirects=2)
        if text is not None and len(text) > max_bytes:
            raise SourceError("malformed", f"{urlparse(url).hostname} body exceeds {max_bytes} bytes")
        return status, text

    async def _request(self, url, params, headers, timeout, deadline, json_body, mode: str, redirects: int = 0, soft_statuses: frozenset[int] = frozenset()) -> tuple[int, Any]:
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
                if resp.status_code == 404 or resp.status_code in soft_statuses:
                    self._record(host, True)
                    return resp.status_code, None
                loc = resp.headers.get("Location")
                if resp.status_code in (301, 302, 303, 307, 308) and loc and redirects > 0:
                    self._record(host, True)
                    # a redirect is followed only to another allow-listed https host (checked on entry), never blindly
                    return await self._request(urljoin(url, loc), None, headers, timeout, deadline, None, mode, redirects - 1)
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
                        data = resp.json() if mode == "json" else resp.text
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
