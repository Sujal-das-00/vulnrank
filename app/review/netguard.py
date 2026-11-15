"""SSRF-safe fetching of caller-named public websites.

The target of a review is chosen by an untrusted caller, so every request is made only after:
  * scheme is http/https and the port is 80/443 (no credentials in the URL),
  * the host resolves ONLY to public addresses (no loopback, private, link-local, metadata, multicast, reserved),
  * the connection is pinned to the validated IP (no DNS-rebinding window); TLS still verifies the real hostname,
  * redirects are followed manually (max 3), re-validating every hop,
  * the body is size-capped and the call is time-boxed.
"""
from __future__ import annotations

import asyncio
import ipaddress
import socket
import time
from dataclasses import dataclass
from typing import Awaitable, Callable
from urllib.parse import urljoin, urlsplit

import httpx

USER_AGENT = "VulnRank-LaunchReview/0.1 (passive public-page check)"
MAX_REDIRECTS = 3
TEXT_TYPES = ("text/", "application/xhtml", "application/xml", "application/json")


class Blocked(Exception):
    """The URL is not allowed to be fetched (reason is safe to show to the caller)."""


def ip_is_public(ip: str) -> bool:
    a = ipaddress.ip_address(ip)
    if getattr(a, "ipv4_mapped", None):
        a = a.ipv4_mapped
    return a.is_global and not a.is_multicast


async def resolve_host(host: str) -> list[str]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    return list(dict.fromkeys(i[4][0] for i in infos))


Resolver = Callable[[str], Awaitable[list[str]]]


@dataclass
class Page:
    url: str
    status: int
    headers: dict[str, str]
    text: str
    truncated: bool
    set_cookies: list[str]


def validate_url(url: str) -> tuple[str, str, int, str]:
    """-> (scheme, host, port, path_and_query). Raises Blocked."""
    u = urlsplit(url.strip())
    if u.scheme not in ("http", "https"):
        raise Blocked("only http and https URLs are supported")
    if u.username or u.password:
        raise Blocked("credentials in URLs are not allowed")
    host = (u.hostname or "").lower().rstrip(".")
    if not host or "." not in host and not host.startswith("["):
        raise Blocked("a public hostname is required")
    try:
        port = u.port or (443 if u.scheme == "https" else 80)
    except ValueError:
        raise Blocked("invalid port")
    if port not in (80, 443):
        raise Blocked("only ports 80 and 443 are allowed")
    try:
        ipaddress.ip_address(host)
        raise Blocked("IP-address targets are not allowed; use a hostname")
    except ValueError:
        pass
    path = (u.path or "/") + (f"?{u.query}" if u.query else "")
    return u.scheme, host, port, path


class SafeFetcher:
    def __init__(self, client: httpx.AsyncClient | None = None, *, resolver: Resolver = resolve_host,
                 max_bytes: int = 1_500_000, timeout: float = 6.0, monotonic: Callable[[], float] = time.monotonic):
        self.client = client or httpx.AsyncClient(follow_redirects=False)
        self.resolver, self.max_bytes, self.timeout, self._mono = resolver, max_bytes, timeout, monotonic

    async def _pin(self, host: str) -> str:
        try:
            ips = await self.resolver(host)
        except OSError:
            raise Blocked("hostname does not resolve")
        if not ips:
            raise Blocked("hostname does not resolve")
        bad = [i for i in ips if not ip_is_public(i)]
        if bad:
            raise Blocked("hostname resolves to a non-public address")
        return ips[0]

    async def get(self, url: str, *, deadline: float | None = None) -> Page:
        current = url
        for _hop in range(MAX_REDIRECTS + 1):
            scheme, host, port, path = validate_url(current)
            ip = await self._pin(host)
            netloc_ip = f"[{ip}]" if ":" in ip else ip
            default = 443 if scheme == "https" else 80
            target = f"{scheme}://{netloc_ip}{'' if port == default else f':{port}'}{path}"
            budget = self.timeout if deadline is None else max(0.5, min(self.timeout, deadline - self._mono()))
            headers = {"Host": host, "User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml,*/*;q=0.5",
                       "Accept-Encoding": "identity"}
            ext = {"sni_hostname": host} if scheme == "https" else {}
            try:
                async with self.client.stream("GET", target, headers=headers, extensions=ext,
                                              timeout=httpx.Timeout(budget)) as r:
                    if r.status_code in (301, 302, 303, 307, 308) and r.headers.get("location"):
                        current = urljoin(f"{scheme}://{host}{path}", r.headers["location"])
                        continue
                    ctype = r.headers.get("content-type", "").lower()
                    if ctype and not ctype.startswith(TEXT_TYPES):
                        return Page(current, r.status_code, {k.lower(): v for k, v in r.headers.items()}, "", False, r.headers.get_list("set-cookie"))
                    buf, truncated = bytearray(), False
                    async for chunk in r.aiter_bytes():
                        buf.extend(chunk)
                        if len(buf) > self.max_bytes:
                            truncated = True
                            del buf[self.max_bytes:]
                            break
                    return Page(current, r.status_code, {k.lower(): v for k, v in r.headers.items()},
                                bytes(buf).decode("utf-8", "replace"), truncated, r.headers.get_list("set-cookie"))
            except httpx.TimeoutException:
                raise Blocked("the site did not respond in time")
            except httpx.HTTPError as ex:
                raise Blocked(f"could not connect ({type(ex).__name__})")
        raise Blocked("too many redirects")
