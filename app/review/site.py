"""Passive website check: the home page plus a few policy pages, and the security headers of the home page.

Only public pages are requested (GET, no forms, no probing, no authentication), through the SSRF-safe fetcher.
"""
from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from app.review.evidence import Doc
from app.review.findings import Finding
from app.review.netguard import Blocked, Page, SafeFetcher

I = re.IGNORECASE | re.DOTALL
LINK = re.compile(r"<a\b[^>]*?href\s*=\s*[\"']([^\"'#\s]+)[\"'][^>]*>(.*?)</a>", I)
WANTED = re.compile(r"privacy|datenschutz|terms|conditions|\btos\b|refund|return|withdraw|contact|imprint|impressum|legal|grievance|cookie|shipping|cancel|unsubscribe|about", I)
MAX_PAGES = 6


@dataclass
class SiteScan:
    url: str
    docs: list[Doc] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    coverage: dict = field(default_factory=dict)


def pick_links(base: str, html: str) -> list[str]:
    host = (urlsplit(base).hostname or "").lower()
    seen, out = set(), []
    for href, label in LINK.findall(html[:600_000]):
        if href.startswith(("mailto:", "tel:", "javascript:")):
            continue
        absu = urljoin(base, href)
        u = urlsplit(absu)
        h = (u.hostname or "").lower()
        if u.scheme not in ("http", "https") or not (h == host or h.endswith("." + host) or host.endswith("." + h)):
            continue
        text = re.sub(r"<[^>]+>", " ", label)[:80]
        if WANTED.search(u.path) or WANTED.search(text):
            key = u.path.rstrip("/") or "/"
            if key not in seen and key != (urlsplit(base).path.rstrip("/") or "/"):
                seen.add(key)
                out.append(absu.split("#")[0])
    return out[:MAX_PAGES]


def header_findings(page: Page, final_https: bool) -> list[Finding]:
    h, out = page.headers, []
    ref = [{"url": page.url}]
    if not final_https:
        out.append(Finding("site:no-https", "security", "site_header", "Site is served over plain HTTP (no HTTPS)", "high",
                           "Serve the whole site over HTTPS with a valid certificate and redirect HTTP to HTTPS.", confidence="high", evidence=ref, tags=["CWE-319"]))
        return out
    if "strict-transport-security" not in h:
        out.append(Finding("site:no-hsts", "security", "site_header", "HSTS header missing", "medium",
                           "Send Strict-Transport-Security (e.g. max-age=31536000; includeSubDomains) so browsers refuse plain HTTP.", confidence="high", evidence=ref, tags=["CWE-319"]))
    if "content-security-policy" not in h:
        out.append(Finding("site:no-csp", "security", "site_header", "Content-Security-Policy header missing", "low",
                           "Add a Content-Security-Policy that restricts script sources to limit the impact of XSS.", confidence="high", evidence=ref, tags=["CWE-693"]))
    if h.get("x-content-type-options", "").lower() != "nosniff":
        out.append(Finding("site:no-nosniff", "security", "site_header", "X-Content-Type-Options: nosniff missing", "low",
                           "Send X-Content-Type-Options: nosniff.", confidence="high", evidence=ref, tags=["CWE-693"]))
    if "x-frame-options" not in h and "frame-ancestors" not in h.get("content-security-policy", ""):
        out.append(Finding("site:no-framing-protection", "security", "site_header", "No clickjacking protection (X-Frame-Options / frame-ancestors)", "low",
                           "Send X-Frame-Options: DENY or a CSP frame-ancestors directive.", confidence="high", evidence=ref, tags=["CWE-1021"]))
    weak = []
    for c in page.set_cookies:
        low = c.lower()
        name = c.split("=", 1)[0].strip()
        miss = [f for f, k in (("Secure", "secure"), ("HttpOnly", "httponly"), ("SameSite", "samesite")) if k not in low]
        if miss:
            weak.append({"cookie": name, "missing": miss})
    if weak:
        out.append(Finding("site:cookie-flags", "security", "site_header", f"{len(weak)} cookie(s) set without Secure/HttpOnly/SameSite", "medium",
                           "Set Secure, HttpOnly and SameSite on session and authentication cookies.", confidence="high", evidence=weak[:4], tags=["CWE-614"]))
    if re.search(r"""(?:src|href|action)\s*=\s*["']http://""", page.text[:600_000], I):
        out.append(Finding("site:mixed-content", "security", "site_header", "Page loads resources over plain HTTP (mixed content)", "medium",
                           "Load every script, stylesheet, image and form action over HTTPS.", confidence="medium", evidence=ref, tags=["CWE-311"]))
    return out


async def scan_site(sf: SafeFetcher, url: str, *, deadline: float | None = None) -> SiteScan:
    scan = SiteScan(url)
    try:
        home = await sf.get(url, deadline=deadline)
    except Blocked as ex:
        scan.coverage = {"fetched": False, "reason": str(ex)}
        return scan
    final_https = urlsplit(home.url).scheme == "https"
    scan.docs.append(Doc(home.url, "page", home.text))
    scan.findings.extend(header_findings(home, final_https))
    links = pick_links(home.url, home.text) if home.text else []

    async def one(u: str):
        try:
            p = await sf.get(u, deadline=deadline)
            return p if p.status < 400 and p.text else None
        except Blocked:
            return None
    pages = await asyncio.gather(*[one(u) for u in links])
    for p in pages:
        if p:
            scan.docs.append(Doc(p.url, "page", p.text))
    scan.coverage = {"fetched": True, "status": home.status, "pages_read": len(scan.docs), "https": final_https, "truncated": home.truncated,
                     "linked_pages_found": len(links)}
    return scan
