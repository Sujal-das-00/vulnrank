"""DNS_RECORD_LOOKUP_GENERAL: record presence agreed by Google Public DNS and Cloudflare (DNS-over-HTTPS)."""
from __future__ import annotations

import asyncio
import re
from typing import Any
from urllib.parse import urlparse

from app.intents.common import first, free_text, ok, soft
from app.sources.base import Fetcher, SourceError

RESOLVERS = {"Google Public DNS": "https://dns.google/resolve", "Cloudflare": "https://cloudflare-dns.com/dns-query"}
TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28, "SRV": 33, "CAA": 257}
LABEL = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")
MAX_RECORDS = 25


def parse_name(raw: str) -> str | None:
    raw = raw.strip()
    if "://" in raw:
        raw = urlparse(raw).hostname or ""
    raw = raw.strip().rstrip(".").lower()
    try:
        raw = raw.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    labels = raw.split(".")
    if not raw or len(raw) > 253 or not all(LABEL.match(l) for l in labels):
        return None
    return raw


def resolve_request(params: dict[str, Any]) -> tuple[str | None, str | None]:
    text = free_text(params)
    name = first(params, "name", "domain", "hostname", "host", "fqdn")
    if name:
        name = parse_name(name)
    elif text:
        m = re.search(r"\b((?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z]{2,63})\b", text, re.I)
        name = parse_name(m.group(1)) if m else None
    rtype = first(params, "record_type", "type", "rtype", "record")
    if rtype:
        rtype = rtype.strip().upper()
    else:
        found = [t for t in TYPES if re.search(rf"\b{t}\b", text.upper())]
        rtype = found[0] if found else "A"
    return name, rtype


async def _ask(f: Fetcher, label: str, url: str, name: str, rtype: str, timeout: float, deadline: float | None) -> dict[str, Any]:
    _, js = await f.get_json(url, {"name": name, "type": rtype}, headers={"Accept": "application/dns-json"}, timeout=timeout, deadline=deadline)
    if not isinstance(js, dict) or "Status" not in js:
        raise SourceError("malformed", f"{label} returned an unexpected DNS response")
    rcode = js["Status"]
    if rcode not in (0, 3):  # SERVFAIL / REFUSED etc. say nothing about whether the record exists
        raise SourceError("http_error", f"{label} returned DNS rcode {rcode}")
    want = TYPES[rtype]
    recs = [a for a in (js.get("Answer") or []) if a.get("type") == want]
    return {"resolver": label, "nxdomain": rcode == 3, "records": sorted({str(a["data"])[:2048] for a in recs}),
            "ttl": min((a.get("TTL", 0) for a in recs), default=None)}


async def lookup(f: Fetcher, params: dict[str, Any], *, timeout: float, deadline: float | None) -> dict[str, Any]:
    name, rtype = resolve_request(params)
    if not name:
        return soft("no_name", "No valid DNS name was found in the request, so no lookup was made. Supply name (e.g. example.com).",
                    has_record=None)
    if rtype not in TYPES:
        return soft("unsupported_record_type", f"Record type {rtype} is not supported (supported: {', '.join(TYPES)}).", has_record=None, name=name)
    res = await asyncio.gather(*(_ask(f, l, u, name, rtype, timeout, deadline) for l, u in RESOLVERS.items()), return_exceptions=True)
    got = [r for r in res if isinstance(r, dict)]
    if not got:
        return soft("unavailable", f"No DNS resolver answered for {name}, so presence of {rtype} records is unknown (not reported as absent).",
                    has_record=None, name=name, record_type=rtype)
    presence = {bool(r["records"]) for r in got}
    resolvers = [{"resolver": r["resolver"], "has_record": bool(r["records"]), "nxdomain": r["nxdomain"]} for r in got]
    if len(presence) > 1:
        return soft("conflicting", f"Google and Cloudflare disagree about {rtype} records for {name} (possible propagation in progress); no verdict is given.",
                    has_record=None, name=name, record_type=rtype, resolvers=resolvers)
    has = presence.pop()
    records = sorted({d for r in got for d in r["records"]})[:MAX_RECORDS]
    nx = all(r["nxdomain"] for r in got)
    conf = 0.95 if len(got) == 2 else 0.7
    if has:
        answer = f"{name} has {len(records)} {rtype} record(s): {'; '.join(records[:5])}{' ...' if len(records) > 5 else ''}."
    elif nx:
        answer = f"{name} does not exist (NXDOMAIN), so it has no {rtype} records."
    else:
        answer = f"{name} exists but has no {rtype} record."
    answer += " Confirmed by Google and Cloudflare." if len(got) == 2 else " Only one resolver answered."
    ttls = [r["ttl"] for r in got if r["ttl"] is not None]
    return ok(answer, conf, has_record=has, name=name, record_type=rtype, records=records, ttl=min(ttls) if ttls else None,
              nxdomain=nx, resolvers=resolvers)
