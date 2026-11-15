"""CISA Known Exploited Vulnerabilities catalogue, loaded and cached as a whole."""
from __future__ import annotations

import asyncio
from typing import Any

from app.cache import Cache
from app.clock import utc_iso
from app.sources.base import AVAILABLE, STALE, UNAVAILABLE, Fetcher, SourceError, SourceResult

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_KEY = "kev:catalogue"


def parse_kev(js: dict[str, Any]) -> dict[str, Any]:
    items = js.get("vulnerabilities")
    if not isinstance(items, list):
        raise SourceError("malformed", "KEV catalogue has no vulnerabilities list")
    by_id = {}
    for v in items:
        cid = v.get("cveID")
        if cid:
            by_id[cid.upper()] = {
                "name": v.get("vulnerabilityName"),
                "vendor": v.get("vendorProject"),
                "product": v.get("product"),
                "date_added": v.get("dateAdded"),
                "due_date": v.get("dueDate"),
                "required_action": v.get("requiredAction"),
                "ransomware": (v.get("knownRansomwareCampaignUse") or "").lower() == "known",
            }
    return {"version": js.get("catalogVersion"), "released": js.get("dateReleased"),
            "count": js.get("count", len(by_id)), "by_id": by_id}


_GENERIC = {"server", "service", "services", "system", "systems", "software", "platform", "manager", "management", "device",
            "devices", "client", "web", "application", "applications", "remote", "data", "code", "network", "security", "cloud",
            "access", "control", "controller", "gateway", "portal", "framework", "library", "driver", "kernel", "firmware"}


def match_products(by_id: dict[str, dict[str, Any]], text: str, limit: int = 5) -> list[tuple[str, dict[str, Any]]]:
    """KEV entries whose product's first word appears in free text (e.g. 'should I patch log4j?'). Conservative on purpose."""
    import re
    words = {w for w in re.findall(r"[a-z0-9][a-z0-9.+-]{3,}", text.lower()) if w not in _GENERIC}
    hits = []
    for cid, v in by_id.items():
        prod = re.findall(r"[a-z0-9][a-z0-9.+-]*", (v.get("product") or "").lower())
        if not prod or prod[0] in _GENERIC or len(prod[0]) < 4:
            continue
        if any(w == prod[0] or (len(w) >= 5 and (prod[0].startswith(w) or w.startswith(prod[0]))) for w in words):
            hits.append((cid, v))
    hits.sort(key=lambda kv: (not kv[1].get("ransomware"), -int((kv[1].get("date_added") or "0000-00-00").replace("-", ""))))
    return hits[:limit]


class KevClient:
    name = "CISA KEV"

    def __init__(self, fetcher: Fetcher, cache: Cache, *, ttl: int, timeout: float):
        self.f, self.cache, self.ttl, self.timeout = fetcher, cache, ttl, timeout
        self._lock = asyncio.Lock()  # one refresh at a time (no stampede)

    async def _catalogue(self, deadline: float | None) -> tuple[dict | None, str, str | None, str | None]:
        """-> (catalogue, status, retrieved_at, note)"""
        e = self.cache.get(_KEY)
        if e and e.fresh(self.cache.now()):
            return e.value["cat"], AVAILABLE, e.value["retrieved_at"], None
        async with self._lock:
            e = self.cache.get(_KEY)
            if e and e.fresh(self.cache.now()):
                return e.value["cat"], AVAILABLE, e.value["retrieved_at"], None
            try:
                status, js = await self.f.get_json(KEV_URL, timeout=max(self.timeout, 10), deadline=deadline)
                if status != 200 or not isinstance(js, dict):
                    raise SourceError("http_error", f"KEV HTTP {status}")
                cat = parse_kev(js)
                retrieved = utc_iso(self.cache.now())
                self.cache.set(_KEY, {"cat": cat, "retrieved_at": retrieved}, self.ttl)
                return cat, AVAILABLE, retrieved, None
            except SourceError as ex:
                if e:  # last-known-good, clearly marked stale
                    return (e.value["cat"], STALE, e.value["retrieved_at"],
                            f"KEV refresh failed ({ex.kind}); using last-known-good snapshot.")
                return None, UNAVAILABLE, None, f"KEV catalogue could not be retrieved ({ex.kind})."

    async def lookup(self, cve_id: str, deadline: float | None = None) -> SourceResult:
        cat, status, retrieved, note = await self._catalogue(deadline)
        if cat is None:
            return SourceResult(self.name, UNAVAILABLE, None, None, KEV_URL, note=note)
        entry = cat["by_id"].get(cve_id)
        data = {"listed": entry is not None, "catalogue_version": cat["version"],
                "catalogue_released": cat["released"], "catalogue_size": cat["count"], **(entry or {})}
        n = note
        if entry is None:
            msg = "Not listed in the queried KEV snapshot (this does not prove the CVE is not exploited)."
            n = f"{n} {msg}" if n else msg
        return SourceResult(self.name, status, data, retrieved, KEV_URL, cat["released"], n)

    async def search_products(self, text: str, limit: int = 5) -> list[tuple[str, dict[str, Any]]]:
        """Best-effort product-name match against the cached catalogue. Never raises."""
        try:
            cat, _status, _at, _note = await self._catalogue(None)
        except Exception:
            return []
        return match_products(cat["by_id"], text, limit) if cat else []
