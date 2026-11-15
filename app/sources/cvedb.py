"""Shodan CVEDB (keyless): fallback CVSS source when NVD is slow/unavailable."""
from __future__ import annotations

from app.cache import Cache
from app.clock import utc_iso
from app.sources.base import AVAILABLE, NOT_FOUND, STALE, UNAVAILABLE, Fetcher, SourceError, SourceResult

CVEDB_URL = "https://cvedb.shodan.io/cve/{cve}"


class CveDbClient:
    name = "Shodan CVEDB"

    def __init__(self, fetcher: Fetcher, cache: Cache, *, ttl: int, ttl_not_found: int, timeout: float):
        self.f, self.cache, self.ttl, self.ttl_nf, self.timeout = fetcher, cache, ttl, ttl_not_found, timeout

    async def fetch(self, cve_id: str, deadline: float | None = None) -> SourceResult:
        key = f"cvedb:{cve_id}"
        url = CVEDB_URL.format(cve=cve_id)
        e = self.cache.get(key)
        if e and e.fresh(self.cache.now()):
            return SourceResult(**e.value)
        try:
            status, js = await self.f.get_json(url, timeout=self.timeout, deadline=deadline)
        except SourceError as ex:
            if e:
                r = SourceResult(**e.value)
                r.status = STALE if r.status == AVAILABLE else r.status
                r.note = f"CVEDB refresh failed ({ex.kind}); serving last-known-good record."
                return r
            return SourceResult(self.name, UNAVAILABLE, source_url=url, note=f"CVEDB unavailable ({ex.kind}).")
        now = utc_iso(self.cache.now())
        if status == 404 or not isinstance(js, dict) or "cve_id" not in js:
            r = SourceResult(self.name, NOT_FOUND, None, now, url, note="CVE not present in CVEDB.")
            self.cache.set(key, r.__dict__, self.ttl_nf)
            return r
        v3 = js.get("cvss_v3")
        data = {
            "cvss_v3": float(v3) if isinstance(v3, (int, float)) else None,
            "epss": js.get("epss"),
            "kev": bool(js.get("kev")),
            "ransomware": (js.get("ransomware_campaign") or "").lower() == "known",
            "published": js.get("published_time"),
            "summary": js.get("summary"),
        }
        r = SourceResult(self.name, AVAILABLE, data, now, url, js.get("published_time"))
        self.cache.set(key, r.__dict__, self.ttl)
        return r
