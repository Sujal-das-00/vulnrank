"""FIRST EPSS client (batched)."""
from __future__ import annotations

from app.cache import Cache
from app.clock import utc_iso
from app.sources.base import (
    AVAILABLE, NOT_FOUND, STALE, UNAVAILABLE, Fetcher, SourceError, SourceResult,
)

EPSS_URL = "https://api.first.org/data/v1/epss"
CHUNK = 50


class EpssClient:
    name = "FIRST EPSS"

    def __init__(self, fetcher: Fetcher, cache: Cache, *, ttl: int, ttl_not_found: int, timeout: float):
        self.f, self.cache, self.ttl, self.ttl_nf, self.timeout = fetcher, cache, ttl, ttl_not_found, timeout

    async def fetch_many(self, cve_ids: list[str], deadline: float | None = None) -> dict[str, SourceResult]:
        out: dict[str, SourceResult] = {}
        missing: list[str] = []
        stale: dict[str, SourceResult] = {}
        for c in cve_ids:
            e = self.cache.get(f"epss:{c}")
            if e and e.fresh(self.cache.now()):
                out[c] = SourceResult(**e.value)
            else:
                missing.append(c)
                if e:
                    stale[c] = SourceResult(**e.value)
        for i in range(0, len(missing), CHUNK):
            chunk = missing[i : i + CHUNK]
            try:
                status, js = await self.f.get_json(
                    EPSS_URL, {"cve": ",".join(chunk)}, timeout=self.timeout, deadline=deadline
                )
                if status != 200 or not isinstance(js, dict) or not isinstance(js.get("data"), list):
                    raise SourceError("malformed", "unexpected EPSS response")
            except SourceError as ex:
                for c in chunk:
                    if c in stale:
                        r = stale[c]
                        r.status = STALE if r.status == AVAILABLE else r.status
                        r.note = f"EPSS refresh failed ({ex.kind}); serving last-known-good score."
                        out[c] = r
                    else:
                        out[c] = SourceResult(self.name, UNAVAILABLE, source_url=EPSS_URL,
                                              note=f"EPSS unavailable ({ex.kind}).")
                continue
            now = utc_iso(self.cache.now())
            found = {}
            for row in js["data"]:
                try:
                    found[row["cve"].upper()] = (float(row["epss"]), float(row["percentile"]), row.get("date"))
                except (KeyError, ValueError, TypeError):
                    continue
            for c in chunk:
                if c in found:
                    p, pct, date = found[c]
                    if not (0.0 <= p <= 1.0 and 0.0 <= pct <= 1.0):
                        out[c] = SourceResult(self.name, UNAVAILABLE, source_url=EPSS_URL, note="EPSS value out of range.")
                        continue
                    r = SourceResult(self.name, AVAILABLE, {"probability": p, "percentile": pct, "score_date": date},
                                     now, f"{EPSS_URL}?cve={c}", date)
                    self.cache.set(f"epss:{c}", r.__dict__, self.ttl)
                else:
                    r = SourceResult(self.name, NOT_FOUND, None, now, f"{EPSS_URL}?cve={c}",
                                     note="No EPSS score published for this CVE (common for very new CVEs).")
                    self.cache.set(f"epss:{c}", r.__dict__, self.ttl_nf)
                out[c] = r
        return out
