"""Background cache warmer.

Keyless NVD is slow (often 10s+) and rate-limited (~5 calls / 30s), while callers expect
sub-2s answers. After loading the KEV catalogue (one call), the warmer trickles NVD lookups for
(1) a few well-known CVEs and (2) KEV-listed CVEs, newest first, using only a fraction of the
NVD budget so live requests are never starved. Everything lands in the cache (SQLite persists
across restarts). Losing the cache only costs latency, never correctness.
"""
from __future__ import annotations

import asyncio
import logging

from app.config import Settings
from app.triage import TriageService

log = logging.getLogger("vulnrank.warmer")

WELL_KNOWN = [
    "CVE-2021-44228", "CVE-2024-3094", "CVE-2014-0160", "CVE-2017-0144", "CVE-2022-22965", "CVE-2023-4863",
    "CVE-2023-44487", "CVE-2021-34527", "CVE-2020-1472", "CVE-2019-0708", "CVE-2022-0847", "CVE-2021-4034",
    "CVE-2023-34362", "CVE-2024-6387", "CVE-2017-5638", "CVE-2018-13379", "CVE-2022-26134", "CVE-2023-23397",
]


async def warm_cache(svc: TriageService, s: Settings, limit: int = 400) -> None:
    try:
        await asyncio.sleep(1)
        await svc.kev.lookup("CVE-1999-0001")  # loads/refreshes the catalogue
        cat = svc.kev.cache.get("kev:catalogue")
        kev_ids: list[str] = []
        if cat:
            by_id = cat.value["cat"]["by_id"]
            kev_ids = [c for c, _ in sorted(by_id.items(), key=lambda kv: kv[1].get("date_added") or "", reverse=True)]
        queue = list(dict.fromkeys(WELL_KNOWN + kev_ids))[:limit]
        # EPSS is batched (50/call), so warm it for the whole queue quickly
        await svc.epss.fetch_many(queue)
        interval = s.nvd_rate_period_sec / max(1.0, s.nvd_rate_calls * s.warm_budget_fraction)
        for cve in queue:
            e = svc.nvd.cache.get(f"nvd:{cve}")
            if e and e.fresh(svc.nvd.cache.now()):
                continue
            await svc.nvd.fetch(cve)
            await asyncio.sleep(interval)
    except asyncio.CancelledError:
        raise
    except Exception:  # warming must never crash the service
        log.exception("cache warmer stopped")
