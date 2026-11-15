"""NVD CVE API 2.0 client: CVSS + metadata + NVD-tagged exploit references."""
from __future__ import annotations

from typing import Any

from app.cache import Cache
from app.clock import utc_iso
from app.sources.base import (
    AVAILABLE, NOT_FOUND, STALE, UNAVAILABLE, Fetcher, RateLimiter, SourceError, SourceResult,
)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_PAGE = "https://nvd.nist.gov/vuln/detail/{cve}"


def severity_from_score(score: float | None) -> str | None:
    if score is None:
        return None
    if score == 0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def parse_nvd(js: dict[str, Any], cve_id: str) -> dict[str, Any] | None:
    vulns = js.get("vulnerabilities") or []
    cve = next((v.get("cve", {}) for v in vulns if v.get("cve", {}).get("id") == cve_id), None)
    if cve is None:
        return None
    entries: list[dict[str, Any]] = []
    for key, ver in (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0")):
        for m in (cve.get("metrics") or {}).get(key, []):
            d = m.get("cvssData", {})
            score = d.get("baseScore")
            if score is None:
                continue
            entries.append(
                {
                    "version": ver,
                    "score": float(score),
                    "severity": (d.get("baseSeverity") or severity_from_score(score) or "").lower() or None,
                    "vector": d.get("vectorString"),
                    "type": m.get("type"),  # Primary (NVD) | Secondary (CNA etc.)
                    "source": m.get("source"),
                }
            )
    desc = next((x.get("value") for x in cve.get("descriptions", []) if x.get("lang") == "en"), None)
    exploit_refs = [
        r["url"] for r in cve.get("references", []) if "Exploit" in (r.get("tags") or []) and r.get("url")
    ]
    cwes = sorted(
        {d["value"] for w in cve.get("weaknesses", []) for d in w.get("description", []) if d.get("value", "").startswith("CWE-")}
    )
    return {
        "id": cve_id,
        "vuln_status": cve.get("vulnStatus"),
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "description": desc,
        "cvss": entries,
        "exploit_refs": exploit_refs[:10],
        "cwes": cwes,
        "reference_count": len(cve.get("references", [])),
    }


def select_cvss(parsed: dict[str, Any]) -> dict[str, Any] | None:
    """Pick the score used for `cvss_base_score`.

    Authoritative = NVD *Primary* v3.1 (then Primary v3.0, clearly labelled).
    Anything else (CNA/secondary) is returned as provisional and lowers confidence.
    """
    ents = parsed.get("cvss", [])
    for ver in ("3.1", "3.0"):
        for e in ents:
            if e["type"] == "Primary" and e["version"] == ver:
                return {**e, "authoritative": True}
    for ver in ("3.1", "3.0"):
        for e in ents:
            if e["version"] == ver:
                return {**e, "authoritative": False}
    return None


class NvdClient:
    name = "NVD"

    def __init__(self, fetcher: Fetcher, cache: Cache, limiter: RateLimiter, *, api_key: str | None,
                 ttl: int, ttl_not_found: int, timeout: float):
        self.f, self.cache, self.limiter = fetcher, cache, limiter
        self.api_key, self.ttl, self.ttl_nf, self.timeout = api_key, ttl, ttl_not_found, timeout

    async def fetch(self, cve_id: str, deadline: float | None = None) -> SourceResult:
        key = f"nvd:{cve_id}"
        entry = self.cache.get(key)
        if entry and entry.fresh(self.cache.now()):
            return SourceResult(**entry.value)

        def degraded(why: str) -> SourceResult:
            if entry:
                r = SourceResult(**entry.value)
                if r.status == AVAILABLE:
                    r.status = STALE
                r.note = f"NVD refresh failed ({why}); serving last-known-good record."
                return r
            return SourceResult(self.name, UNAVAILABLE, note=f"NVD unavailable: {why}", source_url=NVD_URL)

        if not await self.limiter.acquire(timeout=min(2.5, self.timeout)):
            return degraded("local NVD rate-limit budget exhausted")
        headers = {"apiKey": self.api_key} if self.api_key else None
        try:
            status, js = await self.f.get_json(
                NVD_URL, {"cveId": cve_id}, headers=headers, timeout=self.timeout, deadline=deadline
            )
        except SourceError as e:
            return degraded(e.kind)
        now = utc_iso(self.cache.now())
        parsed = parse_nvd(js, cve_id) if status == 200 and isinstance(js, dict) else None
        if status == 404 or (isinstance(js, dict) and js.get("totalResults") == 0) or parsed is None:
            if status == 200 and isinstance(js, dict) and "vulnerabilities" not in js:
                return degraded("malformed")
            res = SourceResult(self.name, NOT_FOUND, retrieved_at=now, source_url=NVD_PAGE.format(cve=cve_id),
                               note="CVE not present in NVD.")
            self.cache.set(key, res.__dict__, self.ttl_nf)
            return res
        res = SourceResult(self.name, AVAILABLE, parsed, now, NVD_PAGE.format(cve=cve_id), parsed["last_modified"])
        self.cache.set(key, res.__dict__, self.ttl)
        return res
