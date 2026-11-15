"""Builders for upstream-shaped payloads (shapes verified against live APIs, 2026-11-15)."""
from __future__ import annotations


def nvd(cve: str, primary: float | None = 9.8, secondary: float | None = None, version: str = "31",
        status: str = "Analyzed", exploit_ref: bool = False, desc: str = "Test vulnerability.") -> dict:
    metrics: dict = {}
    key = f"cvssMetricV{version}"
    entries = []
    if primary is not None:
        entries.append({"source": "nvd@nist.gov", "type": "Primary",
                        "cvssData": {"version": f"{version[0]}.{version[1]}", "baseScore": primary,
                                     "baseSeverity": "CRITICAL" if primary >= 9 else "HIGH",
                                     "vectorString": f"CVSS:3.{version[1]}/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}})
    if secondary is not None:
        entries.append({"source": "cna@example.org", "type": "Secondary",
                        "cvssData": {"version": f"{version[0]}.{version[1]}", "baseScore": secondary,
                                     "baseSeverity": "MEDIUM", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L"}})
    if entries:
        metrics[key] = entries
    refs = [{"url": "https://vendor.example/advisory", "source": "x", "tags": ["Vendor Advisory"]}]
    if exploit_ref:
        refs.append({"url": "https://exploit-db.example/1", "source": "x", "tags": ["Exploit", "Third Party Advisory"]})
    return {"resultsPerPage": 1, "startIndex": 0, "totalResults": 1, "vulnerabilities": [{"cve": {
        "id": cve, "vulnStatus": status, "published": "2021-12-10T10:15:09.143", "lastModified": "2026-08-11T19:33:44.513",
        "descriptions": [{"lang": "en", "value": desc}], "metrics": metrics, "references": refs,
        "weaknesses": [{"description": [{"lang": "en", "value": "CWE-502"}]}]}}]}


NVD_EMPTY = {"resultsPerPage": 0, "startIndex": 0, "totalResults": 0, "vulnerabilities": []}


def kev(entries: dict[str, dict] | None = None) -> dict:
    entries = entries or {}
    return {"title": "CISA KEV", "catalogVersion": "2026.11.13", "dateReleased": "2026-11-13T20:24:18Z",
            "count": len(entries), "vulnerabilities": [
                {"cveID": c, "vendorProject": "V", "product": "P", "vulnerabilityName": "N", "dateAdded": e.get("added", "2024-01-01"),
                 "dueDate": e.get("due", "2024-01-22"), "requiredAction": "Apply updates per vendor instructions.",
                 "knownRansomwareCampaignUse": "Known" if e.get("ransomware") else "Unknown"}
                for c, e in entries.items()]}


def epss(rows: dict[str, tuple[float, float]]) -> dict:
    return {"status": "OK", "status-code": 200, "version": "1.0", "total": len(rows), "offset": 0, "limit": 100,
            "data": [{"cve": c, "epss": f"{p:.9f}", "percentile": f"{q:.9f}", "date": "2026-11-14"} for c, (p, q) in rows.items()]}


def cvedb(cve: str, v3: float | None = 9.8, kev_: bool = False) -> dict:
    return {"cve_id": cve, "summary": "s", "cvss": v3, "cvss_v3": v3, "epss": 0.5, "kev": kev_,
            "ransomware_campaign": "Unknown", "published_time": "2021-12-10T10:15:09"}
