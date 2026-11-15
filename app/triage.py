"""Triage orchestrator: enrich -> score -> rank -> explain. Domain-only (no Telegraph here)."""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Callable

from app import explain
from app.clock import utc_iso
from app.config import ENGINE_VERSION, SCORE_VERSION, Settings
from app.models import (
    Evidence, Finding, ItemError, Priority, ScoreBreakdown, ScoreComponent, Summary, TriageResponse,
)
from app.scoring import AssetContext, ScoreInputs, rank_key, score
from app.sources.base import AVAILABLE, NOT_FOUND, STALE, UNAVAILABLE, SourceResult
from app.sources.cvedb import CveDbClient
from app.sources.epss import EpssClient
from app.sources.kev import KevClient
from app.sources.nvd import NvdClient, select_cvss, severity_from_score

log = logging.getLogger("vulnrank.triage")


def _asset_ctx(f: Finding) -> AssetContext:
    a = f.asset
    if not a:
        return AssetContext()
    return AssetContext(a.criticality, a.effective_exposure(), a.environment)


class TriageService:
    def __init__(self, nvd: NvdClient, kev: KevClient, epss: EpssClient, cvedb: CveDbClient, settings: Settings,
                 monotonic: Callable[[], float] = time.monotonic):
        self.nvd, self.kev, self.epss, self.cvedb, self.s, self._mono = nvd, kev, epss, cvedb, settings, monotonic
        self._bg: set[asyncio.Task] = set()

    # ---- enrichment -------------------------------------------------------------------
    def _spawn(self, coro) -> asyncio.Task:
        t = asyncio.ensure_future(coro)
        self._bg.add(t)
        t.add_done_callback(lambda x: (self._bg.discard(x), x.cancelled() or x.exception()))
        return t

    async def _cvss_sources(self, cve: str, deadline: float) -> tuple[SourceResult, SourceResult | None]:
        """NVD first; if slow (> soft timeout) or unusable, race Shodan CVEDB as a labelled fallback."""
        # NVD runs on its own budget so a slow answer still lands in the cache for the next caller
        nvd_task = self._spawn(self.nvd.fetch(cve, self._mono() + self.s.nvd_timeout_sec))
        done, _ = await asyncio.wait({nvd_task}, timeout=self.s.nvd_soft_timeout_sec)
        if nvd_task in done:
            r = nvd_task.result()
            if r.usable and select_cvss(r.data) and select_cvss(r.data)["authoritative"]:
                return r, None
            if r.status == NOT_FOUND:
                return r, None
        fb = await self.cvedb.fetch(cve, deadline)
        if nvd_task.done():
            return nvd_task.result(), fb
        remaining = max(0.0, min(1.5, deadline - self._mono()))
        try:
            return await asyncio.wait_for(asyncio.shield(nvd_task), timeout=remaining), fb
        except asyncio.TimeoutError:
            return SourceResult("NVD", UNAVAILABLE, note="NVD did not answer within the time budget."), fb

    async def _enrich(self, cves: list[str], deadline: float):
        sem = asyncio.Semaphore(self.s.max_concurrency)

        async def one(c: str):
            async with sem:
                return c, await self._cvss_sources(c, deadline)

        epss_t = self._spawn(self.epss.fetch_many(cves, deadline))
        kev_t = self._spawn(asyncio.gather(*[self.kev.lookup(c, deadline) for c in cves]))
        cvss = dict(await asyncio.gather(*[one(c) for c in cves]))
        epss = await epss_t
        kev = dict(zip(cves, await kev_t))
        return cvss, epss, kev

    # ---- main -------------------------------------------------------------------------
    async def run(self, findings: list[Finding], *, request_id: str | None = None, errors: list[ItemError] | None = None,
                  top_n: int | None = None, include_remediation: bool = True, total_submitted: int | None = None,
                  notes: list[str] | None = None) -> TriageResponse:
        errors = list(errors or [])
        limitations: list[str] = list(notes or [])
        # de-duplicate (CVE, asset) pairs, remember how many were merged
        merged: dict[tuple[str, str], tuple[Finding, int]] = {}
        for f in findings:
            key = (f.cve_id, f.asset.model_dump_json() if f.asset else "")
            if key in merged:
                merged[key] = (merged[key][0], merged[key][1] + 1)
            else:
                merged[key] = (f, 0)
        uniq = list(merged.values())
        cves = sorted({f.cve_id for f, _ in uniq})
        deadline = self._mono() + self.s.request_deadline_sec

        cvss_map, epss_map, kev_map = ({}, {}, {})
        if cves:
            cvss_map, epss_map, kev_map = await self._enrich(cves, deadline)

        items: list[tuple[tuple, Priority]] = []
        for f, dups in uniq:
            nvd, fb = cvss_map[f.cve_id]
            items.append(self._assess(f, dups, nvd, fb, epss_map[f.cve_id], kev_map[f.cve_id], include_remediation))
        items.sort(key=lambda x: x[0])
        prios = [p for _, p in items]
        for n, p in enumerate(prios, 1):
            p.rank = n
        shown = prios[:top_n] if top_n else prios
        if top_n and len(prios) > top_n:
            limitations.append(f"Showing the top {top_n} of {len(prios)} analysed findings.")

        srcs = self._source_status(cvss_map, epss_map, kev_map)
        for name, st in srcs.items():
            if st in ("unavailable", "stale"):
                limitations.append(f"{name} was {st} for part of this request; affected findings carry explicit uncertainty.")
        if any(d for _, d in uniq):
            limitations.append("Duplicate (CVE, asset) findings were merged; see `duplicates_merged`.")

        scored = [p for p in prios if p.status == "scored"]
        summ = Summary(
            total_submitted=total_submitted if total_submitted is not None else len(findings) + len([e for e in errors if e.code != "batch_too_large"]),
            successfully_analysed=len(scored), insufficient_evidence=len(prios) - len(scored), failed=len(errors),
            critical=sum(p.priority == "critical" for p in prios), high=sum(p.priority == "high" for p in prios),
            medium=sum(p.priority == "medium" for p in prios), low=sum(p.priority == "low" for p in prios),
        )
        return TriageResponse(request_id=request_id, engine_version=ENGINE_VERSION, score_version=SCORE_VERSION,
                              generated_at=utc_iso(), summary=summ, priorities=shown, errors=errors,
                              limitations=limitations, source_status=srcs)

    @staticmethod
    def _source_status(cvss_map, epss_map, kev_map) -> dict[str, str]:
        def worst(results: list[str]) -> str:
            for s in (UNAVAILABLE, STALE):
                if s in results:
                    return s
            return AVAILABLE if results else "not_queried"
        return {
            "NVD": worst([r[0].status for r in cvss_map.values() if r[0].status != NOT_FOUND]),
            "FIRST EPSS": worst([r.status for r in epss_map.values() if r.status != NOT_FOUND]),
            "CISA KEV": worst([r.status for r in kev_map.values()]),
            "Shodan CVEDB (fallback)": "used" if any(r[1] is not None for r in cvss_map.values()) else "not_needed",
        }

    # ---- per-finding assessment ---------------------------------------------------------
    def _assess(self, f: Finding, dups: int, nvd: SourceResult, fb: SourceResult | None, epss: SourceResult,
                kev: SourceResult, include_remediation: bool):
        ev: list[Evidence] = []
        unc_extra: list[str] = []
        nd = nvd.data if nvd.usable else None

        # --- CVSS: NVD primary > NVD provisional > CVEDB fallback (always labelled)
        cvss_val = cvss_ver = cvss_vec = cvss_src = None
        authoritative = False
        sel = select_cvss(nd) if nd else None
        if sel:
            cvss_val, cvss_ver, cvss_vec = sel["score"], sel["version"], sel["vector"]
            authoritative = sel["authoritative"]
            cvss_src = f"NVD ({'primary' if authoritative else 'secondary/CNA'})"
            others = [e for e in nd["cvss"] if e is not None and e["version"] == sel["version"] and e["score"] != sel["score"]]
            if authoritative and others and max(abs(e["score"] - sel["score"]) for e in others) >= 1.0:
                unc_extra.append("CVSS sources conflict: NVD primary and a secondary (CNA) score differ by 1.0 or more.")
        elif fb and fb.usable and fb.data.get("cvss_v3") is not None:
            cvss_val, cvss_ver, cvss_src = fb.data["cvss_v3"], "3.x", "Shodan CVEDB (fallback)"
            unc_extra.append("NVD did not provide a usable score in time; CVSS is from the Shodan CVEDB fallback and is provisional.")
        if nd and nd.get("vuln_status") == "Rejected":
            unc_extra.append("NVD lists this CVE as REJECTED; it should not be treated as a valid vulnerability.")

        ev.append(Evidence(source_name="NVD", source_url=nvd.source_url, retrieved_at=nvd.retrieved_at,
                           source_updated_at=nvd.source_updated_at, field="cvss_base_score",
                           value=cvss_val if cvss_src and cvss_src.startswith("NVD") else None,
                           status=nvd.status if sel or nvd.status != AVAILABLE else "available_no_score", notes=nvd.note))
        if fb is not None:
            ev.append(Evidence(source_name=fb.source, source_url=fb.source_url, retrieved_at=fb.retrieved_at,
                               field="cvss_v3", value=(fb.data or {}).get("cvss_v3"), status=fb.status, notes=fb.note))

        # --- KEV
        kev_listed = None
        kev_info = None
        if kev.usable:
            kev_listed = bool(kev.data["listed"])
            kev_info = kev.data
        ev.append(Evidence(source_name="CISA KEV", source_url=kev.source_url, retrieved_at=kev.retrieved_at,
                           source_updated_at=kev.source_updated_at, field="kev_listed",
                           value=kev_listed, status=kev.status, notes=kev.note))
        # --- EPSS
        epss_p = epss_pct = None
        if epss.usable:
            epss_p, epss_pct = epss.data["probability"], epss.data["percentile"]
        ev.append(Evidence(source_name="FIRST EPSS", source_url=epss.source_url, retrieved_at=epss.retrieved_at,
                           source_updated_at=epss.source_updated_at, field="epss_probability", value=epss_p,
                           status=epss.status, notes=epss.note))
        # --- exploit references (NVD tags)
        refs = (nd or {}).get("exploit_refs", [])
        if nd:
            ev.append(Evidence(source_name="NVD", source_url=nvd.source_url, retrieved_at=nvd.retrieved_at,
                               field="exploit_reference_tags", value=refs[:5], status="available",
                               notes="References tagged 'Exploit' by NVD; absence is not proof that no exploit exists."))

        inputs = ScoreInputs(
            cvss=cvss_val, cvss_authoritative=authoritative, epss=epss_p, kev_listed=kev_listed,
            kev_ransomware=bool(kev_info and kev_info.get("ransomware")), exploit_ref=bool(refs), asset=_asset_ctx(f),
        )
        res = score(inputs)
        if nd and nd.get("vuln_status") == "Rejected":
            res.status, res.risk_score, res.priority = "insufficient_evidence", None, "insufficient_evidence"
        if nvd.status == NOT_FOUND and cvss_val is None and epss_p is None and kev_listed is not True:
            unc_extra.append("CVE not found in NVD; verify the identifier.")

        unc = res.uncertainty + unc_extra
        for r, name in ((nvd, "NVD"), (epss, "FIRST EPSS"), (kev, "CISA KEV")):
            if r.status in (UNAVAILABLE, STALE) and r.note:
                unc.append(r.note)

        why = explain.why_ranked_here(inputs, res, kev_info, epss_pct, severity_from_score(cvss_val))
        action = explain.recommended_action(res, inputs, kev_info) if include_remediation else None

        a = f.asset
        signals: dict[str, Any] = {
            "cvss": {"score": cvss_val, "version": cvss_ver, "severity": severity_from_score(cvss_val), "vector": cvss_vec,
                     "source": cvss_src, "authoritative": authoritative,
                     "status": "available" if cvss_val is not None else nvd.status},
            "epss": {"probability": epss_p, "percentile": epss_pct, "source": "FIRST EPSS", "status": epss.status,
                     "score_date": (epss.data or {}).get("score_date")},
            "kev": {"listed": kev_listed, "source": "CISA KEV", "status": kev.status,
                    "date_added": (kev_info or {}).get("date_added"), "due_date": (kev_info or {}).get("due_date"),
                    "known_ransomware_use": bool(kev_info and kev_info.get("ransomware"))},
            "public_exploit": {"status": "referenced" if refs else ("not_referenced_by_nvd" if nd else "unknown"),
                               "references": refs[:5], "source": "NVD reference tags"},
            "asset_context": {"criticality": a.criticality if a else None, "internet_exposed": (a.effective_exposure() == "internet") if a and a.effective_exposure() else None,
                              "exposure": a.effective_exposure() if a else None, "environment": a.environment if a else None,
                              "supplied": inputs.asset.supplied},
        }
        p = Priority(
            rank=0, cve_id=f.cve_id, asset_id=a.asset_id if a else None, status=res.status, priority=res.priority,
            risk_score=res.risk_score, score_version=res.score_version, evidence_coverage=res.evidence_coverage,
            confidence_label=res.confidence_label, why_ranked_here=why, signals=signals,
            score_breakdown=ScoreBreakdown(score_version=res.score_version, base_score=res.base_score,
                                           floors_applied=res.floors_applied,
                                           components=[ScoreComponent(dimension=c.dimension, raw_value=c.raw, status=c.status,
                                                                      nominal_weight=c.nominal_weight, effective_weight=c.effective_weight,
                                                                      points=c.points, detail=c.detail) for c in res.components]),
            recommended_action=action, evidence=ev, uncertainty=list(dict.fromkeys(unc)),
            scanner_severity=f.scanner_severity, component=f.component, installed_version=f.installed_version,
            duplicates_merged=dups,
        )
        key = rank_key(res.risk_score, kev_listed, epss_p, f.cve_id, a.asset_id if a and a.asset_id else "")
        return key, p
