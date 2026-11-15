"""Orchestrates a launch review: fetch (repo and/or site) -> security scan -> legal checklist -> one ranked fix-first list."""
from __future__ import annotations

import asyncio
import time
from typing import Any, Callable

import httpx

from app.clock import utc_iso
from app.config import ENGINE_VERSION, Settings
from app.models import Finding as TriageFinding
from app.models import Priority
from app.review import github
from app.review.deps import scan_dependencies
from app.review.evidence import Doc, extract_signals
from app.review.findings import SEV_SCORE, Finding
from app.review.legal import attach_security_relevance, evaluate, infer_sector, load_rules
from app.review.netguard import SafeFetcher
from app.review.secrets import scan_code_patterns, scan_secrets
from app.review.site import scan_site
from app.review.target import Target, parse_target
from app.sources.base import Fetcher
from app.triage import TriageService

TOP_N = 12


class ReviewService:
    def __init__(self, triage: TriageService, fetcher: Fetcher, client: httpx.AsyncClient, safe: SafeFetcher, settings: Settings,
                 monotonic: Callable[[], float] = time.monotonic):
        self.triage, self.fetcher, self.client, self.safe, self.s, self._mono = triage, fetcher, client, safe, settings, monotonic

    async def _triage_cves(self, cves: list[str], budget: float | None = None) -> dict[str, Priority]:
        """Rank CVEs with the VulnRank engine. If it cannot finish in `budget`, return {} so callers fall back to advisory labels."""
        if not cves:
            return {}
        try:
            resp = await asyncio.wait_for(self.triage.run([TriageFinding(cve_id=c) for c in cves]), budget)
        except asyncio.TimeoutError:
            return {}
        return {p.cve_id: p for p in resp.priorities}

    async def run(self, target_text: str, *, country: str | None = None, sector: str | None = None) -> dict[str, Any]:
        tgt = parse_target(target_text, country=country, sector=sector)
        if not tgt.reviewable:
            return self._no_target(tgt)
        t0 = self._mono()
        deadline = t0 + self.s.review_deadline_sec
        left = lambda: deadline - self._mono()            # noqa: E731
        coverage: dict[str, Any] = {}
        files: dict[str, str] = {}
        site_docs: list[Doc] = []
        findings: list[Finding] = []
        dep_vulns = 0
        locations = 0

        async def do_repo():
            nonlocal files
            name = f"{tgt.repo[0]}/{tgt.repo[1]}"
            try:
                snap = await asyncio.wait_for(github.fetch_repo(self.client, *tgt.repo, timeout=max(1.0, left() - 1)), max(1.0, left()))
                files = snap.files
                coverage["repo"] = {"repository": name, "fetched": True, **snap.stats}
            except github.RepoError as ex:
                coverage["repo"] = {"repository": name, "fetched": False, "reason": str(ex)}
            except asyncio.TimeoutError:
                coverage["repo"] = {"repository": name, "fetched": False, "reason": "timed out"}

        async def do_site():
            try:
                scan = await asyncio.wait_for(scan_site(self.safe, tgt.site_url, deadline=deadline - 1), max(1.0, left()))
                site_docs.extend(scan.docs)
                findings.extend(scan.findings)
                coverage["site"] = {"url": tgt.site_url, **scan.coverage}
            except asyncio.TimeoutError:
                coverage["site"] = {"url": tgt.site_url, "fetched": False, "reason": "timed out"}

        await asyncio.gather(*([do_repo()] if tgt.repo else []), *([do_site()] if tgt.site_url else []))

        scan_files = dict(files)
        if tgt.snippet:
            scan_files["snippet.txt"] = tgt.snippet
            coverage["snippet"] = {"lines": tgt.snippet.count("\n") + 1, "method": "pattern rules only (not a proof of safety)"}
        if scan_files and left() > 0.5:
            try:
                secrets, patterns = await asyncio.wait_for(asyncio.gather(
                    asyncio.to_thread(scan_secrets, scan_files),
                    asyncio.to_thread(scan_code_patterns, scan_files, any_ext=bool(tgt.snippet and not files))), max(0.5, left()))
                findings.extend(secrets + patterns)
                locations = sum(f.detail.get("locations", len(f.evidence) or 1) for f in secrets + patterns)
            except asyncio.TimeoutError:
                coverage["code_scan"] = "timed out; code-pattern and secret results omitted"
        elif scan_files:
            coverage["code_scan"] = "skipped (time budget used up)"

        dep_vulns, dep_findings = await self._dependencies(tgt, files, coverage, left, deadline)
        findings.extend(dep_findings)

        legal = None
        sector_used = tgt.sector
        assumptions = list(tgt.assumptions)
        if tgt.legal_requested and (files or site_docs):
            docs = [Doc(p, "file", t) for p, t in files.items()] + site_docs
            sig = await asyncio.to_thread(extract_signals, docs)             # CPU-bound: keep the event loop free
            sector_used = tgt.sector or infer_sector(sig)
            if not tgt.sector:
                assumptions.append(f"Business sector not given; inferred '{sector_used}' from the code" + (" (checkout/cart code found)." if sector_used == "ecommerce" else " (no checkout code found)."))
            legal = evaluate(sig, tgt.jurisdictions, sector_used)
            findings.extend(legal.findings)
        if tgt.jurisdictions:
            attach_security_relevance(findings, tgt.jurisdictions)
        if left() < 0:
            assumptions.append("The review hit its time budget; results above are partial (see scan_coverage).")
        return self._assemble(tgt, sector_used, findings, legal, coverage, assumptions, dep_vulns, locations, round(self._mono() - t0, 1))

    async def _dependencies(self, tgt: Target, files: dict[str, str], coverage: dict, left, deadline: float):
        """Repo manifests and/or package versions named in the request -> OSV -> VulnRank triage."""
        from app.review.deps import parse_manifests, scan_packages
        pkgs, unpinned, manifests = parse_manifests(files) if files else ([], 0, [])
        for eco, name, ver in tgt.packages:
            for e in (("npm", "PyPI") if eco == "?" else (eco,)):
                pkgs.append((e, name, ver, "(named in request)"))
        if not pkgs and not unpinned:
            if files:
                coverage["dependencies"] = {"osv": "no_pinned_packages", "manifests": manifests}
            return 0, []
        if left() < 1.0:
            coverage["dependencies"] = {"osv": "skipped (time budget used up)"}
            return 0, []
        async def triage(cves: list[str]):
            out = await self._triage_cves(cves, max(1.5, left() - 2.5))
            if cves and not out:
                coverage["triage"] = "VulnRank scoring did not finish in time (slow upstream); severities below come from the OSV advisory labels. Re-run for KEV/EPSS-based ranking."
            return out
        try:
            scan = await asyncio.wait_for(scan_packages(pkgs, unpinned, manifests, self.fetcher, triage, deadline=deadline), max(1.0, left()))
        except asyncio.TimeoutError:
            coverage["dependencies"] = {"osv": "timed out; dependency results omitted"}
            return 0, []
        coverage["dependencies"] = scan.coverage
        return scan.vuln_count, scan.findings

    # ------------------------------------------------------------------ output
    def _no_target(self, tgt: Target) -> dict[str, Any]:
        msg = ("No reviewable target was found. Send code or a diff, package versions (e.g. 'lodash@4.17.15' or 'django==3.2.0'), "
               "a public GitHub repository (github.com/owner/repo) or a website URL, optionally with countries (EU, India, US) and sector "
               "(SaaS or e-commerce), e.g. 'github.com/acme/shop eu india ecommerce'.")
        return {"verdict": None, "vulnerability_count": None, "issues": [], "summary": msg, "answer": msg, "status": "no_target", "fix_first": [], "priority": "none", "confidence": 0.0,
                "as_of": utc_iso(time.time()), "engine_version": ENGINE_VERSION}

    def _assemble(self, tgt: Target, sector: str | None, findings: list[Finding], legal, coverage: dict, assumptions: list[str], dep_vulns: int,
                  locations: int, seconds: float) -> dict[str, Any]:
        findings = sorted(findings, key=lambda f: (-f.score, f.id))
        sec = [f for f in findings if f.category == "security"]
        comp = [f for f in findings if f.category == "compliance"]
        scanned = bool(coverage.get("repo", {}).get("fetched") or coverage.get("site", {}).get("fetched") or "snippet" in coverage
                       or coverage.get("dependencies", {}).get("osv") == "ok")
        vuln_count = dep_vulns + locations + sum(1 for f in sec if f.kind == "site_header")
        sev = {s: sum(1 for f in sec if f.severity == s) for s in ("critical", "high", "medium", "low")}
        kev = any("CISA-KEV" in f.tags for f in sec)
        if not scanned:
            verdict, why = None, "nothing could be fetched"
        elif sev["critical"] or kev:
            verdict, why = "Insecure", "critical or known-exploited issues present"
        elif sev["high"] or sev["medium"]:
            verdict, why = "Needs changes", "high or medium security issues present"
        elif sec:
            verdict, why = "Needs changes", "only low-severity security observations"
        else:
            verdict, why = "Secure", "no security issues detected in what was scanned" + (" (pattern rules only; not a proof of safety)" if "snippet" in coverage and not tgt.repo else "")
        gaps = [f for f in comp if "upcoming" not in f.tags]
        high_gaps = [f for f in gaps if f.severity in ("critical", "high") and f.confidence != "low"]  # weak evidence never blocks a launch
        readiness = ("blocked" if (verdict == "Insecure" or high_gaps) else "conditional" if (verdict == "Needs changes" or gaps) else "ready") if scanned else "unknown"
        issues: list[str] = []
        for f in sec:
            for t in (f.cves or f.tags[:1] or [f.id]):
                if t not in issues and not t.startswith("CISA"):
                    issues.append(t)
        top = findings[:TOP_N]
        fix_first = []
        for i, f in enumerate(top, 1):
            d = f.to_dict()
            d["rank"] = i
            fix_first.append(d)
        sec_n, comp_n = len(sec), len(gaps)
        parts = [f"Verdict: {verdict or 'not determined'} ({why}); launch readiness: {readiness}.",
                 f"{vuln_count} security issue(s) found" + (f" ({sev['critical']} critical, {sev['high']} high, {sev['medium']} medium)" if sec_n else "") +
                 (f"; {comp_n} compliance item(s) not detected for {', '.join(j.upper() for j in tgt.jurisdictions)} ({sector})." if legal else ".")]
        if top:
            parts.append("Fix first: " + " | ".join(f"{i}. {f.title[:70]}" for i, f in enumerate(top[:3], 1)) + ".")
        parts.append("Not legal advice; 'not detected' means no evidence was found by this scan.")
        short = " ".join(parts)
        cfg = load_rules()
        return {
            "verdict": verdict, "vulnerability_count": vuln_count if scanned else None, "issues": issues[:20], "summary": short, "answer": short,
            "launch_readiness": readiness,
            "priority": (top[0].severity if top and top[0].category == "security" else (sec[0].severity if sec else "none")),
            "confidence": 0.9 if scanned and not any("time budget" in str(v) or "timed out" in str(v) for v in coverage.values()) else 0.5 if scanned else 0.0,
            "target": {"repository": f"{tgt.repo[0]}/{tgt.repo[1]}" if tgt.repo else None, "site": tgt.site_url,
                       "packages": [f"{e}:{n}@{v}" for e, n, v in tgt.packages], "code_snippet": bool(tgt.snippet), "jurisdictions": tgt.jurisdictions, "sector": sector},
            "fix_first": fix_first,
            "security": {"counts": sev, "scored_via": "VulnRank triage engine (NVD, CISA KEV, FIRST EPSS) for dependency CVEs"},
            "compliance": ({
                "checklist": [self._compact_check(c) for c in legal.checklist],
                "legal_exposure": legal.exposure,
                "rules_table_as_of": cfg["as_of"],
            } if legal else {"checklist": [], "legal_exposure": [], "note": "The legal checklist needs a repository or website to inspect; none was reviewed."}),
            "scan_coverage": coverage, "assumptions": assumptions, "disclaimer": cfg["disclaimer"].strip().replace("\n", " "),
            "scan_seconds": seconds, "as_of": utc_iso(time.time()), "engine_version": ENGINE_VERSION,
        }

    @staticmethod
    def _compact_check(c: dict) -> dict:
        keep = ("id", "status", "title", "citation", "severity", "confidence", "note", "caveat")
        out = {k: c[k] for k in keep if k in c}
        out["jurisdictions"] = c["jurisdictions"]
        return out
