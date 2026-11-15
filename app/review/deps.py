"""Dependency vulnerability scan: manifests -> OSV (read-only) -> CVE ids -> existing VulnRank triage engine.

Only exact, resolvable versions are checked (lockfiles, == pins, go.mod, Gemfile.lock). Ranges such as ^1.2.0 are counted as
`unpinned` and reported as a coverage limit, never silently treated as safe.
"""
from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, field
from typing import Awaitable, Callable

from app.ids import normalize_cve_id
from app.models import Finding as TriageFinding
from app.models import Priority
from app.review.findings import SEV_SCORE, Finding
from app.sources.base import Fetcher, SourceError
from app.sources.nvd import severity_from_score

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/{id}"
MAX_PACKAGES = 600
MAX_DETAIL_IDS = 40
MAX_TRIAGE_CVES = 20
_ORDER = ["critical", "high", "medium", "low", "info"]
GHSA_SEV = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}

Pkg = tuple[str, str, str, str]  # ecosystem, name, version, manifest path
_NON_APP = re.compile(r"(^|/)(tests?|__tests__|spec|fixtures?|mocks?|docs?|examples?|samples?|demos?|tutorials?|\.github|e2e)(/|$)", re.I)


def parse_manifests(files: dict[str, str]) -> tuple[list[Pkg], int, list[str]]:
    pkgs: list[Pkg] = []
    unpinned = 0
    manifests: list[str] = []
    paths = set(files)
    for path, text in files.items():
        base = path.rsplit("/", 1)[-1].lower()
        if _NON_APP.search(path):          # dependency files under docs/examples/tests are not the shipped product
            continue
        if base == "requirements.txt" or (base.startswith("requirements") and base.endswith(".txt")):
            manifests.append(path)
            for raw in text.splitlines():
                line = raw.split("#", 1)[0].split(";", 1)[0].strip()
                if not line or line.startswith(("-", "git+", "http")):
                    continue
                m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([0-9][A-Za-z0-9.+!_-]*)\s*$", line)
                if m:
                    pkgs.append(("PyPI", m.group(1), m.group(2), path))
                else:
                    unpinned += 1
        elif base == "package-lock.json":
            manifests.append(path)
            try:
                js = json.loads(text)
            except ValueError:
                continue
            if isinstance(js.get("packages"), dict):
                for k, v in js["packages"].items():
                    if k and isinstance(v, dict) and v.get("version") and "node_modules/" in k:
                        pkgs.append(("npm", k.rsplit("node_modules/", 1)[-1], v["version"], path))
            else:
                def walk(d):
                    for n, v in (d or {}).items():
                        if isinstance(v, dict):
                            if v.get("version"):
                                pkgs.append(("npm", n, v["version"], path))
                            walk(v.get("dependencies"))
                walk(js.get("dependencies"))
        elif base == "package.json" and "node_modules" not in path:
            lock = path.rsplit("/", 1)[0] + "/package-lock.json" if "/" in path else "package-lock.json"
            if lock in paths:
                continue
            manifests.append(path)
            try:
                js = json.loads(text)
            except ValueError:
                continue
            for sect in ("dependencies", "devDependencies"):
                for n, v in (js.get(sect) or {}).items():
                    if isinstance(v, str) and re.fullmatch(r"\d+\.\d+\.\d+", v.strip()):
                        pkgs.append(("npm", n, v.strip(), path))
                    else:
                        unpinned += 1
        elif base == "go.mod":
            manifests.append(path)
            for m in re.finditer(r"^\s*(?:require\s+)?([A-Za-z0-9][\w./~-]*\.[\w./~-]+)\s+v(\d[\w.+-]*)", text, re.M):
                pkgs.append(("Go", m.group(1), m.group(2), path))
        elif base == "gemfile.lock":
            manifests.append(path)
            for m in re.finditer(r"^    ([A-Za-z0-9_.-]+) \((\d[\w.]*)\)$", text, re.M):
                pkgs.append(("RubyGems", m.group(1), m.group(2), path))
    seen, uniq = set(), []
    for p in pkgs:
        if (p[0], p[1].lower(), p[2]) not in seen:
            seen.add((p[0], p[1].lower(), p[2]))
            uniq.append(p)
    return uniq, unpinned, manifests


@dataclass
class VulnDetail:
    osv_id: str
    aliases: list[str] = field(default_factory=list)
    summary: str = ""
    label: str | None = None
    fixed: dict[str, list[str]] = field(default_factory=dict)  # package(lower) -> fixed versions
    packages: list[tuple[str, str, str]] = field(default_factory=list)  # name, version, manifest

    @property
    def cves(self) -> list[str]:
        out = []
        for a in [self.osv_id] + self.aliases:
            if a.upper().startswith("CVE-"):
                try:
                    out.append(normalize_cve_id(a))
                except ValueError:
                    pass
        return list(dict.fromkeys(out))


@dataclass
class DepScan:
    findings: list[Finding] = field(default_factory=list)
    vuln_count: int = 0
    coverage: dict = field(default_factory=dict)


TriageFn = Callable[[list[str]], Awaitable[dict[str, Priority]]]


def _detail_from_osv(js: dict) -> VulnDetail:
    d = VulnDetail(js.get("id", ""), [a for a in js.get("aliases", []) if isinstance(a, str)], (js.get("summary") or js.get("details") or "")[:200])
    label = (js.get("database_specific") or {}).get("severity")
    d.label = GHSA_SEV.get(str(label).upper()) if label else None
    for aff in js.get("affected", []) or []:
        name = ((aff.get("package") or {}).get("name") or "").lower()
        for rg in aff.get("ranges", []) or []:
            for ev in rg.get("events", []) or []:
                if "fixed" in ev:
                    d.fixed.setdefault(name, []).append(ev["fixed"])
    return d


async def scan_dependencies(files: dict[str, str], fetcher: Fetcher, triage: TriageFn, *, deadline: float | None = None) -> DepScan:
    pkgs, unpinned, manifests = parse_manifests(files)
    return await scan_packages(pkgs, unpinned, manifests, fetcher, triage, deadline=deadline)


async def scan_packages(pkgs: list[Pkg], unpinned: int, manifests: list[str], fetcher: Fetcher, triage: TriageFn, *, deadline: float | None = None) -> DepScan:
    scan = DepScan(coverage={"manifests": manifests, "packages_checked": 0, "unpinned_not_checked": unpinned, "osv": "not_run"})
    if not pkgs:
        scan.coverage["osv"] = "no_pinned_packages"
        return scan
    truncated = len(pkgs) > MAX_PACKAGES
    pkgs = pkgs[:MAX_PACKAGES]
    scan.coverage["packages_checked"] = len(pkgs)
    scan.coverage["truncated"] = truncated
    queries = [{"package": {"name": n, "ecosystem": e}, "version": v} for e, n, v, _ in pkgs]
    try:
        _, js = await fetcher.get_json(OSV_BATCH, json_body={"queries": queries}, timeout=8.0, deadline=deadline)
    except SourceError as ex:
        scan.coverage["osv"] = f"unavailable ({ex.kind})"
        return scan
    results = (js or {}).get("results", [])
    by_id: dict[str, VulnDetail] = {}
    for (e, n, v, path), res in zip(pkgs, results):
        for vu in (res or {}).get("vulns", []) or []:
            vid = vu.get("id")
            if vid:
                by_id.setdefault(vid, VulnDetail(vid)).packages.append((n, v, path))
    scan.coverage["osv"] = "ok"
    scan.vuln_count = len(by_id)
    if not by_id:
        return scan

    sem = asyncio.Semaphore(16)

    async def detail(vid: str) -> None:
        async with sem:
            try:
                st, j = await fetcher.get_json(OSV_VULN.format(id=vid), timeout=6.0, deadline=deadline)
            except SourceError:
                return
        if st == 200 and isinstance(j, dict):
            d = _detail_from_osv(j)
            cur = by_id[vid]
            cur.aliases, cur.summary, cur.label, cur.fixed = d.aliases, d.summary, d.label, d.fixed

    ids = sorted(by_id)[:MAX_DETAIL_IDS]
    await asyncio.gather(*[detail(i) for i in ids])
    scan.coverage["details_fetched_for"] = len(ids)

    cve_order = []
    for vid in sorted(ids, key=lambda i: ["critical", "high", "medium", "low", None].index(by_id[i].label) if by_id[i].label in ("critical", "high", "medium", "low") else 4):
        cve_order.extend(c for c in by_id[vid].cves if c not in cve_order)
    prios = await triage(cve_order[:MAX_TRIAGE_CVES]) if cve_order else {}

    for vid in ids:
        d = by_id[vid]
        best: Priority | None = None
        for c in d.cves:
            p = prios.get(c)
            if p and p.status == "scored" and (best is None or (p.risk_score or 0) > (best.risk_score or 0)):
                best = p
        risk_pri = best.priority if best else None
        if risk_pri == "insufficient_evidence":
            risk_pri = None
        cvss = best.signals["cvss"]["score"] if best else None
        band = severity_from_score(cvss)
        # `severity` = the higher of the CVSS band and the exploitation-aware priority, so a CVSS 8.1 never reads "low";
        # the fix-first ORDER still follows the risk score, and both inputs stay visible in `detail`.
        cands = [x for x in (band if band != "none" else None, risk_pri, None if (band or risk_pri) else (d.label or "medium")) if x]
        sev = min(cands, key=lambda x: _ORDER.index(x))
        score = float(best.risk_score) if best and best.risk_score is not None else float(SEV_SCORE.get(sev, 45))
        pk = d.packages[0]
        fixed = d.fixed.get(pk[0].lower(), [])
        kev = bool(best and best.signals["kev"]["listed"])
        title = f"{pk[0]} {pk[1]}: {d.summary or d.osv_id}"
        why = []
        if best:
            why = best.why_ranked_here[:2]
        scan.findings.append(Finding(
            f"dep:{vid}", "security", "dependency", title[:160], sev,
            (f"Upgrade {pk[0]} to a fixed version ({', '.join(dict.fromkeys(fixed))[:80]})." if fixed else f"Upgrade or replace {pk[0]}; no fixed version was listed by OSV."),
            score=score, confidence="high" if best else "medium",
            evidence=[{"path": p[2], "package": f"{p[0]}@{p[1]}"} for p in d.packages[:3]],
            cves=d.cves, tags=(["CISA-KEV"] if kev else []),
            detail={"osv_id": vid, "cvss_severity": band, "risk_priority": risk_pri, **({"cvss_base_score": best.signals["cvss"]["score"], "epss": best.signals["epss"]["probability"], "kev_listed": kev,
                                      "why": why} if best else {"note": "No CVE alias scored; severity from the advisory label."})}))
    scan.findings.sort(key=lambda f: -f.score)
    return scan
