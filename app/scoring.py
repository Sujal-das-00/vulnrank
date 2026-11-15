"""Deterministic, versioned risk-scoring engine (score_version v1).

Pure functions only: no I/O, no clock, no randomness. Same input + same evidence snapshot
=> same output. Documented in docs/scoring-model.md.

risk = weighted mean of the dimensions that could be assessed:
    severity       30%  CVSS base score * 10
    exploitation   35%  0.5*EPSS + 0.3*KEV + 0.2*public-exploit-reference, re-normalised over
                        the sub-signals actually known (unknown is never treated as zero)
    criticality    20%  caller-supplied asset criticality (x environment factor)
    exposure       15%  caller-supplied network exposure
Missing dimensions are dropped and the remaining weights re-normalised; this is reported as
`evidence_coverage`. Floors (KEV etc.) are applied afterwards and are always listed.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

SCORE_VERSION = "v1"

DIM_WEIGHTS = {"severity": 0.30, "exploitation": 0.35, "criticality": 0.20, "exposure": 0.15}
EXPL_WEIGHTS = {"epss": 0.50, "kev": 0.30, "exploit_ref": 0.20}

CRITICALITY_SCORE = {"critical": 100.0, "high": 75.0, "medium": 50.0, "low": 25.0, "unknown": 40.0}
EXPOSURE_SCORE = {"internet": 100.0, "internal": 40.0, "isolated": 15.0, "unknown": 40.0}
ENV_FACTOR = {"production": 1.0, "staging": 0.75, "development": 0.5, "test": 0.5, "unknown": 1.0}
# A CNA/secondary (non-NVD-primary) CVSS is usable for ranking but flagged provisional.

THRESHOLDS = (("critical", 80.0), ("high", 60.0), ("medium", 40.0), ("low", 0.0))
PRIORITY_ORDER = {"critical": 3, "high": 2, "medium": 1, "low": 0}

Priority = Literal["critical", "high", "medium", "low", "insufficient_evidence"]


@dataclass(frozen=True)
class AssetContext:
    criticality: str | None = None   # critical|high|medium|low|unknown|None(not supplied)
    exposure: str | None = None      # internet|internal|isolated|unknown|None(not supplied)
    environment: str | None = None   # production|staging|development|test|unknown|None

    @property
    def supplied(self) -> bool:
        return any(v not in (None, "unknown") for v in (self.criticality, self.exposure, self.environment))


@dataclass(frozen=True)
class ScoreInputs:
    cvss: float | None = None            # 0-10
    cvss_authoritative: bool = True      # False => CNA/secondary/fallback (provisional)
    epss: float | None = None            # 0-1, None = unavailable/not published
    kev_listed: bool | None = None       # None = KEV could not be checked
    kev_ransomware: bool = False
    exploit_ref: bool = False            # NVD-tagged public exploit reference present
    asset: AssetContext = field(default_factory=AssetContext)


@dataclass
class Component:
    dimension: str
    raw: float | None
    status: str                 # used | not_assessed | defaulted
    nominal_weight: float
    effective_weight: float
    points: float               # contribution to the final 0-100 score
    detail: str


@dataclass
class ScoreResult:
    status: Literal["scored", "insufficient_evidence"]
    risk_score: float | None
    base_score: float | None
    priority: Priority
    components: list[Component]
    floors_applied: list[str]
    evidence_coverage: float
    confidence_label: Literal["high", "medium", "low"]
    uncertainty: list[str]
    score_version: str = SCORE_VERSION


def priority_for(score: float) -> str:
    for name, lo in THRESHOLDS:
        if score >= lo:
            return name
    return "low"


def exploitation_score(i: ScoreInputs) -> tuple[float | None, str, list[str]]:
    """Weighted mean over *known* sub-signals. KEV checked-and-not-listed is a known 0;
    KEV unchecked, EPSS unpublished, and no exploit reference are simply unknown."""
    parts: list[tuple[str, float, float]] = []
    notes: list[str] = []
    if i.epss is not None:
        parts.append(("EPSS", EXPL_WEIGHTS["epss"], i.epss * 100.0))
        notes.append(f"EPSS {i.epss:.4f}")
    if i.kev_listed is not None:
        parts.append(("KEV", EXPL_WEIGHTS["kev"], 100.0 if i.kev_listed else 0.0))
        notes.append("KEV listed" if i.kev_listed else "KEV not listed")
    if i.exploit_ref:
        parts.append(("exploit reference", EXPL_WEIGHTS["exploit_ref"], 100.0))
        notes.append("NVD-tagged exploit reference")
    if not parts:
        return None, "no exploitation signal available", notes
    tw = sum(w for _, w, _ in parts)
    return sum(w * v for _, w, v in parts) / tw, "; ".join(notes), notes


def score(i: ScoreInputs) -> ScoreResult:
    uncertainty: list[str] = []
    a = i.asset
    raw: dict[str, tuple[float | None, str, str]] = {}  # dim -> (value, status, detail)

    # severity
    if i.cvss is not None:
        tag = "" if i.cvss_authoritative else " (provisional: not the NVD primary score)"
        raw["severity"] = (i.cvss * 10.0, "used", f"CVSS {i.cvss:.1f}{tag}")
        if not i.cvss_authoritative:
            uncertainty.append("CVSS is provisional (not the NVD primary score); severity may change once NVD analyses the CVE.")
    else:
        raw["severity"] = (None, "not_assessed", "no CVSS score available")
        uncertainty.append("No CVSS base score available; severity not assessed.")

    # exploitation
    ex, ex_detail, _ = exploitation_score(i)
    if ex is not None:
        raw["exploitation"] = (ex, "used", ex_detail)
    else:
        raw["exploitation"] = (None, "not_assessed", ex_detail)
    if i.epss is None:
        uncertainty.append("EPSS probability not available.")
    if i.kev_listed is None:
        uncertainty.append("CISA KEV could not be checked; exploitation status from KEV is unknown (not 'negative').")

    # context (only assessed if the caller supplied something; otherwise dropped, not defaulted)
    if a.supplied:
        env_f = ENV_FACTOR.get(a.environment or "unknown", 1.0)
        crit_key = a.criticality or "unknown"
        crit = CRITICALITY_SCORE[crit_key] * env_f
        status = "used" if a.criticality not in (None, "unknown") else "defaulted"
        raw["criticality"] = (crit, status, f"criticality={crit_key}, environment={a.environment or 'unknown'} (x{env_f})")
        exp_key = a.exposure or "unknown"
        status = "used" if a.exposure not in (None, "unknown") else "defaulted"
        raw["exposure"] = (EXPOSURE_SCORE[exp_key], status, f"exposure={exp_key}")
        if a.criticality in (None, "unknown"):
            uncertainty.append("Asset criticality not supplied; neutral default (40) assumed.")
        if a.exposure in (None, "unknown"):
            uncertainty.append("Network exposure not supplied; neutral default (40) assumed.")
    else:
        raw["criticality"] = (None, "not_assessed", "no asset context supplied")
        raw["exposure"] = (None, "not_assessed", "no asset context supplied")
        uncertainty.append("No asset context supplied: ranked on public threat evidence only.")

    assessed = {d: v for d, (v, s, _) in raw.items() if v is not None}
    expected = 3 + (1 if a.supplied else 0)  # cvss, epss, kev (+ asset context if supplied)
    known = int(i.cvss is not None) + int(i.epss is not None) + int(i.kev_listed is not None) + int(a.supplied)
    coverage = round(known / expected, 2)

    # insufficient evidence: no CVSS and no *positive* exploitation information. "Not in KEV" alone says
    # nothing about the vulnerability (it is also true of CVEs that do not exist), and asset context
    # alone is not evidence about a vulnerability.
    if i.cvss is None and i.epss is None and not i.kev_listed and not i.exploit_ref:
        comps = [Component(d, None, "not_assessed", DIM_WEIGHTS[d], 0.0, 0.0, raw[d][2]) for d in DIM_WEIGHTS]
        return ScoreResult("insufficient_evidence", None, None, "insufficient_evidence", comps, [], 0.0, "low",
                           uncertainty + ["Insufficient evidence to produce a responsible ranking."])

    tw = sum(DIM_WEIGHTS[d] for d in assessed)
    comps: list[Component] = []
    base = 0.0
    for d, w in DIM_WEIGHTS.items():
        v, st, detail = raw[d]
        if v is None:
            comps.append(Component(d, None, st, w, 0.0, 0.0, detail))
            continue
        ew = w / tw
        pts = v * ew
        base += pts
        comps.append(Component(d, round(v, 2), st, w, round(ew, 4), round(pts, 2), detail))
    base = round(base, 2)

    # floors (documented, listed, never hidden)
    final = base
    floors: list[str] = []

    def floor(value: float, why: str) -> None:
        nonlocal final
        if final < value:
            final = value
            floors.append(f"{why} -> raised to minimum {value:g}")

    if i.kev_listed:
        floor(70.0, "CISA KEV listing (known exploited)")
        if i.kev_ransomware:
            floor(80.0, "KEV: known ransomware campaign use")
        if a.exposure == "internet" and a.criticality in ("critical", "high") and (a.environment or "production") == "production":
            floor(80.0, "KEV-listed on an internet-facing, high/critical production asset")
    final = round(min(final, 100.0), 2)

    # confidence (documented rules; refine against evaluation results)
    material_missing = int(i.cvss is None) + int(i.epss is None) + int(i.kev_listed is None)
    ctx_partial = a.supplied and (a.criticality in (None, "unknown") or a.exposure in (None, "unknown"))
    if material_missing >= 2:
        label = "low"
    elif material_missing == 1 or ctx_partial or not i.cvss_authoritative:
        label = "medium"
    else:
        label = "high"  # includes "no asset context": the *threat* assessment is still fully evidenced

    return ScoreResult("scored", final, base, priority_for(final), comps, floors, coverage, label, uncertainty)


def rank_key(risk: float | None, kev: bool | None, epss: float | None, cve_id: str, asset_id: str = ""):
    """Sort ascending by this key: score desc, KEV first, EPSS desc, then CVE id, then asset id."""
    return (-(risk if risk is not None else -1.0), 0 if kev else 1, -(epss if epss is not None else -1.0), cve_id, asset_id)
