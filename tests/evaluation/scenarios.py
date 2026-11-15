"""Labelled evaluation scenarios.

Expectations come from the security reasoning in the `why` field (CISA/EPSS/CVSS semantics and the blueprint's
scenario list), written BEFORE looking at engine output. Each scenario is a set of findings with the evidence
snapshot already resolved, so the evaluation is offline and deterministic.

`before` = list of (a, b) meaning a must rank strictly ahead of b. `last` = ids that must rank last.
`prio` = {id: allowed priorities}.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from app.scoring import AssetContext, ScoreInputs

A = AssetContext
PROD_EXPOSED_CRIT = A("critical", "internet", "production")
DEV_ISOLATED_LOW = A("low", "isolated", "development")


def F(cvss=None, epss=None, kev=False, ransom=False, ref=False, asset=None, auth=True) -> ScoreInputs:
    return ScoreInputs(cvss=cvss, cvss_authoritative=auth, epss=epss, kev_listed=kev, kev_ransomware=ransom,
                       exploit_ref=ref, asset=asset or A())


@dataclass
class Scenario:
    sid: str
    title: str
    why: str
    items: dict[str, ScoreInputs]
    before: list[tuple[str, str]] = field(default_factory=list)
    last: list[str] = field(default_factory=list)
    prio: dict[str, set[str]] = field(default_factory=dict)
    urgent: set[str] = field(default_factory=set)  # items a responder must fix first (for top-k recall)


S: list[Scenario] = []


def add(*a, **k):
    S.append(Scenario(*a, **k))


# --- the blueprint's headline cases -------------------------------------------------------------------
add("S01", "High CVSS, isolated low-criticality, no exploitation  vs  moderate CVSS, KEV, exposed critical asset",
    "Known exploitation on an exposed crown-jewel asset outranks a theoretical 9.8 nobody can reach.",
    {"CVE-2024-0001": F(9.8, 0.01, False, asset=DEV_ISOLATED_LOW),
     "CVE-2024-0002": F(6.5, 0.30, True, asset=PROD_EXPOSED_CRIT)},
    before=[("CVE-2024-0002", "CVE-2024-0001")], prio={"CVE-2024-0002": {"critical"}, "CVE-2024-0001": {"low", "medium"}},
    urgent={"CVE-2024-0002"})
add("S02", "High EPSS without KEV beats low EPSS, identical otherwise",
    "EPSS is the only exploitation signal here; a 0.9 vs 0.02 difference must matter.",
    {"CVE-2024-0010": F(7.5, 0.90, False), "CVE-2024-0011": F(7.5, 0.02, False)},
    before=[("CVE-2024-0010", "CVE-2024-0011")])
add("S03", "Missing EPSS is not treated as zero (known-high EPSS vs unknown EPSS)",
    "Unknown exploitation likelihood must not be ranked as if it were a measured low value; evidence-complete high EPSS leads.",
    {"CVE-2024-0020": F(7.5, 0.80, False), "CVE-2024-0021": F(7.5, None, False)},
    before=[("CVE-2024-0020", "CVE-2024-0021")])
add("S04", "Same CVE on two assets with different criticality/exposure",
    "Identical vulnerability: the exposed production crown-jewel is first.",
    {"CVE-2024-0030": F(8.1, 0.4, False, asset=PROD_EXPOSED_CRIT), "CVE-2024-0031": F(8.1, 0.4, False, asset=DEV_ISOLATED_LOW)},
    before=[("CVE-2024-0030", "CVE-2024-0031")])
add("S05", "KEV with ransomware use outranks KEV without, same context",
    "CISA flags ransomware use as an aggravating factor.",
    {"CVE-2024-0040": F(7.0, 0.5, True, ransom=True), "CVE-2024-0041": F(7.0, 0.5, True, ransom=False)},
    before=[("CVE-2024-0040", "CVE-2024-0041")])
add("S06", "Low-CVSS KEV outranks critical-CVSS non-KEV on the same internal asset",
    "KEV is evidence of real exploitation; CVSS 9.8 with EPSS 0.02 is not.",
    {"CVE-2024-0050": F(4.3, 0.2, True, asset=A("medium", "internal", "production")),
     "CVE-2024-0051": F(9.8, 0.02, False, asset=A("medium", "internal", "production"))},
    before=[("CVE-2024-0050", "CVE-2024-0051")], urgent={"CVE-2024-0050"})
add("S07", "NVD unavailable (no CVSS): KEV-listed item still outranks a mid-CVSS unexploited one",
    "A missing CVSS must not bury a known-exploited vulnerability.",
    {"CVE-2024-0060": F(None, 0.7, True), "CVE-2024-0061": F(5.0, 0.01, False)},
    before=[("CVE-2024-0060", "CVE-2024-0061")], urgent={"CVE-2024-0060"})
add("S08", "Insufficient-evidence finding ranks last, never first",
    "No CVSS and no exploitation information: cannot be ranked confidently.",
    {"CVE-2024-0070": F(None, None, False), "CVE-2024-0071": F(3.0, 0.001, False), "CVE-2024-0072": F(8.0, 0.2, False)},
    last=["CVE-2024-0070"], prio={"CVE-2024-0070": {"insufficient_evidence"}})
add("S09", "Production outranks staging, which outranks development (all else equal)",
    "Environment scales asset criticality.",
    {"CVE-2024-0080": F(8.0, 0.3, False, asset=A("high", "internet", "production")),
     "CVE-2024-0081": F(8.0, 0.3, False, asset=A("high", "internet", "staging")),
     "CVE-2024-0082": F(8.0, 0.3, False, asset=A("high", "internet", "development"))},
    before=[("CVE-2024-0080", "CVE-2024-0081"), ("CVE-2024-0081", "CVE-2024-0082")])
add("S10", "Internet-facing outranks internal outranks isolated (all else equal)",
    "Exposure ordering.",
    {"CVE-2024-0090": F(7.5, 0.2, False, asset=A("high", "internet", "production")),
     "CVE-2024-0091": F(7.5, 0.2, False, asset=A("high", "internal", "production")),
     "CVE-2024-0092": F(7.5, 0.2, False, asset=A("high", "isolated", "production"))},
    before=[("CVE-2024-0090", "CVE-2024-0091"), ("CVE-2024-0091", "CVE-2024-0092")])
add("S11", "Criticality ordering (all else equal)",
    "critical > high > medium > low.",
    {"CVE-2024-0100": F(7.5, 0.2, False, asset=A("critical", "internal", "production")),
     "CVE-2024-0101": F(7.5, 0.2, False, asset=A("high", "internal", "production")),
     "CVE-2024-0102": F(7.5, 0.2, False, asset=A("medium", "internal", "production")),
     "CVE-2024-0103": F(7.5, 0.2, False, asset=A("low", "internal", "production"))},
    before=[("CVE-2024-0100", "CVE-2024-0101"), ("CVE-2024-0101", "CVE-2024-0102"), ("CVE-2024-0102", "CVE-2024-0103")])
add("S12", "Limited remediation budget: of 8 findings, the three KEV items must be the top three",
    "With capacity for 3 fixes, responders must pick the actively exploited ones.",
    {"CVE-2024-0110": F(9.8, 0.05, False, asset=A("high", "internet", "production")),
     "CVE-2024-0111": F(5.4, 0.6, True, asset=A("medium", "internal", "production")),
     "CVE-2024-0112": F(8.8, 0.02, False, asset=A("critical", "internet", "production")),
     "CVE-2024-0113": F(6.1, 0.9, True, asset=A("high", "internet", "production")),
     "CVE-2024-0114": F(7.2, 0.01, False, asset=A("low", "isolated", "test")),
     "CVE-2024-0115": F(9.0, 0.7, True, asset=A("critical", "internet", "production")),
     "CVE-2024-0116": F(4.0, 0.001, False),
     "CVE-2024-0117": F(7.5, 0.03, False, asset=A("medium", "internal", "staging"))},
    before=[(k, n) for k in ("CVE-2024-0111", "CVE-2024-0113", "CVE-2024-0115") for n in
            ("CVE-2024-0110", "CVE-2024-0112", "CVE-2024-0114", "CVE-2024-0116", "CVE-2024-0117")],
    urgent={"CVE-2024-0111", "CVE-2024-0113", "CVE-2024-0115"})
add("S13", "Exploit reference (NVD-tagged) lifts an otherwise identical finding",
    "A published exploit is a threat signal even without KEV.",
    {"CVE-2024-0120": F(7.5, 0.1, False, ref=True), "CVE-2024-0121": F(7.5, 0.1, False, ref=False)},
    before=[("CVE-2024-0120", "CVE-2024-0121")])
add("S14", "Deterministic tie-break: identical evidence ordered by KEV, EPSS then CVE id",
    "Stable, reproducible queue.",
    {"CVE-2024-0132": F(7.0, 0.2, False), "CVE-2024-0131": F(7.0, 0.2, False), "CVE-2024-0133": F(7.0, 0.2, False)},
    before=[("CVE-2024-0131", "CVE-2024-0132"), ("CVE-2024-0132", "CVE-2024-0133")])
add("S15", "Authoritative NVD score vs provisional (CNA) score with otherwise equal evidence",
    "Equal numbers; the ranking must still be defined (ties broken by id) and the provisional one carries lower confidence.",
    {"CVE-2024-0140": F(7.0, 0.2, False, auth=False), "CVE-2024-0141": F(7.0, 0.2, False, auth=True)},
    before=[("CVE-2024-0140", "CVE-2024-0141")])  # tie -> lexicographic; confidence asserted separately in the runner
add("S16", "Everything critical but nothing exploited vs medium with high EPSS + exposure",
    "Likelihood and exposure should be able to overtake raw severity.",
    {"CVE-2024-0150": F(9.1, 0.004, False, asset=A("medium", "internal", "production")),
     "CVE-2024-0151": F(6.8, 0.85, False, asset=A("high", "internet", "production"))},
    before=[("CVE-2024-0151", "CVE-2024-0150")])

# --- parameter sweeps (variants of the headline invariants) -------------------------------------------
for n, (k_cvss, hi_cvss) in enumerate([(3.1, 9.0), (5.0, 9.9), (7.0, 9.8), (4.0, 8.0), (2.0, 7.5)]):
    a, b = f"CVE-2023-{1000 + n}", f"CVE-2023-{2000 + n}"
    add(f"S{17 + n}", f"Sweep: KEV CVSS {k_cvss} (internet, high-crit prod) vs non-KEV CVSS {hi_cvss} (isolated, low-crit dev)",
        "Contextual KEV on an exposed important asset beats an unexploited, unreachable high-CVSS finding.",
        {a: F(k_cvss, 0.2, True, asset=A("high", "internet", "production")), b: F(hi_cvss, 0.01, False, asset=DEV_ISOLATED_LOW)},
        before=[(a, b)], urgent={a})
for n, (hi, lo) in enumerate([(0.95, 0.05), (0.60, 0.01), (0.30, 0.001), (0.50, 0.10)]):
    a, b = f"CVE-2023-{3000 + n}", f"CVE-2023-{4000 + n}"
    add(f"S{22 + n}", f"Sweep: EPSS {hi} vs {lo}", "Higher EPSS first when everything else is equal.",
        {a: F(6.0, hi, False, asset=A("medium", "internal", "production")), b: F(6.0, lo, False, asset=A("medium", "internal", "production"))},
        before=[(a, b)])
for n, (c1, c2) in enumerate([(9.8, 5.0), (8.0, 4.0), (7.0, 3.0)]):
    a, b = f"CVE-2023-{5000 + n}", f"CVE-2023-{6000 + n}"
    add(f"S{26 + n}", f"Sweep: CVSS {c1} vs {c2}, nothing else known (no context)", "With identical (absent) other evidence, severity decides.",
        {a: F(c1, 0.05, False), b: F(c2, 0.05, False)}, before=[(a, b)])
add("S29", "Ransomware-KEV on internal low asset vs non-KEV critical on exposed critical asset (judgment call)",
    "Both are defensible; the engine must at least place the ransomware-KEV item in the top priority band.",
    {"CVE-2024-0160": F(6.0, 0.4, True, ransom=True, asset=A("low", "internal", "production")),
     "CVE-2024-0161": F(9.8, 0.2, False, asset=PROD_EXPOSED_CRIT)},
    prio={"CVE-2024-0160": {"critical", "high"}})
add("S30", "Dev/test box with KEV and no exposure is not 'critical' by default",
    "KEV raises urgency but an isolated test machine should not outrank an exposed production KEV.",
    {"CVE-2024-0170": F(8.0, 0.8, True, asset=A("low", "isolated", "test")),
     "CVE-2024-0171": F(8.0, 0.8, True, asset=A("high", "internet", "production"))},
    before=[("CVE-2024-0171", "CVE-2024-0170")], prio={"CVE-2024-0170": {"high", "medium"}})

# invalid-input classification set: (input, should_be_accepted)
ID_CASES = [("CVE-2021-44228", True), ("cve-2021-44228", True), (" CVE-2024-3094 ", True), ("CVE-2026-114713", True),
            ("CVE-21-1", False), ("CVE-2021-12", False), ("2021-44228", False), ("CVE-2021-44228; DROP TABLE", False),
            ("", False), ("log4shell", False), ("https://nvd.nist.gov/CVE-2021-44228", False), ("CVE-2021-", False),
            ("CVE-1800-1234", False), ("CVE-2021-44228\n", True), ("CVE_2021_44228", True)]
