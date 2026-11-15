# Scoring model v1

Deterministic, versioned, no LLM. Implemented in `app/scoring.py` (pure functions); every constant below is exposed at
`GET /v1/score-model`. The score is a **prioritisation heuristic, not a calibrated probability of compromise**.

## Formula

```
risk = Σ w_d · s_d / Σ w_d      over the dimensions d that could be assessed
```

| Dimension | Weight | Score s_d (0-100) |
|---|---|---|
| severity | 0.30 | CVSS base score × 10 (NVD primary v3.1, else v3.0, else labelled provisional) |
| exploitation | 0.35 | weighted mean of the *known* sub-signals: EPSS×100 (0.5), KEV 100/0 (0.3), NVD-tagged exploit reference 100 (0.2) |
| criticality | 0.20 | critical 100 · high 75 · medium 50 · low 25 · unknown 40, × environment factor (production 1.0, staging 0.75, development/test 0.5) |
| exposure | 0.15 | internet 100 · internal 40 · isolated 15 · unknown 40 |

## Missing-signal policy (never zero)

* A dimension or sub-signal that cannot be assessed is **dropped and the remaining weights re-normalised**; the result lists
  each component with `status` = `used` / `defaulted` / `not_assessed`.
* KEV checked and not listed is a *known* 0. KEV that could not be checked is *unknown* and excluded.
* No exploit reference tagged by NVD is *unknown*, not a negative (so it is excluded rather than scored 0).
* No asset context at all: criticality and exposure are `not_assessed` (the ranking reflects public threat evidence only and says so).
  Partial context: the missing field defaults to the neutral 40 and is flagged `defaulted`.
* `insufficient_evidence` is returned (no score, ranked last) when there is no CVSS, no EPSS, no KEV listing and no exploit reference.
  "Not in KEV" alone is not evidence; neither is asset context.

## Floors (listed in `score_breakdown.floors_applied` only when they change the result)

| Condition | Minimum score |
|---|---|
| Listed in CISA KEV | 70 (high) |
| KEV + known ransomware campaign use | 80 (critical) |
| KEV, internet-facing, high/critical criticality, production | 80 (critical) |

CVSS ≥ 9 never auto-wins; scanner severity is stored but never used as evidence.

## Priority bands

critical ≥ 80 · high ≥ 60 · medium ≥ 40 · low < 40.

## Ranking and tie-breaks

Risk score desc → KEV-listed first → EPSS desc → CVE id → asset id. Findings with `insufficient_evidence` sort last.

## Confidence and evidence coverage (separate from the score)

* `evidence_coverage` = known signals / expected signals (CVSS, EPSS, KEV, plus asset context if supplied).
* `confidence_label`: **high** = CVSS (NVD primary), EPSS and KEV all known and any supplied context complete;
  **medium** = one material signal missing, partial context, or provisional CVSS; **low** = two or more missing.
* `uncertainty[]` lists every missing/stale/provisional/conflicting fact in words. NVD primary vs secondary scores
  differing by ≥ 1.0 is reported as a conflict.

These thresholds and weights are initial product rules; change them only with a matching change to
`tests/evaluation/scenarios.py` and a bumped `score_version`.
