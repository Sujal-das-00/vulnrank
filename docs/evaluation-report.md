# VulnRank evaluation report (score_version v1)

Offline, deterministic: evidence snapshots are fixed inputs, so this measures the *scoring and ranking logic*, not upstream data quality or live latency. Expectations were written from security reasoning before running the engine (see `tests/evaluation/scenarios.py`). Many scenarios are parameter sweeps of the same invariants, so treat the count as breadth of coverage, not as independent samples. The scenarios are the author's, not an external benchmark.

## Metrics

| Metric | Result |
|---|---|
| Scenarios | 30 |
| Pairwise ordering agreement with labels | 48/48 (100%) |
| Priority-band expectations met | 5/5 (100%) |
| Urgent-set recall (all must-fix items within top-k, k = size of set) | 9/9 (100%) |
| Determinism (5 shuffled input orders -> identical ranking) | 30/30 (100%) |
| CVE identifier accept/reject accuracy | 15/15 (100%) |

## Failures

None.

## Scenarios

### S01 PASS - High CVSS, isolated low-criticality, no exploitation  vs  moderate CVSS, KEV, exposed critical asset
*Why:* Known exploitation on an exposed crown-jewel asset outranks a theoretical 9.8 nobody can reach.

| rank | CVE | risk | priority | confidence |
|---|---|---|---|---|
| 1 | CVE-2024-0002 | 80.0 | critical | high |
| 2 | CVE-2024-0001 | 34.37 | low | high |

### S02 PASS - High EPSS without KEV beats low EPSS, identical otherwise
*Why:* EPSS is the only exploitation signal here; a 0.9 vs 0.02 difference must matter.

| rank | CVE | risk | priority | confidence |
|---|---|---|---|---|
| 1 | CVE-2024-0010 | 64.9 | high | high |
| 2 | CVE-2024-0011 | 35.29 | low | high |

### S03 PASS - Missing EPSS is not treated as zero (known-high EPSS vs unknown EPSS)
*Why:* Unknown exploitation likelihood must not be ranked as if it were a measured low value; evidence-complete high EPSS leads.

| rank | CVE | risk | priority | confidence |
|---|---|---|---|---|
| 1 | CVE-2024-0020 | 61.54 | high | high |
| 2 | CVE-2024-0021 | 34.62 | low | medium |

### S04 PASS - Same CVE on two assets with different criticality/exposure
*Why:* Identical vulnerability: the exposed production crown-jewel is first.

| rank | CVE | risk | priority | confidence |
|---|---|---|---|---|
| 1 | CVE-2024-0030 | 68.05 | high | high |
| 2 | CVE-2024-0031 | 37.8 | low | high |

### S05 PASS - KEV with ransomware use outranks KEV without, same context
*Why:* CISA flags ransomware use as an aggravating factor.

| rank | CVE | risk | priority | confidence |
|---|---|---|---|---|
| 1 | CVE-2024-0040 | 80.0 | critical | high |
| 2 | CVE-2024-0041 | 70.0 | high | high |

### S06 PASS - Low-CVSS KEV outranks critical-CVSS non-KEV on the same internal asset
*Why:* KEV is evidence of real exploitation; CVSS 9.8 with EPSS 0.02 is not.

| rank | CVE | risk | priority | confidence |
|---|---|---|---|---|
| 1 | CVE-2024-0050 | 70.0 | high | high |
| 2 | CVE-2024-0051 | 45.84 | medium | high |

### S07 PASS - NVD unavailable (no CVSS): KEV-listed item still outranks a mid-CVSS unexploited one
*Why:* A missing CVSS must not bury a known-exploited vulnerability.

| rank | CVE | risk | priority | confidence |
|---|---|---|---|---|
| 1 | CVE-2024-0060 | 81.25 | critical | medium |
| 2 | CVE-2024-0061 | 23.41 | low | high |

### S08 PASS - Insufficient-evidence finding ranks last, never first
*Why:* No CVSS and no exploitation information: cannot be ranked confidently.

| rank | CVE | risk | priority | confidence |
|---|---|---|---|---|
| 1 | CVE-2024-0072 | 43.65 | medium | high |
| 2 | CVE-2024-0071 | 13.88 | low | high |
| 3 | CVE-2024-0070 | - | insufficient_evidence | low |

### S09 PASS - Production outranks staging, which outranks development (all else equal)
*Why:* Environment scales asset criticality.

| rank | CVE | risk | priority | confidence |
|---|---|---|---|---|
| 1 | CVE-2024-0080 | 60.56 | high | high |
| 2 | CVE-2024-0081 | 56.81 | medium | high |
| 3 | CVE-2024-0082 | 53.06 | medium | high |

### S10 PASS - Internet-facing outranks internal outranks isolated (all else equal)
*Why:* Exposure ordering.

| rank | CVE | risk | priority | confidence |
|---|---|---|---|---|
| 1 | CVE-2024-0090 | 56.88 | medium | high |
| 2 | CVE-2024-0091 | 47.88 | medium | high |
| 3 | CVE-2024-0092 | 44.12 | medium | high |

### S11 PASS - Criticality ordering (all else equal)
*Why:* critical > high > medium > low.

| rank | CVE | risk | priority | confidence |
|---|---|---|---|---|
| 1 | CVE-2024-0100 | 52.88 | medium | high |
| 2 | CVE-2024-0101 | 47.88 | medium | high |
| 3 | CVE-2024-0102 | 42.88 | medium | high |
| 4 | CVE-2024-0103 | 37.88 | low | high |

### S12 PASS - Limited remediation budget: of 8 findings, the three KEV items must be the top three
*Why:* With capacity for 3 fixes, responders must pick the actively exploited ones.

| rank | CVE | risk | priority | confidence |
|---|---|---|---|---|
| 1 | CVE-2024-0115 | 90.44 | critical | high |
| 2 | CVE-2024-0113 | 81.11 | critical | high |
| 3 | CVE-2024-0111 | 70.0 | high | high |
| 4 | CVE-2024-0112 | 61.84 | high | high |
| 5 | CVE-2024-0110 | 60.49 | high | high |
| 6 | CVE-2024-0117 | 36.66 | low | high |
| 7 | CVE-2024-0114 | 26.57 | low | high |
| 8 | CVE-2024-0116 | 18.5 | low | high |

### S13 PASS - Exploit reference (NVD-tagged) lifts an otherwise identical finding
*Why:* A published exploit is a threat signal even without KEV.

| rank | CVE | risk | priority | confidence |
|---|---|---|---|---|
| 1 | CVE-2024-0120 | 48.08 | medium | high |
| 2 | CVE-2024-0121 | 37.98 | low | high |

### S14 PASS - Deterministic tie-break: identical evidence ordered by KEV, EPSS then CVE id
*Why:* Stable, reproducible queue.

| rank | CVE | risk | priority | confidence |
|---|---|---|---|---|
| 1 | CVE-2024-0131 | 39.04 | low | high |
| 2 | CVE-2024-0132 | 39.04 | low | high |
| 3 | CVE-2024-0133 | 39.04 | low | high |

### S15 PASS - Authoritative NVD score vs provisional (CNA) score with otherwise equal evidence
*Why:* Equal numbers; the ranking must still be defined (ties broken by id) and the provisional one carries lower confidence.

| rank | CVE | risk | priority | confidence |
|---|---|---|---|---|
| 1 | CVE-2024-0140 | 39.04 | low | medium |
| 2 | CVE-2024-0141 | 39.04 | low | high |

### S16 PASS - Everything critical but nothing exploited vs medium with high EPSS + exposure
*Why:* Likelihood and exposure should be able to overtake raw severity.

| rank | CVE | risk | priority | confidence |
|---|---|---|---|---|
| 1 | CVE-2024-0151 | 68.99 | high | high |
| 2 | CVE-2024-0150 | 43.39 | medium | high |

### S17 PASS - Sweep: KEV CVSS 3.1 (internet, high-crit prod) vs non-KEV CVSS 9.0 (isolated, low-crit dev)
*Why:* Contextual KEV on an exposed important asset beats an unexploited, unreachable high-CVSS finding.

| rank | CVE | risk | priority | confidence |
|---|---|---|---|---|
| 1 | CVE-2023-1000 | 80.0 | critical | high |
| 2 | CVE-2023-2000 | 31.97 | low | high |

### S18 PASS - Sweep: KEV CVSS 5.0 (internet, high-crit prod) vs non-KEV CVSS 9.9 (isolated, low-crit dev)
*Why:* Contextual KEV on an exposed important asset beats an unexploited, unreachable high-CVSS finding.

| rank | CVE | risk | priority | confidence |
|---|---|---|---|---|
| 1 | CVE-2023-1001 | 80.0 | critical | high |
| 2 | CVE-2023-2001 | 34.67 | low | high |

### S19 PASS - Sweep: KEV CVSS 7.0 (internet, high-crit prod) vs non-KEV CVSS 9.8 (isolated, low-crit dev)
*Why:* Contextual KEV on an exposed important asset beats an unexploited, unreachable high-CVSS finding.

| rank | CVE | risk | priority | confidence |
|---|---|---|---|---|
| 1 | CVE-2023-1002 | 80.0 | critical | high |
| 2 | CVE-2023-2002 | 34.37 | low | high |

### S20 PASS - Sweep: KEV CVSS 4.0 (internet, high-crit prod) vs non-KEV CVSS 8.0 (isolated, low-crit dev)
*Why:* Contextual KEV on an exposed important asset beats an unexploited, unreachable high-CVSS finding.

| rank | CVE | risk | priority | confidence |
|---|---|---|---|---|
| 1 | CVE-2023-1003 | 80.0 | critical | high |
| 2 | CVE-2023-2003 | 28.97 | low | high |

### S21 PASS - Sweep: KEV CVSS 2.0 (internet, high-crit prod) vs non-KEV CVSS 7.5 (isolated, low-crit dev)
*Why:* Contextual KEV on an exposed important asset beats an unexploited, unreachable high-CVSS finding.

| rank | CVE | risk | priority | confidence |
|---|---|---|---|---|
| 1 | CVE-2023-1004 | 80.0 | critical | high |
| 2 | CVE-2023-2004 | 27.47 | low | high |

### S22 PASS - Sweep: EPSS 0.95 vs 0.05
*Why:* Higher EPSS first when everything else is equal.

| rank | CVE | risk | priority | confidence |
|---|---|---|---|---|
| 1 | CVE-2023-3000 | 54.78 | medium | high |
| 2 | CVE-2023-4000 | 35.09 | low | high |

### S23 PASS - Sweep: EPSS 0.6 vs 0.01
*Why:* Higher EPSS first when everything else is equal.

| rank | CVE | risk | priority | confidence |
|---|---|---|---|---|
| 1 | CVE-2023-3001 | 47.12 | medium | high |
| 2 | CVE-2023-4001 | 34.22 | low | high |

### S24 PASS - Sweep: EPSS 0.3 vs 0.001
*Why:* Higher EPSS first when everything else is equal.

| rank | CVE | risk | priority | confidence |
|---|---|---|---|---|
| 1 | CVE-2023-3002 | 40.56 | medium | high |
| 2 | CVE-2023-4002 | 34.02 | low | high |

### S25 PASS - Sweep: EPSS 0.5 vs 0.1
*Why:* Higher EPSS first when everything else is equal.

| rank | CVE | risk | priority | confidence |
|---|---|---|---|---|
| 1 | CVE-2023-3003 | 44.94 | medium | high |
| 2 | CVE-2023-4003 | 36.19 | low | high |

### S26 PASS - Sweep: CVSS 9.8 vs 5.0, nothing else known (no context)
*Why:* With identical (absent) other evidence, severity decides.

| rank | CVE | risk | priority | confidence |
|---|---|---|---|---|
| 1 | CVE-2023-5000 | 46.91 | medium | high |
| 2 | CVE-2023-6000 | 24.76 | low | high |

### S27 PASS - Sweep: CVSS 8.0 vs 4.0, nothing else known (no context)
*Why:* With identical (absent) other evidence, severity decides.

| rank | CVE | risk | priority | confidence |
|---|---|---|---|---|
| 1 | CVE-2023-5001 | 38.61 | low | high |
| 2 | CVE-2023-6001 | 20.14 | low | high |

### S28 PASS - Sweep: CVSS 7.0 vs 3.0, nothing else known (no context)
*Why:* With identical (absent) other evidence, severity decides.

| rank | CVE | risk | priority | confidence |
|---|---|---|---|---|
| 1 | CVE-2023-5002 | 33.99 | low | high |
| 2 | CVE-2023-6002 | 15.53 | low | high |

### S29 PASS - Ransomware-KEV on internal low asset vs non-KEV critical on exposed critical asset (judgment call)
*Why:* Both are defensible; the engine must at least place the ransomware-KEV item in the top priority band.

| rank | CVE | risk | priority | confidence |
|---|---|---|---|---|
| 1 | CVE-2024-0160 | 80.0 | critical | high |
| 2 | CVE-2024-0161 | 68.78 | high | high |

### S30 PASS - Dev/test box with KEV and no exposure is not 'critical' by default
*Why:* KEV raises urgency but an isolated test machine should not outrank an exposed production KEV.

| rank | CVE | risk | priority | confidence |
|---|---|---|---|---|
| 1 | CVE-2024-0171 | 84.62 | critical | high |
| 2 | CVE-2024-0170 | 70.0 | high | high |
