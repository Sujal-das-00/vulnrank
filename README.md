# VulnRank

Evidence-backed vulnerability prioritisation, built as a [Telegraph Protocol](https://github.com/telegraphprotocol/telegraph-docs)
miner for the `VULNERABILITY_TRIAGE_GENERAL` intent. CPU-only, no LLM, no GPU, no Docker.

Give it detected CVEs (and optionally what they run on); it returns an explainable remediation queue built from
**NVD** (CVSS), **CISA KEV** (known exploitation), **FIRST EPSS** (exploitation probability) and asset context.
Unavailable evidence is reported as unavailable, never as "no risk".

```
GET  /vuln-triage?cve_id=CVE-2021-44228                    # Telegraph-facing; top-level cvss_base_score
GET  /vuln-triage?cve_id=CVE-2021-44228,CVE-2024-3094&criticality=critical&internet_exposed=true&environment=production
GET  /vuln-triage?question=Rank CVE-2021-44228 and CVE-2024-3094 on an internet-facing payments service
POST /v1/triage                                            # full per-finding asset context (see below)
GET  /v1/score-model   /v1/sources/status   /health   /ready
```

## How it fits Telegraph (read `docs/protocol-mapping.md`)
The scored contract is **one `cve_id` -> `cvss_base_score`** (NVD primary CVSS v3.1). VulnRank returns exactly that at the top
level, plus `priority`, `risk_score`, `kev_listed`, `epss_*`, `summary`, `ranking[]`, `uncertainty[]` and full `details`
(evidence with source URLs/timestamps, per-dimension score breakdown). Multi-CVE requests are ranked; top-level fields
describe rank 1.

## Run locally
```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
cp .env.example .env            # optional: add NVD_API_KEY
.venv/bin/uvicorn app.main:app --port 8000
.venv/bin/pytest                          # 80+ tests, no network
.venv/bin/pytest -m live -s               # manual smoke test against real upstreams
.venv/bin/python scripts/run_evaluation.py   # -> docs/evaluation-report.md
```

### POST /v1/triage
```json
{"request_id":"r1","findings":[
 {"cve_id":"CVE-2021-44228","asset":{"asset_id":"pay-api","environment":"production","criticality":"critical","internet_exposed":true}},
 {"cve_id":"CVE-2022-0001","asset":{"asset_id":"dev-box","environment":"development","criticality":"low","exposure":"isolated"}}],
 "preferences":{"top_n":10,"include_remediation":true}}
```
Invalid items yield per-item `errors[]` (never silently dropped); duplicates of the same (CVE, asset) are merged and counted.

## Design notes
* `docs/scoring-model.md` - formula, missing-signal policy, floors, confidence rules. `docs/evaluation-report.md` - results.
* Resilience: per-host timeouts, retries with backoff + `Retry-After`, circuit breaker, last-known-good (`stale`) cache,
  host allow-list (no SSRF), NVD rate limiter. Keyless NVD is slow (10s+) and ~5 calls/30s, so: SQLite cache, a background
  warmer for KEV-listed CVEs, and **Shodan CVEDB as a clearly-labelled fallback** when NVD does not answer within 1.5s
  (`cvss_is_nvd_primary: false`, confidence lowered). A slow NVD call keeps running and fills the cache for the next caller.
* Privacy: only public CVE enrichment is cached; asset context is never persisted or logged.

## Register on Telegraph
1. Deploy (`render.yaml`; use an always-on plan, see caveats), set `NVD_API_KEY`.
2. Edit `telegraph/vulnrank.yaml`: `base_url` and `docs.repository`; check `id`/`slug` are free
   (`curl -s https://devnode.telegraphprotocol.com/api/miners | jq ...`).
3. Validate + register at https://anjoman.ai/dashboard/earn (needs a wallet, Sepolia ETH, ~$1 MACHINA bond).
   Registration is on-chain and not editable - validate first.

## Limitations (honest list)
* Score is a heuristic, not a probability of compromise; weights are un-calibrated initial values (`docs/scoring-model.md`).
* Evaluation scenarios are authored by the same people as the engine; no external ground truth exists for "correct" ranking.
* Not yet exercised against the real Telegraph node (needs a funded wallet): YAML validation, `intent_mapping`, paid `ask`.
* `public_exploit` only reflects NVD reference tags; absence is "unknown", not "no exploit".
* Render Free sleeps and has an ephemeral disk; Telegraph liveness spot checks can then fail. Cache is rebuilt after restart.
* CVEDB fallback values are provisional and NVD may later differ. **Any CVE not already cached is answered from the CVEDB fallback on its first call (~1.5-3s, labelled provisional);** NVD fills the cache in the background, and the warmer pre-loads KEV-listed CVEs.
* OSV / vendor-advisory enrichment from the blueprint is not implemented (needs package details; out of scope for the scored contract).


## Launch review (second intent)
`GET /launch-review` reviews a public GitHub repo and/or website for a stated country (EU, India, US) and sector (SaaS, e-commerce):
dependency CVEs ranked by KEV/EPSS/NVD, secrets, risky code patterns, site security headers, and an evidence-based legal checklist with cited
rules, merged into one fix-first list. See [docs/launch-review.md](docs/launch-review.md). It is served as `SECURITY_REVIEW_GENERAL` in `telegraph/vulnrank.yaml`.
