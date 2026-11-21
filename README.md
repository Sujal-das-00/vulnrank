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

## Extra intents (verified lookups)
Five more intents, picked from the live Telegraph intent list by miner count (`/engine/v1/intents`) among those answerable keyless and
deterministically. Each is corroborated by two independent public sources, always answers HTTP 200, and returns `null` plus an `outcome`
(never a guess) when sources fail. Code: `app/intents/`; manifest entries in `telegraph/vulnrank-fixed.yaml`.

| Intent (miners) | Endpoint | Graded field | Sources |
|---|---|---|---|
| `CRYPTO_PRICE_USD` (54) | `/crypto-price?symbol=ETH` | `price_usd` | Coinbase + Kraken (null if >2% apart) |
| `WEATHER_CHECK_TEMPERATURE` (31) | `/weather-temperature?location=London` | `temperature_c` | Open-Meteo geocoder + forecast, worldwide |
| `GAS_PRICE_GENERAL` (28) | `/gas-price?chain=base` | `gas_price_gwei` | two public RPC operators per chain |
| `ONCHAIN_TX_LOOKUP_GENERAL` (28) | `/tx-lookup?tx_hash=0x...` | `status` | two RPC operators; chain auto-detected if omitted |
| `DNS_RECORD_LOOKUP_GENERAL` (25) | `/dns-lookup?name=example.com&record_type=MX` | `has_record` | Google Public DNS + Cloudflare DoH |

Chains: Ethereum, Base, Arbitrum, Polygon, Optimism. New upstream hosts are added to the allow-list in `app/sources/base.py`.
Caveat: the leaderboard has no scored rows yet for `GAS_PRICE_GENERAL` and `DNS_RECORD_LOOKUP_GENERAL`, so they add coverage but cannot earn a #1 until scoring starts.

## Legal / compliance and NLP intents (7 more, 14 in total)
Chosen from the live intent list (miner counts in brackets); all deterministic, no language model, and every answer says what it did
**not** check. Code in `app/intents/`, manifest entries in `telegraph/vulnrank-fixed.yaml`.

| Intent (miners) | Endpoint | Graded fields | Sources |
|---|---|---|---|
| `SANCTIONS_SCREENING_MATCH_GENERAL` (28) | `/sanctions-screening?name=` | `matched`, `matches`, `highest_score` | OFAC SDN + UN consolidated lists (fuzzy names, aliases, DOB year, crypto addresses). EU/UK lists are **not** checked. |
| `CORPORATE_REGISTRY_LOOKUP_GENERAL` (25) | `/corporate-registry?company=` | `legal_name`, `registration_id`, `active`, `registered_address`, `incorporated` | GLEIF (entities with an LEI only; no directors/owners) |
| `VENDOR_VERIFY_GENERAL` (25) | `/vendor-verify?vendor=&vat_number=` | `verdict`, `valid`, `registered_name` | EU VIES VAT + GLEIF + sanctions; bank and certification checks are listed as not checked |
| `REGULATORY_FILING_MONITOR_GENERAL` (22) | `/filing-monitor?entity=&form=&period=` | `filing_count`, `filings`, `urls` | SEC EDGAR submissions index (filing text is not read) |
| `CONTRACT_OBLIGATION_AUDIT_GENERAL` (11) | `/contract-audit?contract=` (GET or POST) | `verdict`, `obligations`, `clauses` | Rule-based extraction; reports passed dates, cannot prove breach |
| `SENTIMENT_ANALYSIS_GENERAL` (21) | `/sentiment?text=` | `sentiment`, `score` | VADER lexicon (English); local, nothing leaves the service |
| `LANGUAGE_TRANSLATION_GENERAL` (22) | `/translate?text=&target_language=` | `translation` | MyMemory (the text is sent to that third party; free quota is limited) |

Notes: the sanctions lists (~30 MB) are downloaded in the background at start-up and refreshed every 12 h; until loaded, the answer is
`loading`/`unavailable` and never "clear". Redirects are followed only to allow-listed hosts. A sanctions hit is a lead for human review,
not a legal determination. SEC requests use a descriptive `VulnRank/0.1` user agent and no personal contact details.

## AI/language, blockchain and compliance intents (17 more, 31 in total, all declared in the manifest)
Intent names, parameters and graded fields come from the Telegraph intent catalogue (`catalog/intents.json` in the
[telegraphprotocol/bounties](https://github.com/telegraphprotocol/bounties) repo), so asks routed to those intents reach these endpoints.
Caveat: when this was written the catalogue marked 7 of the 17 `onchain_ready: false` (no response format yet; `TOKEN_TOTAL_SUPPLY_VERIFY_GENERAL`: no decimals): `KEYWORD_EXTRACTION`, `SEMANTIC_SIMILARITY`, `ENTITY_EXTRACTION`, `TEXT_SUMMARIZATION`, `TOKEN_TOTAL_SUPPLY_VERIFY`, `SMART_CONTRACT_AUDIT`, `PLAGIARISM_DETECTION`. They are declared anyway; if the node's validation rejects the YAML over them, remove their `endpoints`, `intent_mapping` and `supported_intents` entries. All answer HTTP 200 and return `null` plus an `outcome` instead of guessing. Code in `app/intents/`; tests in `tests/intents/test_new_intents.py`.

| Group | Intent | Endpoint | Graded fields | Method / source |
|---|---|---|---|---|
| AI / ML | `TEXT_CLASSIFICATION_GENERAL` | `/text-classification` | `category`, `reason`, `confidence` | label + keyword overlap; null when no label is supported |
| AI / ML | `KEYWORD_EXTRACTION_GENERAL` | `/keyword-extraction` | `keywords` | RAKE |
| AI / ML | `SEMANTIC_SIMILARITY_GENERAL` | `/semantic-similarity` | `similarity`, `verdict` | TF cosine (lexical, not a neural embedding) |
| AI / ML | `ENTITY_EXTRACTION_GENERAL` | `/entity-extraction` | `entities` (with offsets) | regex + gazetteer; person/org labels are heuristic |
| AI / ML | `TEXT_SUMMARIZATION_GENERAL` | `/text-summarization` | `summary` | extractive, nothing added |
| AI / ML | `LLM_OUTPUT_EVALUATION_GENERAL` | `/llm-evaluation` | `rating`, `score`, `strengths`, `errors` | structural checks; cannot verify facts |
| AI / ML | `AI_TEXT_DETECTION_GENERAL` | `/ai-text-detection` | `verdict`, `ai_likelihood`, `cues` | stylometric heuristic, confidence capped at 0.6 |
| Blockchain | `WALLET_BALANCE_CHECK_GENERAL` | `/wallet-balance` | `balance`, `token_symbol` | two RPC operators must agree (no ENS) |
| Blockchain | `TOKEN_TOTAL_SUPPLY_VERIFY_GENERAL` | `/token-supply` | `total_supply` | two RPC operators must agree |
| Blockchain | `TVL_LOOKUP_GENERAL` | `/tvl` | `tvl_usd`, `chain_tvl_usd` | DefiLlama |
| Blockchain | `CRYPTO_YIELD_RATE_GENERAL` | `/yield-rate` | `supply_apy` | DefiLlama pools |
| Blockchain | `LIQUIDITY_DEPTH_VERIFY_GENERAL` | `/liquidity-depth` | `liquidity_usd` | DefiLlama pool TVL + constant-product slippage estimate |
| Blockchain | `SMART_CONTRACT_AUDIT_GENERAL` | `/contract-source-audit` | `verdict`, `findings` | SWC pattern scan of Solidity source; never says "secure" |
| Legal / compliance | `CONTENT_MODERATION_GENERAL` | `/content-moderation` | `verdict`, `flagged`, `categories` | pattern rules incl. personal data (GDPR-style) |
| Legal / compliance | `PLAGIARISM_DETECTION_GENERAL` | `/plagiarism-check` | `similarity_pct`, `verdict` | overlap with a **supplied** source only |
| Legal / compliance | `EMAIL_SECURITY_GENERAL` | `/email-security` | `lookup_ok`, `grade` | SPF/DKIM/DMARC via Google + Cloudflare DoH |
| Legal / compliance | `TRANSACTION_RISK_GENERAL` | `/transaction-risk` | `risk_level`, `risk_score`, `signals` | additive rule scorecard |

No language model and no API key is used anywhere: everything is rules, lexicons, public data sources or two-RPC agreement. (`LLM_OUTPUT_EVALUATION_GENERAL` judges a model's output with structural checks; it does not call a model.) The long-text endpoints also accept POST with a JSON body.
