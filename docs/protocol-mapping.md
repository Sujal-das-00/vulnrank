# Telegraph protocol mapping (verified 2026-11-15)

Sources: `telegraphprotocol/telegraph-docs` (miners/*, using/*), `telegraphprotocol/bounties` (catalog/intents.json),
and the live devnode `https://devnode.telegraphprotocol.com`.

## What Telegraph actually requires of a miner

* **No SDK, no protocol envelope.** A miner is a public HTTPS API plus a YAML manifest (YAML Miner Standard v1).
  The node turns the user's question into an HTTP call from the manifest's `params`, calls the miner, and parses the answer.
* **Registration is on-chain** (Ethereum Sepolia testnet): upload/pin the YAML, compute its hash, `registerMiner`
  (bond ≈ $1 in MACHINA for the first intent, returned on deregistration; gas in Sepolia ETH). `anjoman.ai/dashboard/earn`
  validates the YAML against the live endpoint and registers. Activation takes ~10-15 min; then a 7-day grace period
  (5% of routed traffic shared by new miners) sets the starting leaderboard position.
* **The YAML schema is a closed set**: unknown keys are rejected (`tests/unit/test_manifest.py` enforces the allowed keys).

## The intent

`VULNERABILITY_TRIAGE_GENERAL` (family `VULNERABILITY_TRIAGE`, class **judgment**):

| | |
|---|---|
| request params (on-chain schema) | `cve_id` (string, required, ≤ 256 bytes) |
| response field (scored) | `cvss_base_score` - number 0-10 - "CVSS v3.1 base score of {key}, the NVD primary score (not an EPSS probability or percentile)" |
| scoring | model-based *evaluator adapter* ranks miners on pool questions; the node's parser reads the answer into `cvss_base_score` |
| liveness | spot checks ~hourly: an empty answer / no response, repeated, revokes routing for the intent |

### Consequences for VulnRank

1. The contract is **one `cve_id` in, `cvss_base_score` out**. VulnRank answers that exactly (top-level `cvss_base_score`
   = NVD primary CVSS v3.1) and layers its differentiators on top as additive fields.
2. Portfolio ranking travels through `cve_id` (comma-separated), a free-text `question`, or the full `POST /v1/triage` API.
   In multi-CVE mode the top-level fields describe the **rank-1** finding; `ranking[]` has all of them.
3. Asset context is optional query params (`criticality`, `internet_exposed`, `environment`) or is conservatively inferred
   from the question text and *labelled as inferred*.
4. Requests we cannot score still get a non-empty HTTP 200 with `cvss_base_score: null` and a `status` (`no_cve_identified`, `cve_not_found`, `insufficient_evidence`), because the node treats an empty or failed answer as a liveness/ranking failure; the score is never fabricated
   answers; the YAML maps `errors.message_path` to `message`.

## Observed about the leaders (see `competitor-notes.md`)

* `txlens` (rank 1, 0.99) declares its triage endpoint with a single required `query` param carrying the **user's whole question
  verbatim**, and answers one CVE in ~700 bytes (CVSS, KEV, tier, action). So real requests may arrive as natural language, not
  only typed `cve_id`. VulnRank therefore accepts `cve_id`, `cve`, `question`, `query` and extracts every CVE id from any of them.
* Answers are short and answer-first; ours are kept to ~3.5 KB (single CVE) with `cvss_base_score` and `summary` first and the
  full domain payload left on `POST /v1/triage`.

## Not yet verified (needs a funded wallet / live node access)

* The YAML passing the anjoman sandbox validation and `intent_mapping` acceptance by the node.
* How the evaluator adapter scores the free-text parts of our answer relative to other miners (we only know scoring is
  rank-vs-other-miners on pool questions; the pool content is hidden).
* The questions the evaluator actually asks (the daemon feed and the eval pool were not inspectable for this intent).
* End-to-end paid invocation through `/engine/v1/ask` (x402/escrow).
