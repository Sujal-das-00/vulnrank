# Competitor observations (2026-11-15, devnode registry + direct calls; not a full benchmark)

Recorded from `GET /api/miners`, `GET /leaderboard/miners` and direct unauthenticated calls to miner endpoints.
No paid `ask` calls were made, so this does **not** show how the node routes or parses their answers.

* 37 miners serve `VULNERABILITY_TRIAGE_GENERAL`. Leaderboard snapshot (epoch 2097): `txlens` 0.99, `a1-preflight` 0.98,
  `vuln-shodan-cvedb` 0.98, `vuln-alpine-secdb` 0.72, `chainsight-oracle` 0.50, `zk-cve-triage` 0.48, `vuln-ghsa*` 0.38 ...
  and ~17 miners at 0. Most are thin single-record wrappers (e.g. `vuln-nvd`, `vuln-osv-cvss`).
* `vuln-shodan-cvedb` forwards Shodan CVEDB's raw record for one CVE (cvss, EPSS, KEV flag...). No ranking, no asset context.
* `zk-cve-triage` (CodeWire): one CVE per call; returns the NVD primary v3.1 `cvss_base_score`, vector, KEV and EPSS as prose,
  explicitly states "asset applicability is not established". Its registry description and `limitations` say single CVE.
* `codewire-vulnerability-triage`: LLM-generated prose for one vulnerability ("A single request, not a batch"); score 0.
* None of the miners inspected accepts a list of findings or asset context. That is the gap VulnRank targets, but the
  graded field is still one CVSS number, so the differentiation only helps if the evaluator rewards richer answers.
  Treat this as a hypothesis to test, not a claim.

## Addendum: top-ranked `txlens` (direct call, one CVE)
`GET /vulnerability-triage?cve=CVE-2021-44228` -> a ~700-byte JSON with `answer`/`summary` (one paragraph: "URGENT triage priority: CVSS 10.0 ...
listed in CISA KEV ... Recommended action: patch or mitigate immediately"), `cvss_score`, `triage_tier`, `known_exploited`. Its YAML declares one
required `query` param (the whole question). It covers 100+ other intents, i.e. it is a generalist; no batch ranking or asset context was visible.
