# Launch review (`GET /launch-review`, intent `SECURITY_REVIEW_GENERAL`)

A security review, and for repos and sites a pre-launch legal gate. `target` can be any of:

| Target | Example | What runs |
|---|---|---|
| Code or a unified diff | a pasted snippet, ```` ```python ... ``` ````, `diff --git ...` (added lines only) | secret + code-pattern rules |
| Package versions | `lodash@4.17.15`, `django==3.2.0`, `lodash 4.17.15 on npm` | OSV lookup, then the VulnRank engine (KEV, EPSS, NVD) |
| Public GitHub repo | `github.com/acme/shop` | all of the above + manifests + legal checklist |
| Public website | `https://acme.shop` | headers + policy pages + legal checklist |

The legal checklist (EU, India, US x SaaS, e-commerce) only runs when a repo or website is given. Country and sector come from the
`country` / `sector` params or words inside `target` ("github.com/acme/shop eu india ecommerce"); with none given all three jurisdictions
are checked and the answer says so under `assumptions`.

    GET /launch-review?target=github.com/acme/shop%20https://acme.shop&country=eu,india&sector=ecommerce

The graded leaders of this intent accept pasted code and `package@version` questions, so those paths are the fast ones (a few seconds).

## Response (scored fields first)
| Field | Meaning |
|---|---|
| `verdict` | `Secure` / `Needs changes` / `Insecure` (security only). `null` when nothing could be scanned (never `Secure` by default). For snippets, `Secure` means no pattern matched; the summary says it is not a proof. |
| `vulnerability_count` | Dependency vulnerabilities + secret/code-pattern locations + site-header issues. Legal gaps are **not** counted. |
| `issues` | CVE ids and weakness categories (CWE), most serious first |
| `summary` / `answer` | Short decision-first text |
| `priority` / `confidence` | Top severity and 0-1 confidence (0.5 when results are partial, 0 when nothing was scanned) |
| `launch_readiness` | `blocked` / `conditional` / `ready` / `unknown`. Low-confidence gaps never block. |
| `fix_first` | Top 12 findings merged and ranked (security and compliance), each with evidence, fix, and for legal items the cited basis |
| `compliance.checklist` | Every applicable rule: `passed` / `not_detected` / `upcoming` / `not_applicable` |
| `compliance.legal_exposure` | Per law: statutory **ceiling** (never a predicted fine), gap counts, verification status |
| `scan_coverage` | What was and was not scanned (unpinned dependencies, truncated archives, OSV outage...) |

## What it checks
* **Dependencies** (`requirements.txt`, lockfiles, `go.mod`, `Gemfile.lock`): OSV lookup, then CVEs are ranked by the VulnRank
  engine (NVD, CISA KEV, FIRST EPSS). A KEV-listed dependency makes the verdict `Insecure`.
* **Secrets** (AWS, GitHub, Stripe live, Slack, Google keys, private keys, hard-coded credentials, committed `.env`): values are never echoed, only a 4-character prefix and length.
* **Code patterns** (TLS verification off, SQL string building, eval/exec, unsafe deserialisation, debug on, weak hashes, XSS sinks, open CORS, hard-coded JWT secret): pattern hits to review, not proof of exploitability.
* **Website** (home page + up to 6 policy pages, passive GETs): HTTPS, HSTS, CSP, nosniff, framing, cookie flags, mixed content.
* **Legal checklist** from `app/review/rules.yaml` (about 20 rules; EU, India, US; SaaS and e-commerce).

## Honesty rules
1. **"Not detected" is never "violation".** A policy may live in Shopify, another repo, or offline. Backend-only repos get low-confidence legal findings and a caveat.
2. **Every legal statement is data** in `rules.yaml` with law, citation, URL, `verification` (`checked` = confirmed against published sources while writing, `knowledge` = not re-checked) and an as-of date. No model writes legal text.
3. **Penalties are statutory ceilings**, e.g. GDPR Art. 83(4)/(5), DPDP Act Schedule, CCPA per-violation amounts. They are not estimates of what a regulator would impose.
4. **Dated rules.** DPDP notice/consent duties show as `upcoming` until about 14 May 2027; the EU withdrawal-button rule applies from 19 June 2026 but national transposition varies.
5. Not legal advice. Counsel must confirm.

## Safety of fetching caller-named targets
Websites: http/https on ports 80/443 only, hostnames only; DNS must resolve exclusively to public addresses; the connection is pinned to the validated IP
(TLS still verifies the real hostname); redirects are re-validated hop by hop (max 3); 1.5 MB body cap; no credentials, forms or probing.
Repos: only `codeload.github.com`, 15 MB download cap, 40 MB extracted cap, 4000 files; the repo's code is never executed.
At most two reviews run at once. The overall budget is `REVIEW_DEADLINE_SEC` (default 12 s); anything unfinished is reported in `scan_coverage` and the result is marked partial.
CPU-bound scanning runs off the event loop (verified: `/health` and `/vuln-triage` stayed under 60 ms during a large-repo review).

## Known limits
* The node's request timeout is not documented anywhere I could find, so the 12 s budget is a guess; lower `REVIEW_DEADLINE_SEC` if the node cuts calls sooner.
* Large repos (about 10 MB archive, e.g. Django) do not download inside the budget and return `verdict: null` with a reason. GitHub's download host also rate-limits shared IPs (HTTP 429), also reported as `null`, never as `Secure`.
* A cold NVD cache makes ranking slow; the review then keeps the OSV advisory severities and says so under `scan_coverage.triage`.
* Dependency files under `docs/`, `examples/`, `tests/` are ignored (they are not the shipped product).
* Public repos only; no private repos or authenticated sites.
* Only exactly pinned dependencies are checked; ranges are reported as `unpinned_not_checked`.
* The site crawl is shallow (home page plus linked policy pages), so a page reachable only through scripts is missed.
* Rules marked `verification: knowledge` are leads for counsel, not confirmed law. Several laws changed recently; re-check the table before relying on it (`as_of` is in the response).
