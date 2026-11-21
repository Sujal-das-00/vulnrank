"""FastAPI application: health, readiness, domain API and the Telegraph-facing endpoint."""
from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from app.cache import Cache
from app.intents import (chain as chain_intents, compliance as compliance_intents, contract as contract_intents, crypto as crypto_intents,
                         defi as defi_intents, dns as dns_intents, emailsec as emailsec_intents, evm as evm_intents, filings as filings_intents,
                         nlp as nlp_intents, registry as registry_intents, sanctions as sanctions_intents,
                         sentiment as sentiment_intents, solidity as solidity_intents, translate as translate_intents, vendor as vendor_intents,
                         weather as weather_intents)
from app.config import ENGINE_VERSION, SCORE_VERSION, Settings
from app.inputs import findings_from_body, findings_from_query
from app.models import RawTriageRequest
from app.protocol.adapter import soft_answer, to_telegraph_answer
from app.scoring import CRITICALITY_SCORE, DIM_WEIGHTS, ENV_FACTOR, EXPL_WEIGHTS, EXPOSURE_SCORE, THRESHOLDS
from app.sources.base import Fetcher, RateLimiter
from app.sources.cvedb import CveDbClient
from app.sources.epss import EpssClient
from app.sources.kev import KevClient
from app.sources.nvd import NvdClient
from app.review.netguard import SafeFetcher
from app.review.service import ReviewService
from app.triage import TriageService
from app.warmer import warm_cache

log = logging.getLogger("vulnrank")
MAX_BODY_BYTES = 256 * 1024
# (route, intent) for the seventeen intents added on 2026-11-21: language, blockchain, legal and compliance
EXTRA_ROUTES = [
    ("/text-classification", "TEXT_CLASSIFICATION_GENERAL"), ("/keyword-extraction", "KEYWORD_EXTRACTION_GENERAL"), ("/semantic-similarity", "SEMANTIC_SIMILARITY_GENERAL"),
    ("/entity-extraction", "ENTITY_EXTRACTION_GENERAL"), ("/text-summarization", "TEXT_SUMMARIZATION_GENERAL"), ("/llm-evaluation", "LLM_OUTPUT_EVALUATION_GENERAL"),
    ("/ai-text-detection", "AI_TEXT_DETECTION_GENERAL"), ("/wallet-balance", "WALLET_BALANCE_CHECK_GENERAL"), ("/token-supply", "TOKEN_TOTAL_SUPPLY_VERIFY_GENERAL"),
    ("/tvl", "TVL_LOOKUP_GENERAL"), ("/yield-rate", "CRYPTO_YIELD_RATE_GENERAL"), ("/liquidity-depth", "LIQUIDITY_DEPTH_VERIFY_GENERAL"),
    ("/contract-source-audit", "SMART_CONTRACT_AUDIT_GENERAL"), ("/content-moderation", "CONTENT_MODERATION_GENERAL"), ("/plagiarism-check", "PLAGIARISM_DETECTION_GENERAL"),
    ("/email-security", "EMAIL_SECURITY_GENERAL"), ("/transaction-risk", "TRANSACTION_RISK_GENERAL"),
]
EXTRA_INTENTS = [i for _, i in EXTRA_ROUTES]


class _Json(logging.Formatter):
    def format(self, r: logging.LogRecord) -> str:
        d = {"t": self.formatTime(r, "%Y-%m-%dT%H:%M:%S"), "lvl": r.levelname, "msg": r.getMessage()}
        d.update(getattr(r, "ctx", {}))
        return json.dumps(d)


def build_service(settings: Settings, client: httpx.AsyncClient) -> tuple[TriageService, Cache, Fetcher]:
    cache = Cache(settings.cache_db_path)
    fetcher = Fetcher(client, retries=settings.source_retries, backoff_base=settings.backoff_base_sec,
                      breaker_threshold=settings.breaker_threshold, breaker_cooldown=settings.breaker_cooldown_sec)
    limiter = RateLimiter(settings.nvd_rate_calls, settings.nvd_rate_period_sec)
    nvd = NvdClient(fetcher, cache, limiter, api_key=settings.nvd_api_key, ttl=settings.ttl_nvd,
                    ttl_not_found=settings.ttl_not_found, timeout=settings.nvd_timeout_sec)
    kev = KevClient(fetcher, cache, ttl=settings.ttl_kev, timeout=settings.source_timeout_sec)
    epss = EpssClient(fetcher, cache, ttl=settings.ttl_epss, ttl_not_found=settings.ttl_not_found, timeout=settings.source_timeout_sec)
    cvedb = CveDbClient(fetcher, cache, ttl=settings.ttl_cvedb, ttl_not_found=settings.ttl_not_found, timeout=settings.source_timeout_sec)
    return TriageService(nvd, kev, epss, cvedb, settings), cache, fetcher


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    h = logging.StreamHandler()
    h.setFormatter(_Json())
    logging.getLogger("vulnrank").handlers = [h]
    logging.getLogger("vulnrank").setLevel(settings.log_level)
    logging.getLogger("vulnrank").propagate = False

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        client = httpx.AsyncClient(headers={"User-Agent": "VulnRank/" + ENGINE_VERSION}, http2=False)
        svc, cache, fetcher = build_service(settings, client)
        app.state.svc, app.state.fetcher, app.state.started = svc, fetcher, time.time()
        safe_client = httpx.AsyncClient(follow_redirects=False)
        app.state.review = ReviewService(svc, fetcher, client, SafeFetcher(safe_client), settings)
        app.state.review_slots = asyncio.Semaphore(2)
        app.state.sanctions = sanctions_intents.SanctionsIndex(fetcher)
        app.state.defi = defi_intents.DefiIndex(fetcher)
        defi_warm = asyncio.ensure_future(app.state.defi.ensure_pools()) if settings.warm_enabled else None  # ~6 MB pool list, load before the first ask
        sanctions_warm = asyncio.ensure_future(app.state.sanctions.ensure()) if settings.warm_enabled else None  # ~30 MB of lists, load before the first ask
        warmer = asyncio.ensure_future(warm_cache(svc, settings)) if settings.warm_enabled else None
        yield
        if warmer:
            warmer.cancel()
        if sanctions_warm:
            sanctions_warm.cancel()
        if defi_warm:
            defi_warm.cancel()
        await client.aclose()
        await safe_client.aclose()

    app = FastAPI(title="VulnRank", version=ENGINE_VERSION, lifespan=lifespan,
                  description="Evidence-backed vulnerability prioritisation (Telegraph miner).")

    @app.middleware("http")
    async def guard(request: Request, call_next):
        cl = request.headers.get("content-length")
        if cl and cl.isdigit() and int(cl) > MAX_BODY_BYTES:
            return JSONResponse({"error": "request_too_large", "limit_bytes": MAX_BODY_BYTES}, status_code=413)
        rid = request.headers.get("x-request-id") or uuid.uuid4().hex[:12]
        t0 = time.monotonic()
        resp = await call_next(request)
        resp.headers["x-request-id"] = rid
        if request.url.path not in ("/health",):
            log.info("request", extra={"ctx": {"rid": rid, "path": request.url.path, "status": resp.status_code,
                                                "ms": round((time.monotonic() - t0) * 1000)}})
        return resp

    @app.get("/")
    async def root():
        return {"service": "VulnRank", "engine_version": ENGINE_VERSION, "score_version": SCORE_VERSION,
                "intent": "VULNERABILITY_TRIAGE_GENERAL", "intents": ["VULNERABILITY_TRIAGE_GENERAL", "SECURITY_REVIEW_GENERAL", "CRYPTO_PRICE_USD", "WEATHER_CHECK_TEMPERATURE",
                                   "GAS_PRICE_GENERAL", "ONCHAIN_TX_LOOKUP_GENERAL", "DNS_RECORD_LOOKUP_GENERAL",
                                   "SANCTIONS_SCREENING_MATCH_GENERAL", "CORPORATE_REGISTRY_LOOKUP_GENERAL", "VENDOR_VERIFY_GENERAL",
                                   "REGULATORY_FILING_MONITOR_GENERAL", "CONTRACT_OBLIGATION_AUDIT_GENERAL", "SENTIMENT_ANALYSIS_GENERAL",
                                   "LANGUAGE_TRANSLATION_GENERAL", *EXTRA_INTENTS],
                "endpoints": ["/vuln-triage", "/launch-review", "/crypto-price", "/weather-temperature", "/gas-price", "/tx-lookup", "/dns-lookup", "/sanctions-screening",
                              "/corporate-registry", "/vendor-verify", "/filing-monitor", "/contract-audit", "/sentiment", "/translate", *[r for r, _ in EXTRA_ROUTES], "/v1/triage", "/v1/score-model", "/v1/sources/status", "/health"]}

    @app.get("/health")
    async def health():  # cheap: no external calls
        return {"status": "ok"}

    @app.get("/ready")
    async def ready(request: Request):
        return {"status": "ready", "nvd_api_key_configured": bool(settings.nvd_api_key),
                "cache_persistent": bool(settings.cache_db_path), "max_batch_size": settings.max_batch_size,
                "uptime_sec": round(time.time() - request.app.state.started)}

    @app.get("/v1/score-model")
    async def score_model():
        return {"score_version": SCORE_VERSION, "dimension_weights": DIM_WEIGHTS, "exploitation_weights": EXPL_WEIGHTS,
                "criticality_scores": CRITICALITY_SCORE, "exposure_scores": EXPOSURE_SCORE, "environment_factors": ENV_FACTOR,
                "priority_thresholds": [{"priority": n, "min_score": lo} for n, lo in THRESHOLDS],
                "missing_signal_policy": "Unknown is never zero: dimensions/sub-signals that cannot be assessed are dropped and weights re-normalised; coverage is reported.",
                "docs": "docs/scoring-model.md"}

    @app.get("/v1/sources/status")
    async def sources_status(request: Request):
        f: Fetcher = request.app.state.fetcher
        return {h: f.breaker_state(h) for h in ("services.nvd.nist.gov", "www.cisa.gov", "api.first.org", "cvedb.shodan.io", "api.coinbase.com", "api.kraken.com",
                                                           "api.open-meteo.com", "dns.google", "cloudflare-dns.com")}

    @app.post("/v1/triage")
    async def triage(request: Request, body: RawTriageRequest):
        findings, errors = findings_from_body(body, settings.max_batch_size)
        if not findings:
            return JSONResponse({"error": "no_valid_findings", "errors": [e.model_dump(exclude_none=True) for e in errors]}, status_code=422)
        svc: TriageService = request.app.state.svc
        resp = await svc.run(findings, request_id=body.request_id, errors=errors, top_n=body.preferences.top_n,
                             include_remediation=body.preferences.include_remediation, total_submitted=len(body.findings))
        return resp

    @app.get("/launch-review")
    async def launch_review(request: Request):
        p = dict(request.query_params)
        target = " ".join(str(p[k]) for k in ("target", "question", "query", "q", "repo", "url", "site") if p.get(k))[:2000]
        slots: asyncio.Semaphore = request.app.state.review_slots
        if slots.locked():
            msg = "The reviewer is handling several launch reviews right now; please retry in a few seconds."
            return {"verdict": None, "vulnerability_count": None, "issues": [], "summary": msg, "answer": msg, "status": "busy", "fix_first": []}
        async with slots:
            return await request.app.state.review.run(target, country=p.get("country") or p.get("countries") or p.get("jurisdiction"), sector=p.get("sector"))

    def _extra(handler, *, ensure: dict[str, Any] | None = None):
        async def endpoint(request: Request):
            f: Fetcher = request.app.state.fetcher
            deadline = time.monotonic() + settings.request_deadline_sec
            out = await handler(f, dict(request.query_params), timeout=settings.source_timeout_sec, deadline=deadline)
            for k, v in (ensure or {}).items():
                out.setdefault(k, v)
            return out
        return endpoint

    app.get("/crypto-price")(_extra(crypto_intents.lookup, ensure={"price_usd": None}))
    app.get("/weather-temperature")(_extra(weather_intents.lookup, ensure={"temperature_c": None}))
    app.get("/gas-price")(_extra(chain_intents.gas_price, ensure={"gas_price_gwei": None}))
    app.get("/tx-lookup")(_extra(chain_intents.tx_lookup, ensure={"status": None}))
    app.get("/dns-lookup")(_extra(dns_intents.lookup, ensure={"has_record": None}))

    def _with_index(handler, ensure: dict[str, Any]):
        async def endpoint(request: Request):
            f: Fetcher = request.app.state.fetcher
            deadline = time.monotonic() + settings.request_deadline_sec
            args = (f, request.app.state.sanctions, dict(request.query_params)) if handler is vendor_intents.verify else (request.app.state.sanctions, dict(request.query_params))
            kw = {"timeout": settings.source_timeout_sec, "deadline": deadline}
            out = await handler(*args, **kw)
            for k, v in ensure.items():
                out.setdefault(k, v)
            return out
        return endpoint

    app.get("/sanctions-screening")(_with_index(sanctions_intents.screen, {"matched": None}))
    app.get("/vendor-verify")(_with_index(vendor_intents.verify, {"verdict": None}))
    app.get("/corporate-registry")(_extra(registry_intents.lookup, ensure={"legal_name": None}))
    app.get("/filing-monitor")(_extra(filings_intents.lookup, ensure={"filing_count": None}))
    app.get("/translate")(_extra(translate_intents.run, ensure={"translation": None}))

    async def _params(request: Request) -> dict[str, Any]:
        """Query parameters, plus a JSON or form body for POST (long texts and contracts do not fit a URL)."""
        params: dict[str, Any] = dict(request.query_params)
        if request.method == "POST":
            try:
                body = await request.json()
                params.update({k: v if isinstance(v, (list, dict)) else str(v) for k, v in body.items() if v is not None} if isinstance(body, dict) else {})
            except ValueError:
                params.update({k: v for k, v in (await request.form()).items() if isinstance(v, str)})
        return params

    def _extra_route(route: str, handler, ensure: dict[str, Any], kind: str = "sync"):
        async def endpoint(request: Request):
            params = await _params(request)
            if kind == "sync":
                out = handler(params)
            elif kind == "async":
                out = await handler(params)
            else:
                f: Fetcher = request.app.state.fetcher
                deadline = time.monotonic() + settings.request_deadline_sec
                kw = {"timeout": settings.source_timeout_sec, "deadline": deadline}
                if kind == "defi":
                    out = await handler(f, request.app.state.defi, params, **kw)
                else:
                    out = await handler(f, params, **kw)
            for k, v in ensure.items():
                out.setdefault(k, v)
            return out
        app.api_route(route, methods=["GET", "POST"])(endpoint)

    N, C = nlp_intents, compliance_intents
    for route, handler, ensure, kind in [
        ("/text-classification", N.text_classification, {"category": None}, "sync"), ("/keyword-extraction", N.keyword_extraction, {"keywords": None}, "sync"),
        ("/semantic-similarity", N.semantic_similarity, {"similarity": None}, "sync"), ("/entity-extraction", N.entity_extraction, {"entities": None}, "sync"),
        ("/text-summarization", N.text_summarization, {"summary": None}, "sync"), ("/llm-evaluation", N.llm_output_evaluation, {"rating": None, "score": None}, "sync"),
        ("/ai-text-detection", N.ai_text_detection, {"verdict": None, "ai_likelihood": None}, "sync"),
        ("/wallet-balance", evm_intents.wallet_balance, {"balance": None}, "fetch"), ("/token-supply", evm_intents.token_supply, {"total_supply": None}, "fetch"),
        ("/tvl", defi_intents.tvl_lookup, {"tvl_usd": None}, "defi"), ("/yield-rate", defi_intents.yield_rate, {"supply_apy": None}, "defi"),
        ("/liquidity-depth", defi_intents.liquidity_depth, {"liquidity_usd": None}, "defi"),
        ("/contract-source-audit", solidity_intents.smart_contract_audit, {"verdict": None}, "sync"),
        ("/content-moderation", C.content_moderation, {"verdict": None, "flagged": None}, "sync"), ("/plagiarism-check", C.plagiarism_detection, {"similarity_pct": None}, "sync"),
        ("/email-security", emailsec_intents.lookup, {"lookup_ok": None}, "fetch"), ("/transaction-risk", C.transaction_risk, {"risk_level": None, "risk_score": None}, "sync"),
    ]:
        _extra_route(route, handler, ensure, kind)

    @app.get("/sentiment")
    async def sentiment(request: Request):
        return {"sentiment": None, **sentiment_intents.run(dict(request.query_params))}

    @app.api_route("/contract-audit", methods=["GET", "POST"])
    async def contract_audit(request: Request):
        params: dict[str, Any] = dict(request.query_params)
        if request.method == "POST":  # contracts are long: allow the text in a JSON or form body
            try:
                body = await request.json()
                params.update({k: v for k, v in body.items() if isinstance(v, (str, int, float))} if isinstance(body, dict) else {})
            except ValueError:
                params.update({k: v for k, v in (await request.form()).items() if isinstance(v, str)})
        return {"verdict": None, **contract_intents.run(params)}

    @app.get("/vuln-triage")
    async def telegraph_triage(request: Request):
        params: dict[str, Any] = dict(request.query_params)
        findings, errors, notes, _ = findings_from_query(params)
        if len(findings) > settings.max_batch_size:
            errors.append(__import__("app.models", fromlist=["ItemError"]).ItemError(
                field="cve_id", code="batch_too_large", message=f"Limit is {settings.max_batch_size} CVEs per request."))
            findings = findings[: settings.max_batch_size]
        if not findings:
            text = " ".join(str(params[k]) for k in ("question", "query", "q", "text", "input", "vulnerability", "cve_id", "cve") if params.get(k))
            hits = await request.app.state.svc.kev.search_products(text) if text else []
            return soft_answer("no_cve_identified", "No CVE identifier was found in the request, so no CVSS score or ranking can be given."
                               " Supply cve_id (e.g. CVE-2021-44228) or a question containing CVE ids.", errors=errors, kev_hits=hits)
        explicit = {f.cve_id for f in findings if f.cve_id in _explicit_ids(params)}
        focus = next(iter(explicit)) if len(explicit) == 1 else None
        svc: TriageService = request.app.state.svc
        resp = await svc.run(findings, errors=errors, notes=notes)
        if all(p.status == "insufficient_evidence" for p in resp.priorities):
            nf = all(p.signals["cvss"]["status"] == "not_found" for p in resp.priorities)
            ids = ", ".join(p.cve_id for p in resp.priorities[:5])
            msg = (f"No record for {ids} was found in NVD or the fallback database, so there is no CVSS score; it may be misspelled, reserved or not yet published."
                   if nf else f"Upstream vulnerability sources were unavailable or held no usable data for {ids}; no score or ranking is given rather than a guess.")
            return soft_answer("cve_not_found" if nf else "insufficient_evidence", msg, cve_id=resp.priorities[0].cve_id if len(resp.priorities) == 1 else None,
                               errors=errors, as_of=resp.generated_at)
        return to_telegraph_answer(resp, focus)

    return app


def _explicit_ids(params: dict[str, Any]) -> set[str]:
    from app.ids import extract_cve_ids
    raw = " ".join(str(params[k]) for k in ("cve_id", "cve", "vulnerability", "vulnerabilities", "cve_ids") if params.get(k))
    return set(extract_cve_ids(raw))


app = create_app()
