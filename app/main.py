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
from app.triage import TriageService
from app.warmer import warm_cache

log = logging.getLogger("vulnrank")
MAX_BODY_BYTES = 256 * 1024


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
        warmer = asyncio.ensure_future(warm_cache(svc, settings)) if settings.warm_enabled else None
        yield
        if warmer:
            warmer.cancel()
        await client.aclose()

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
                "intent": "VULNERABILITY_TRIAGE_GENERAL", "endpoints": ["/vuln-triage", "/v1/triage", "/v1/score-model", "/v1/sources/status", "/health"]}

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
        return {h: f.breaker_state(h) for h in ("services.nvd.nist.gov", "www.cisa.gov", "api.first.org", "cvedb.shodan.io")}

    @app.post("/v1/triage")
    async def triage(request: Request, body: RawTriageRequest):
        findings, errors = findings_from_body(body, settings.max_batch_size)
        if not findings:
            return JSONResponse({"error": "no_valid_findings", "errors": [e.model_dump(exclude_none=True) for e in errors]}, status_code=422)
        svc: TriageService = request.app.state.svc
        resp = await svc.run(findings, request_id=body.request_id, errors=errors, top_n=body.preferences.top_n,
                             include_remediation=body.preferences.include_remediation, total_submitted=len(body.findings))
        return resp

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
