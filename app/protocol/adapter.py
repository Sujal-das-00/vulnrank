"""Telegraph transport adapter.

Telegraph miners are plain HTTPS APIs described by a YAML manifest (telegraph/vulnrank.yaml); the
node maps the intent's typed request onto our GET endpoint and parses the response. For
VULNERABILITY_TRIAGE_GENERAL the scored response field is `cvss_base_score`
(NVD primary CVSS v3.1, 0-10), so it is always a top-level key, emitted first. Everything else is additive.

Which finding do the top-level fields describe?  If the caller named exactly one CVE in `cve_id`, that CVE
(even if other CVEs from a free-text question outrank it); otherwise the rank-1 finding. `top_level_basis` says which.
The full domain response (`details`) is NOT included here, it stays on POST /v1/triage, to keep the answer small.
"""
from __future__ import annotations

from typing import Any

from app import explain
from app.models import Priority, TriageResponse

_CONF = {"high": 0.9, "medium": 0.65, "low": 0.35}


def _asset_phrase(p: Priority) -> str | None:
    a = p.signals["asset_context"]
    if not a["supplied"]:
        return None
    bits = [f"{k}={a[k]}" for k in ("criticality", "exposure", "environment") if a.get(k)]
    return "Asset context used: " + ", ".join(bits) + "."


def _compact(p: Priority) -> dict[str, Any]:
    s = p.signals
    return {
        "rank": p.rank, "cve_id": p.cve_id, "asset_id": p.asset_id, "priority": p.priority, "risk_score": p.risk_score,
        "cvss_base_score": s["cvss"]["score"], "cvss_authoritative": s["cvss"]["authoritative"], "severity": (s["cvss"]["severity"] or "unknown").upper(),
        "kev_listed": s["kev"]["listed"], "kev_added": s["kev"]["date_added"], "kev_due": s["kev"]["due_date"],
        "ransomware": s["kev"]["known_ransomware_use"], "epss": s["epss"]["probability"], "epss_percentile": s["epss"]["percentile"],
        "confidence_label": p.confidence_label, "evidence_coverage": p.evidence_coverage,
        "why_ranked_here": p.why_ranked_here, "recommended_action": p.recommended_action, "uncertainty": p.uncertainty,
        "asset_phrase": _asset_phrase(p),
    }


def to_telegraph_answer(resp: TriageResponse, focus_cve: str | None = None) -> dict[str, Any]:
    ranking = [_compact(p) for p in resp.priorities]
    lead = next((p for p in resp.priorities if focus_cve and p.cve_id == focus_cve), resp.priorities[0])
    basis = "requested_cve" if lead.cve_id == focus_cve else "rank_1"
    s = lead.signals
    summary = explain.summary_text(ranking if len(ranking) > 1 else [_compact(lead)], [], resp.limitations,
                                   focus=lead.cve_id if basis == "requested_cve" and len(ranking) > 1 else None)
    return {
        "cvss_base_score": s["cvss"]["score"],
        "cve_id": lead.cve_id,
        "summary": summary,
        "answer": summary,
        "priority": lead.priority,
        "risk_score": lead.risk_score,
        "severity": (s["cvss"]["severity"] or "unknown").upper(),
        "cvss_version": s["cvss"]["version"],
        "cvss_vector": s["cvss"]["vector"],
        "cvss_source": s["cvss"]["source"],
        "cvss_is_nvd_primary": s["cvss"]["authoritative"],
        "confidence": _CONF[lead.confidence_label],
        "confidence_label": lead.confidence_label,
        "evidence_coverage": lead.evidence_coverage,
        "kev_listed": s["kev"]["listed"],
        "epss_probability": s["epss"]["probability"],
        "epss_percentile": s["epss"]["percentile"],
        "recommended_action": (lead.recommended_action or "").split(" CISA required action")[0] or None,
        "uncertainty": lead.uncertainty,
        "top_level_basis": basis,
        "ranking": ranking if len(ranking) > 1 else [],
        "evidence": [e.model_dump(exclude_none=True) for e in lead.evidence],
        "as_of": resp.generated_at,
        "engine_version": resp.engine_version,
        "score_version": resp.score_version,
        "source_status": resp.source_status,
        "errors": [e.model_dump(exclude_none=True) for e in resp.errors],
    }


def soft_answer(code: str, message: str, *, cve_id: str | None = None, errors: list[Any] | None = None,
                kev_hits: list[tuple[str, dict[str, Any]]] | None = None, as_of: str | None = None) -> dict[str, Any]:
    """A non-empty 200 answer for requests we cannot score. cvss_base_score is null, never invented."""
    lines = [message]
    if kev_hits:
        lines.append("CISA KEV entries matching your wording (known exploited in the wild): " + "; ".join(
            f"{cid} ({(v.get('vendor') or '')} {(v.get('product') or '')}, added {v.get('date_added')}"
            + (", used in ransomware" if v.get("ransomware") else "") + ")" for cid, v in kev_hits) + ".")
        lines.append("Send the specific CVE id(s) for a scored, ranked triage.")
    text = " ".join(lines)
    return {
        "cvss_base_score": None, "cve_id": cve_id, "summary": text, "answer": text, "status": code,
        "priority": "unknown", "confidence": 0.0, "kev_candidates": [cid for cid, _ in (kev_hits or [])],
        "top_level_basis": "none", "ranking": [], "evidence": [], "as_of": as_of,
        "errors": [e.model_dump(exclude_none=True) if hasattr(e, "model_dump") else e for e in (errors or [])],
    }
