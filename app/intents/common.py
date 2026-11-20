"""Helpers shared by the extra intent endpoints."""
from __future__ import annotations

from typing import Any

from app.clock import utc_iso


def first(params: dict[str, Any], *keys: str) -> str | None:
    """First non-empty query parameter among `keys`, stripped."""
    for k in keys:
        v = params.get(k)
        if v is not None and str(v).strip():
            return str(v).strip()
    return None


def free_text(params: dict[str, Any]) -> str:
    return " ".join(str(params[k]) for k in ("question", "query", "q", "text", "input", "prompt") if params.get(k))[:2000]


def soft(code: str, message: str, **fields: Any) -> dict[str, Any]:
    """A non-empty 200 answer for a request that cannot be answered. Graded fields are passed as None."""
    return {**fields, "outcome": code, "answer": message, "summary": message, "confidence": 0.0, "as_of": utc_iso()}


def ok(answer: str, confidence: float, **fields: Any) -> dict[str, Any]:
    return {**fields, "outcome": "ok", "answer": answer, "summary": answer, "confidence": confidence, "as_of": utc_iso()}
