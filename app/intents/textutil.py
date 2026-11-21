"""Small text helpers shared by the rule-based language intents (no model, no network)."""
from __future__ import annotations

import re
from typing import Any

STOP = frozenset("""a about above after again against all am an and any are aren't as at be because been before being below between both but by can can't
cannot could did do does doing don't down during each few for from further had has have having he her here hers herself him himself his how i if in into is
it its itself just let's me more most my myself no nor not of off on once only or other our ours ourselves out over own same she should so some such than
that the their theirs them themselves then there these they this those through to too under until up very was we were what when where which while who whom
why will with would you your yours yourself yourselves also may might shall us one two get got like make made many much new use used using""".split())

WORD = re.compile(r"[A-Za-z][A-Za-z'\-]*|\d+(?:[.,]\d+)*")
SENT_SPLIT = re.compile(r"(?<=[.!?])[\"')\]]*\s+(?=[\"'(\[]?[A-Z0-9])|\n{2,}")


def words(text: str) -> list[str]:
    return [w.lower() for w in WORD.findall(text)]


def content_words(text: str) -> list[str]:
    return [w for w in words(text) if w not in STOP and len(w) > 2 and not w[0].isdigit()]


def stem(w: str) -> str:
    """Crude suffix stripping, enough to match plurals and verb forms; deliberately conservative."""
    for suf in ("ingly", "edly", "ing", "ies", "ied", "ed", "es", "s", "ly"):
        if w.endswith(suf) and len(w) - len(suf) >= 4:
            return (w[: -len(suf)] + "y") if suf in ("ies", "ied") else w[: -len(suf)]
    return w


def sentences(text: str) -> list[str]:
    parts = [s.strip() for s in SENT_SPLIT.split(text.strip()) if s and s.strip()]
    return parts or ([text.strip()] if text.strip() else [])


def pick_text(params: dict[str, Any], *keys: str, limit: int = 8000) -> str | None:
    for k in keys:
        v = params.get(k)
        if v is not None and str(v).strip():
            return str(v).strip()[:limit]
    return None


def split_pair(params: dict[str, Any], a_keys: tuple[str, ...], b_keys: tuple[str, ...], free_keys: tuple[str, ...] = ("question", "query", "text", "input")) -> tuple[str | None, str | None]:
    """Two texts from explicit params, or from one free-text value split on ' vs ', '|', a blank line or ' and ' between quoted strings."""
    a, b = pick_text(params, *a_keys), pick_text(params, *b_keys)
    if a and b:
        return a, b
    raw = pick_text(params, *free_keys)
    if raw:
        quoted = re.findall(r"[\"“]([^\"”]{3,})[\"”]", raw)
        if len(quoted) >= 2:
            return quoted[0].strip(), quoted[1].strip()
        for sep in (" ||| ", "|||", "\n\n", " | ", " vs. ", " vs ", " versus "):
            if sep in raw:
                x, y = raw.split(sep, 1)
                if x.strip() and y.strip():
                    return x.strip(), y.strip()
    return a, b


def pct(x: float) -> float:
    return round(100.0 * x, 1)
