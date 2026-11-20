"""LANGUAGE_TRANSLATION_GENERAL: translation through MyMemory (public, keyless). Text leaves this service: disclosed in the manifest."""
from __future__ import annotations

import asyncio
import re
from typing import Any

from app.intents.common import first, free_text, ok, soft
from app.sources.base import Fetcher, SourceError

API = "https://api.mymemory.translated.net/get"
MAX_CHARS = 1500
CHUNK = 450  # MyMemory accepts at most 500 bytes per query
LANGS = {
    "english": "en", "french": "fr", "german": "de", "spanish": "es", "italian": "it", "portuguese": "pt", "dutch": "nl", "russian": "ru",
    "chinese": "zh-CN", "mandarin": "zh-CN", "japanese": "ja", "korean": "ko", "arabic": "ar", "hindi": "hi", "bengali": "bn", "turkish": "tr",
    "polish": "pl", "swedish": "sv", "norwegian": "no", "danish": "da", "finnish": "fi", "greek": "el", "czech": "cs", "hungarian": "hu",
    "romanian": "ro", "ukrainian": "uk", "hebrew": "he", "thai": "th", "vietnamese": "vi", "indonesian": "id", "malay": "ms", "urdu": "ur",
    "tamil": "ta", "telugu": "te", "marathi": "mr", "gujarati": "gu", "persian": "fa", "farsi": "fa", "swahili": "sw", "catalan": "ca",
}
CODES = {v.lower(): v for v in LANGS.values()} | {"zh": "zh-CN"}
_QUOTED = re.compile(r"[\"“”']([^\"“”]{2,})[\"“”']\s*[?.!]*\s*$|[\"“”]([^\"“”]{2,})[\"“”]")
_TARGET = re.compile(r"\b(?:into|to|in)\s+([A-Za-z\-]+)\b", re.I)
_SOURCE = re.compile(r"\bfrom\s+([A-Za-z\-]+)\b", re.I)


def lang_code(v: str | None) -> str | None:
    if not v:
        return None
    v = v.strip().lower()
    return LANGS.get(v) or CODES.get(v) or (v if re.fullmatch(r"[a-z]{2}(-[a-z]{2})?", v) and v.split("-")[0] in CODES else None)


def parse(params: dict[str, Any]) -> tuple[str | None, str | None, str | None]:
    text = first(params, "text", "content", "sentence", "input_text", "source_text")
    target = lang_code(first(params, "target_language", "target", "to", "target_lang", "language", "lang"))
    source = lang_code(first(params, "source_language", "source", "from", "source_lang"))
    q = free_text(params)
    if q:
        if not target:
            for m in _TARGET.finditer(q):
                if lang_code(m.group(1)):
                    target = lang_code(m.group(1))
                    break
        if not source:
            m = _SOURCE.search(q)
            source = lang_code(m.group(1)) if m else None
        if not text:
            m = _QUOTED.search(q)
            text = (m.group(1) or m.group(2)) if m else (q.split(":", 1)[1].strip() if ":" in q else None)
    return (text.strip() if text else None), target, source


def _chunks(text: str) -> list[str]:
    parts, cur = [], ""
    for sent in re.split(r"(?<=[.!?])\s+", text):
        while len(sent) > CHUNK:  # a single very long sentence: split on whitespace
            cut = sent.rfind(" ", 0, CHUNK) or CHUNK
            parts.append(sent[:cut]); sent = sent[cut:].lstrip()
        if len(cur) + len(sent) + 1 > CHUNK and cur:
            parts.append(cur); cur = sent
        else:
            cur = f"{cur} {sent}".strip()
    if cur:
        parts.append(cur)
    return parts


async def _one(f: Fetcher, chunk: str, pair: str, timeout: float, deadline: float | None) -> dict[str, Any]:
    _, js = await f.get_json(API, {"q": chunk, "langpair": pair}, timeout=timeout, deadline=deadline)
    if not isinstance(js, dict) or js.get("quotaFinished") or str(js.get("responseStatus")) not in ("200", "None"):
        raise SourceError("rate_limited" if (js or {}).get("quotaFinished") else "http_error", "MyMemory did not return a translation")
    data = js["responseData"]
    out = data["translatedText"]
    if not out or "MYMEMORY WARNING" in out.upper() or "INVALID" in out.upper()[:12]:
        raise SourceError("rate_limited", "MyMemory refused the request")
    return {"text": out, "match": data.get("match"), "detected": data.get("detectedLanguage")}


async def run(f: Fetcher, params: dict[str, Any], *, timeout: float, deadline: float | None) -> dict[str, Any]:
    text, target, source = parse(params)
    if not text:
        return soft("no_text", "No text to translate was supplied.", translation=None)
    if not target:
        return soft("no_target_language", "No target language was recognised, so nothing was translated. Name one, for example French or fr.",
                    translation=None)
    if len(text) > MAX_CHARS:
        return soft("text_too_long", f"The text is {len(text)} characters; the limit is {MAX_CHARS}. Send it in parts.", translation=None)
    if source and source.split("-")[0] == target.split("-")[0]:
        return ok(text, 0.99, translation=text, source_language=source, target_language=target, note="Source and target language are the same; text returned unchanged.")
    pair = f"{source or 'Autodetect'}|{target}"
    try:
        res = await asyncio.gather(*(_one(f, c, pair, timeout, deadline) for c in _chunks(text)))
    except SourceError as e:
        return soft("unavailable", f"The translation service is unavailable or over quota ({e.kind}); no translation is given.", translation=None,
                    target_language=target)
    translation = " ".join(r["text"] for r in res)
    matches = [float(r["match"]) for r in res if r["match"] is not None]
    quality = round(sum(matches) / len(matches), 2) if matches else None
    detected = source or next((r["detected"] for r in res if r["detected"]), None)
    return ok(translation, round(min(0.95, quality if quality is not None else 0.6), 2), translation=translation, source_language=detected,
              target_language=target, match_quality=quality, engine="MyMemory", chunks=len(res))
