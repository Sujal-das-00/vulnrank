"""SENTIMENT_ANALYSIS_GENERAL: lexicon-and-rules sentiment (VADER), CPU only, no language model, no network."""
from __future__ import annotations

import re
from functools import lru_cache
from typing import Any

from app.intents.common import first, free_text, ok, soft

MAX_CHARS = 5000
_STOP = frozenset("the a an and or but is are was were be been it this that of to in on for with not no very i you he she we they my your "
                  "so just have has had do does did at as by from about its it's i'm don't can't won't".split())
_QUOTED = re.compile(r"[\"“”'‘’]([^\"“”]{3,}?)[\"“”'‘’](?=\s*[?.!]*\s*$|\s+(?:and|or|to)\b)|[\"“”]([^\"“”]{3,})[\"“”]")


@lru_cache(maxsize=1)
def _analyzer():
    from vaderSentiment.vaderSentiment import SentimentIntensityAnalyzer
    return SentimentIntensityAnalyzer()


def extract_text(params: dict[str, Any]) -> str | None:
    t = first(params, "text", "review", "content", "sentence", "message", "comment", "document", "passage")
    if t:
        return t[:MAX_CHARS]
    q = free_text(params)
    if not q:
        return None
    quoted = [a or b for a, b in _QUOTED.findall(q)]
    if quoted:
        return max(quoted, key=len)[:MAX_CHARS]
    if ":" in q:
        tail = q.split(":", 1)[1].strip()
        if len(tail) >= 3:
            return tail[:MAX_CHARS]
    return None


def _looks_english(text: str) -> bool:
    words = re.findall(r"[a-zA-Z']+", text.lower())
    letters = sum(c.isalpha() for c in text)
    if letters == 0:
        return True
    ascii_share = sum(c.isascii() and c.isalpha() for c in text) / letters
    return ascii_share > 0.9 and (len(words) < 4 or any(w in _STOP for w in words))


def analyze(text: str) -> dict[str, Any]:
    a = _analyzer()
    s = a.polarity_scores(text)
    cues = []
    for tok in re.findall(r"[A-Za-z']+", text):
        v = a.lexicon.get(tok.lower())
        if v is not None and abs(v) >= 1.5:
            cues.append((tok.lower(), v))
    seen, ordered = set(), []
    for w, v in sorted(cues, key=lambda c: -abs(c[1])):
        if w not in seen:
            seen.add(w)
            ordered.append({"word": w, "valence": v})
    return {**s, "cues": ordered[:6]}


def run(params: dict[str, Any]) -> dict[str, Any]:
    text = extract_text(params)
    if not text or not re.search(r"[A-Za-z]", text):
        return soft("no_text", "No text to analyse was supplied, so no sentiment is given. Supply text (a sentence, review or message).",
                    sentiment=None, score=None)
    r = analyze(text)
    c, pos, neg = r["compound"], r["pos"], r["neg"]
    if pos >= 0.25 and neg >= 0.25 and abs(c) < 0.35:
        label = "mixed"
    elif c >= 0.05:
        label = "positive"
    elif c <= -0.05:
        label = "negative"
    else:
        label = "neutral"
    strength = "strongly " if abs(c) >= 0.6 else "moderately " if abs(c) >= 0.3 else "slightly " if label in ("positive", "negative") else ""
    conf = round(min(0.97, 0.55 + abs(c) * 0.45), 2) if label != "mixed" else 0.6
    note = None
    if not _looks_english(text):
        conf, note = min(conf, 0.4), "The text does not look English; this analyser's lexicon is English, so confidence is low."
    cue_txt = ""
    if r["cues"]:
        cue_txt = " Driven by: " + ", ".join(f"{x['word']} ({'+' if x['valence'] > 0 else ''}{x['valence']:g})" for x in r["cues"][:4]) + "."
    answer = f"The sentiment is {strength}{label} (compound score {c:+.2f}, from -1 most negative to +1 most positive).{cue_txt}"
    if note:
        answer += " " + note
    return ok(answer, conf, sentiment=label, score=c, positive=r["pos"], neutral=r["neu"], negative=r["neg"],
              cues=r["cues"], method="VADER lexicon and rules (no language model)", language_note=note, characters=len(text))
