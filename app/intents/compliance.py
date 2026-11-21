"""Trust and compliance intents that need no network and no language model: content moderation, plagiarism (text overlap against a
supplied source) and payment-transaction risk. Output is evidence for human review, never a legal or financial determination."""
from __future__ import annotations

import re
from typing import Any

from app.intents.common import first, free_text, ok, soft
from app.intents.nlp import cosine, _vec
from app.intents.textutil import pick_text, words

MAX_CHARS = 8000


# ---- CONTENT_MODERATION_GENERAL ----------------------------------------------------------------------------------------
def _luhn(num: str) -> bool:
    d = [int(c) for c in num][::-1]
    return len(d) >= 13 and (sum(d[0::2]) + sum(sum(divmod(2 * x, 10)) for x in d[1::2])) % 10 == 0


RULES: list[tuple[str, str, re.Pattern]] = [
    ("violent_threat", "unsafe", re.compile(r"\b(?:i(?:'ll|’ll| will| am going to|'m going to|’m going to)|we(?:'ll| will)|gonna|going to)\s+(?:kill|murder|shoot|stab|hurt|beat up|burn down)\s+(?:you|him|her|them|everyone|your)\b|\byou(?:'re| are) (?:going to|gonna) die\b|\bkill yourself\b|\bkys\b", re.I)),
    ("hate", "unsafe", re.compile(r"\b(?:all|those|these)\s+[a-z]{3,20}\s+(?:should|must|deserve to)\s+(?:die|be (?:killed|deported|removed|exterminated|eliminated))\b|\b[a-z]{3,20}\s+are\s+(?:vermin|subhuman|parasites|cockroaches|animals|a disease)\b", re.I)),
    ("illegal_activity", "unsafe", re.compile(r"\b(?:buy|sell|selling|buying)\s+(?:cocaine|heroin|meth|fentanyl|stolen cards?|fake passports?|counterfeit (?:money|cash)|hacked accounts?)\b", re.I)),
    ("self_harm", "review", re.compile(r"\b(?:kill myself|end my life|want to die|commit suicide|hurt myself|self[- ]harm|don'?t want to (?:live|be alive))\b", re.I)),
    ("harassment", "review", re.compile(r"\byou(?:'re|’re| are| r)\s+(?:an?\s+)?(?:idiot|stupid|moron|loser|worthless|pathetic|dumb|trash|scum|useless|disgusting)\b|\b(?:shut up|go away)\b.{0,20}\b(?:idiot|loser|moron)\b|\b(?:idiot|moron)\b", re.I)),
    ("sexual_content", "review", re.compile(r"\b(?:porn|pornographic|nsfw|nude photos?|explicit sex|sex tape)\b", re.I)),
    ("profanity", "review", re.compile(r"\b(?:fuck\w*|shit\w*|bitch\w*|asshole|bastard|dickhead|bullshit)\b", re.I)),
    ("spam_or_scam", "review", re.compile(r"\b(?:click here|free money|you(?:'ve| have) won|claim your (?:prize|reward)|guaranteed returns?|double your (?:bitcoin|crypto|money|eth)|send \d+(?:\.\d+)? ?(?:btc|eth|usdt)|act now|limited time offer|risk[- ]free profit|verify your account (?:now|immediately))\b", re.I)),
]
PII = [("email address", re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")), ("US social security number", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
       ("phone number", re.compile(r"(?<!\w)\+?\d[\d\s().-]{8,15}\d(?!\w)"))]


def content_moderation(params: dict[str, Any]) -> dict[str, Any]:
    text = pick_text(params, "text", "content", "comment", "message", "post", limit=MAX_CHARS)
    if not text:
        q = free_text(params)
        m = re.search(r"[\"“']([^\"”]{3,})[\"”']", q)
        text = m.group(1) if m else None
    if not text:
        return soft("no_text", "No content to moderate was supplied, so no verdict is given.", verdict=None, flagged=None, categories=[])
    found: dict[str, dict[str, Any]] = {}
    for name, sev, rx in RULES:
        ms = [m.group() for m in rx.finditer(text)]
        if ms:
            found[name] = {"category": name, "severity": sev, "matches": ms[:3]}
    card = any(_luhn(re.sub(r"\D", "", m.group())) for m in re.finditer(r"\b(?:\d[ -]?){13,19}\b", text))
    pii = [label for label, rx in PII if rx.search(text) and not (label == "phone number" and card)]
    if card:
        pii.append("payment card number")
    if pii:
        found["personal_data"] = {"category": "personal_data", "severity": "review", "matches": pii}
    if not found:
        return ok("Safe: no policy-violating language, threats, scam patterns or personal data were detected by the rule set. Rules cover explicit patterns only; coded or implicit abuse may be missed.",
                  0.7, verdict="safe", flagged=False, categories=[], reason="No rule matched.", method="pattern rules (no language model)")
    unsafe = any(f["severity"] == "unsafe" for f in found.values())
    verdict = "unsafe" if unsafe else "review"
    cats = sorted(found, key=lambda c: (found[c]["severity"] != "unsafe", c))
    reason = "; ".join(f"{c.replace('_', ' ')}" + (f" ({', '.join(map(str, found[c]['matches'][:2]))})" if c != "personal_data" else f" ({', '.join(found[c]['matches'])})") for c in cats)
    answer = f"{'Unsafe' if unsafe else 'Needs review'}: flagged for {reason}."
    return ok(answer, 0.8 if unsafe else 0.7, verdict=verdict, flagged=True, categories=cats, reason=reason, details=[found[c] for c in cats], method="pattern rules (no language model)")


# ---- PLAGIARISM_DETECTION_GENERAL --------------------------------------------------------------------------------------
SHINGLE = 5


def plagiarism_detection(params: dict[str, Any]) -> dict[str, Any]:
    text = pick_text(params, "text", "content", "submission", "document", "suspect", limit=MAX_CHARS)
    ref = pick_text(params, "source", "reference", "original", "corpus", "source_text", "compare_to", limit=MAX_CHARS)
    if not text or not ref:
        from app.intents.textutil import split_pair
        a, b = split_pair(params, ("text", "submission"), ("source", "reference", "original"))
        text, ref = text or a, ref or b
    if not text:
        return soft("no_text", "No text to check was supplied, so no plagiarism result is given.", similarity_pct=None, plagiarized=None)
    if not ref:
        return soft("no_reference", "No source text to compare against was supplied. This service compares two supplied texts; it does not search the web or a corpus, so it cannot say the text is original.",
                    similarity_pct=None, plagiarized=None, verdict=None, matched_passages=[])
    tw, rw = words(text), words(ref)
    if len(tw) < SHINGLE:
        return soft("text_too_short", f"The text is shorter than {SHINGLE} words, too short to compare reliably.", similarity_pct=None, plagiarized=None)
    ref_sh = {tuple(rw[i:i + SHINGLE]) for i in range(len(rw) - SHINGLE + 1)}
    hit = [tuple(tw[i:i + SHINGLE]) in ref_sh for i in range(len(tw) - SHINGLE + 1)]
    covered = [False] * len(tw)
    passages, i = [], 0
    while i < len(hit):
        if hit[i]:
            j = i
            while j + 1 < len(hit) and hit[j + 1]:
                j += 1
            for k in range(i, j + SHINGLE):
                covered[k] = True
            passages.append({"words": j - i + SHINGLE, "text": " ".join(tw[i:j + SHINGLE])[:300]})
            i = j + 1
        else:
            i += 1
    verbatim = sum(covered) / len(tw)
    cos = cosine(_vec(text), _vec(ref))
    if verbatim >= 0.6:
        verdict = "high_overlap"
    elif verbatim >= 0.2:
        verdict = "partial_overlap"
    elif cos >= 0.75 and len(tw) >= 25:
        verdict = "possible_paraphrase"
    else:
        verdict = "no_overlap_found"
    plag = verdict in ("high_overlap", "partial_overlap", "possible_paraphrase")
    passages.sort(key=lambda p: -p["words"])
    answer = (f"{verdict.replace('_', ' ').capitalize()}: {verbatim * 100:.0f}% of the text's words sit in runs copied verbatim from the supplied source "
              f"({len(passages)} passage{'s' if len(passages) != 1 else ''}); vocabulary similarity {cos:.2f}. "
              "Compared against the supplied source only; this is not a search of the web or a corpus.")
    return ok(answer, 0.8 if verdict != "possible_paraphrase" else 0.55, similarity_pct=round(verbatim * 100, 1), vocabulary_similarity=round(cos, 3), plagiarized=plag,
              verdict=verdict, matched_passages=passages[:10], passage_count=len(passages), method=f"{SHINGLE}-word shingle containment plus TF cosine against the supplied source")


# ---- TRANSACTION_RISK_GENERAL ------------------------------------------------------------------------------------------
HIGH_RISK_CATEGORIES = {"gift card": 18, "gift cards": 18, "crypto": 14, "cryptocurrency": 14, "gambling": 14, "casino": 14, "electronics": 10, "jewelry": 12, "jewellery": 12,
                        "luxury": 10, "wire transfer": 14, "money transfer": 14, "digital goods": 8, "prepaid": 12, "travel": 6, "airline": 6, "adult": 10, "forex": 12}
LOW_RISK_CATEGORIES = {"grocery": -6, "groceries": -6, "utilities": -6, "utility": -6, "subscription": -3, "insurance": -4, "education": -3, "restaurant": -3, "pharmacy": -2}
WIN = {"second": 1 / 60, "seconds": 1 / 60, "min": 1, "mins": 1, "minute": 1, "minutes": 1, "hour": 60, "hours": 60, "day": 1440, "days": 1440}


def _amount(text: str) -> float | None:
    m = re.search(r"(?:[$€£₹]\s?|USD\s?|EUR\s?|GBP\s?)(\d[\d,]*(?:\.\d+)?)(\s?[kK]\b)?|(\d[\d,]*(?:\.\d+)?)\s?(USD|EUR|GBP|dollars|euros)\b", text)
    if not m:
        return None
    raw = (m.group(1) or m.group(3)).replace(",", "")
    v = float(raw)
    return v * 1000 if m.group(2) else v


def transaction_risk(params: dict[str, Any]) -> dict[str, Any]:
    ctx = " ".join(str(params[k]) for k in ("transaction", "description", "context", "question", "query", "text") if params.get(k))[:3000]
    structured: list[str] = []
    for k in ("amount", "merchant_category", "category", "attempts", "chargebacks", "country", "billing_country", "shipping_country"):
        if params.get(k):
            structured.append(f"{k.replace('_', ' ')} {params[k]}")
    low = (ctx + " " + " ".join(structured)).lower()
    if not low.strip():
        return soft("no_transaction", "No transaction context (amount, merchant category, velocity, chargeback history) was supplied, so no risk score is given.",
                    risk_level=None, risk_score=None, signals=[])
    score, signals = 12.0, []

    def add(points: float, label: str, evidence: str) -> None:
        nonlocal score
        score += points
        signals.append({"signal": label, "effect": "raises risk" if points > 0 else "lowers risk", "points": points, "evidence": evidence})

    amt = None
    if params.get("amount"):
        try:
            amt = float(str(params["amount"]).replace(",", "").lstrip("$€£"))
        except ValueError:
            amt = None
    amt = amt if amt is not None else _amount(ctx)
    if amt is not None:
        pts = 0 if amt < 100 else 6 if amt < 500 else 14 if amt < 1000 else 24 if amt < 2500 else 34 if amt < 10000 else 45
        if pts:
            add(pts, "transaction amount", f"{amt:,.0f}")
    for cat, pts in {**HIGH_RISK_CATEGORIES, **LOW_RISK_CATEGORIES}.items():
        if re.search(rf"\b{re.escape(cat)}\b", low):
            add(pts, "merchant category", cat)
            break
    m = re.search(r"(\d+)\s+(?:attempts?|transactions?|purchases?|orders?|tries|authori[sz]ations?)\s+(?:in|within|over)\s+(?:the last\s+)?(\d+)?\s*(seconds?|mins?|minutes?|hours?|days?)", low)
    if m:
        n, span = int(m.group(1)), (int(m.group(2) or 1)) * WIN[m.group(3)]
        if n >= 3 and span <= 1440:
            rate = n / max(span, 1)
            add(min(30, 8 + 6 * min(n, 6) + (10 if rate >= 0.2 else 0)), "velocity", f"{n} in {m.group(2) or 1} {m.group(3)}")
    elif re.search(r"\b(?:velocity|rapid|multiple attempts|repeated attempts)\b", low):
        add(14, "velocity", "rapid repeated attempts")
    m = re.search(r"(\d+)\s+(?:prior\s+|previous\s+)?chargebacks?", low)
    if m and int(m.group(1)) > 0:
        add(min(32, 14 + 8 * int(m.group(1))), "chargeback history", f"{m.group(1)} prior chargeback(s)")
    elif re.search(r"\b(?:prior|previous|history of)\s+chargebacks?\b", low) and not re.search(r"\bno (?:prior |previous )?chargebacks?\b", low):
        add(20, "chargeback history", "prior chargebacks reported")
    for pat, pts, label in [(r"billing (?:and|&) shipping (?:addresses? )?(?:differ|mismatch|do not match|don't match)|shipping address differs|different (?:shipping|billing) address", 10, "address mismatch"),
                            (r"\b(?:vpn|proxy|tor exit|anonymi[sz]er)\b", 10, "anonymised connection"),
                            (r"ip (?:country )?(?:differs|mismatch|does not match)|different country|foreign card|cross[- ]border", 10, "geography mismatch"),
                            (r"new device|unrecogni[sz]ed device|first time seen device", 8, "new device"),
                            (r"(?:new|just created|created (?:today|yesterday|\d+ (?:hours?|days?) ago)) account|account (?:created|opened) (?:today|yesterday|\d+ (?:hours?|days?) ago)", 12, "new account"),
                            (r"first[- ](?:time )?(?:purchase|order|transaction)|first purchase", 6, "first purchase"),
                            (r"cvv (?:fail|mismatch|declin)|avs (?:fail|mismatch)|failed (?:cvv|avs)", 18, "card verification failed"),
                            (r"(?:several|multiple|many) (?:declined|failed) (?:cards?|payments?)|card testing", 20, "declined card attempts"),
                            (r"disposable email|temporary email|mismatched email", 8, "disposable email")]:
        if re.search(pat, low):
            add(pts, label, re.search(pat, low).group())
    for pat, pts, label in [(r"3-?d secure(?:d)? (?:passed|authenti[a-z]+|verified|success)|3ds (?:passed|verified|success)|strong customer authentication", -14, "3-D Secure passed"),
                            (r"(?:returning|repeat|long[- ]standing|loyal) customer|(\d+) (?:prior|previous) (?:successful )?(?:orders|purchases|transactions)", -10, "established customer"),
                            (r"\bavs match(?:ed)?\b|cvv match(?:ed)?", -6, "card checks matched")]:
        m2 = re.search(pat, low)
        if m2 and not re.search(r"\bno (?:prior|previous)\b", low):
            add(pts, label, m2.group())
    if not signals:
        return soft("insufficient_evidence", "The text contains no scorable risk signals (amount, merchant category, velocity, chargebacks, geography, device or account age), so no risk level is given rather than a guess.",
                    risk_level=None, risk_score=None, signals=[])
    score = round(max(1.0, min(99.0, score)), 0)
    level = "critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 35 else "low"
    action = {"critical": "decline or hold for manual review", "high": "step-up authentication or manual review", "medium": "apply additional checks such as 3-D Secure", "low": "approve under normal controls"}[level]
    top = sorted(signals, key=lambda s: -abs(s["points"]))[:3]
    summary = f"Risk {level} (score {score:.0f}/100); suggested handling: {action}. Main signals: " + "; ".join(f"{s['signal']} ({s['evidence']})" for s in top) + ". Rule-based estimate, not a chargeback probability model."
    return ok(summary, 0.65, risk_level=level, risk_score=score, signals=signals, suggested_action=action, method="additive rule scorecard (no language model, no network)")
