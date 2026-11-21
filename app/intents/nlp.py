"""Rule-based language intents (no language model, no network): classification, keywords, similarity, entities, summaries,
output evaluation and AI-text detection. Every answer states its method; weak evidence gives null, never a guess."""
from __future__ import annotations

import json
import math
import re
from collections import Counter
from typing import Any

from app.intents.common import first, free_text, ok, soft
from app.intents.textutil import STOP, content_words, pct, pick_text, sentences, split_pair, stem, words

MAX_CHARS = 8000

# ---- TEXT_CLASSIFICATION_GENERAL ----------------------------------------------------------------------------------------
LEXICON: dict[str, str] = {
    "billing": "bill billing invoice charge charged refund payment paid price pricing subscription renewal card receipt fee overcharged",
    "technical": "error bug crash broken fails failed failure install update login password reset server connect connection slow loading app website",
    "account": "account login log password username email profile sign signup register verify verification locked access two-factor",
    "complaint": "terrible awful worst unacceptable disappointed angry complaint unhappy poor horrible disgusted",
    "praise": "great excellent amazing love loved fantastic wonderful perfect awesome thank thanks brilliant",
    "question": "how what why when where can could does is are help explain",
    "spam": "free winner prize click offer limited urgent congratulations giveaway cheap buy discount lottery viagra unsubscribe",
    "sports": "game match team player score season league goal coach championship tournament win won",
    "politics": "election government president senate vote voter policy minister parliament congress law campaign",
    "technology": "software hardware ai computer internet app startup data cloud chip algorithm developer code",
    "finance": "stock market bank investment interest loan inflation earnings revenue profit trading fund economy",
    "health": "health doctor disease patient hospital medicine treatment symptom vaccine therapy clinical diet",
    "business": "company business customers sales growth merger acquisition ceo strategy management enterprise",
    "entertainment": "movie film music album actor actress celebrity series show concert streaming director",
    "science": "research study scientists experiment physics biology climate space particle discovery journal",
    "travel": "flight hotel booking trip travel airport visa tour vacation luggage itinerary",
    "legal": "contract agreement clause liability law lawsuit court compliance regulation terms license",
    "urgent": "urgent asap immediately emergency critical now deadline",
    "positive": "good great happy love excellent wonderful best amazing pleased",
    "negative": "bad terrible awful hate worst sad angry poor horrible",
}


def parse_categories(raw: Any) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, (list, tuple)):
        items = [str(x) for x in raw]
    else:
        s = str(raw).strip()
        if s.startswith("["):
            try:
                items = [str(x) for x in json.loads(s)]
            except ValueError:
                items = re.split(r"[,;|]", s.strip("[]"))
        else:
            items = re.split(r"[,;|]|\bor\b", s)
    out, seen = [], set()
    for i in items:
        c = i.strip().strip("\"'").strip()
        if c and c.lower() not in seen:
            seen.add(c.lower())
            out.append(c)
    return out[:30]


def _category_terms(cat: str) -> tuple[set[str], set[str]]:
    label = {stem(w) for w in words(cat) if w not in STOP}
    syn: set[str] = set()
    for key, lex in LEXICON.items():
        if key in cat.lower() or stem(key) in label:
            syn |= {stem(w) for w in lex.split()}
    return label, syn - label


def classify(text: str, categories: list[str]) -> dict[str, Any]:
    toks = [stem(w) for w in words(text)]
    counts = Counter(toks)
    scores: dict[str, float] = {}
    evidence: dict[str, list[str]] = {}
    for cat in categories:
        label, syn = _category_terms(cat)
        s, ev = 0.0, []
        for t in label:
            if counts.get(t):
                s += 3.0 * min(counts[t], 2)
                ev.append(t)
        for t in syn:
            if counts.get(t):
                s += 1.0 * min(counts[t], 2)
                ev.append(t)
        scores[cat], evidence[cat] = s, ev[:6]
    ranked = sorted(scores.items(), key=lambda kv: -kv[1])
    return {"ranked": ranked, "evidence": evidence}


def text_classification(params: dict[str, Any]) -> dict[str, Any]:
    text = pick_text(params, "text", "content", "message", "ticket", "document", limit=MAX_CHARS)
    cats = parse_categories(first(params, "categories", "labels", "category", "classes", "options"))
    q = free_text(params)
    if not text and q:
        m = re.search(r"[\"“']([^\"”]{4,})[\"”']\s*[?.]?\s*$", q)
        text = m.group(1) if m else None
        if not cats:
            m2 = re.search(r"\bas\b\s+(?:either\s+|one of\s+)?(.+?)(?::|\?|$)", q, re.I)
            cats = parse_categories(m2.group(1)) if m2 else []
    if not text:
        return soft("no_text", "No text to classify was supplied, so no category is given.", category=None)
    defaults = False
    if len(cats) < 2:
        cats, defaults = ["billing", "technical", "account", "complaint", "question", "spam", "sports", "politics", "technology", "finance", "health", "business", "entertainment", "science", "travel", "legal"], True
    r = classify(text, cats)
    (top, s1), (_, s2) = r["ranked"][0], (r["ranked"][1] if len(r["ranked"]) > 1 else ("", 0.0))
    if s1 <= 0:
        return soft("no_signal", f"None of the categories ({', '.join(cats[:6])}{'...' if len(cats) > 6 else ''}) is supported by words in the text, so no category is assigned rather than a guess.",
                    category=None, categories=cats, scores={c: 0 for c in cats[:10]}, method="keyword and label-overlap scoring (no language model)")
    conf = round(min(0.9, 0.45 + 0.5 * (s1 - s2) / max(s1, 1.0) + min(0.15, s1 / 40)), 2)
    if s1 == s2:
        conf = 0.3
    ev = r["evidence"][top]
    reason = (f"The text contains {', '.join(repr(x) for x in ev[:4])}, which match '{top}'." if ev else f"'{top}' scored highest.")
    if s1 == s2:
        reason += " Another category scored equally, so confidence is low."
    answer = f"Category: {top}. {reason}"
    return ok(answer, conf, category=top, reason=reason, categories=cats, scores={c: round(s, 1) for c, s in r["ranked"][:10]},
              used_default_categories=defaults, method="keyword and label-overlap scoring (no language model)")


# ---- KEYWORD_EXTRACTION_GENERAL ----------------------------------------------------------------------------------------
def keyword_extraction(params: dict[str, Any]) -> dict[str, Any]:
    text = pick_text(params, "text", "content", "document", "body", "article", limit=MAX_CHARS)
    if not text:
        q = free_text(params)
        m = re.search(r":\s*(.{40,})$", q, re.S)
        text = m.group(1) if m else (q if len(q.split()) >= 8 else None)
    if not text:
        return soft("no_text", "No body text was supplied, so no keywords are extracted.", keywords=[], keyword_count=0)
    try:
        top_n = max(1, min(30, int(first(params, "top_n", "limit", "count", "max_keywords", "n") or 10)))
    except ValueError:
        top_n = 10
    # RAKE: candidate phrases are runs of non-stopwords; a word scores degree/frequency, a phrase the sum of its words
    cands: list[list[str]] = []
    for chunk in re.split(r"[.,;:!?()\[\]{}\"“”\n\t]|\s[-–—]\s", text):
        cur: list[str] = []
        for w in words(chunk):
            if w in STOP or w[0].isdigit() or len(w) < 3:
                if cur:
                    cands.append(cur)
                cur = []
            else:
                cur.append(w)
        if cur:
            cands.append(cur)
    freq, deg = Counter(), Counter()
    for ph in cands:
        for w in ph:
            freq[w] += 1
            deg[w] += len(ph)
    scores: dict[str, float] = {}
    for ph in cands:
        if len(ph) > 4:
            continue
        key = " ".join(ph)
        scores[key] = max(scores.get(key, 0.0), sum(deg[w] / freq[w] for w in ph))
    # a phrase seen several times outranks an equal one seen once
    occ = Counter(" ".join(p) for p in cands)
    ranked = sorted(scores.items(), key=lambda kv: (-(kv[1] * (1 + 0.25 * math.log(occ[kv[0]]))), kv[0]))
    out, used = [], set()
    for k, v in ranked:
        stems = {stem(w) for w in k.split()}
        if len(stems & used) == len(stems):
            continue
        used |= stems
        out.append({"keyword": k, "score": round(v, 2), "occurrences": occ[k]})
        if len(out) >= top_n:
            break
    if not out:
        return soft("no_keywords", "The text has no content words to extract keywords from.", keywords=[], keyword_count=0)
    answer = "Keywords: " + ", ".join(o["keyword"] for o in out) + "."
    return ok(answer, 0.8 if len(text.split()) >= 30 else 0.55, keywords=[o["keyword"] for o in out], keyword_scores=out, keyword_count=len(out),
              method="RAKE phrase scoring (stopword-delimited, no language model)")


# ---- SEMANTIC_SIMILARITY_GENERAL ---------------------------------------------------------------------------------------
SYN = {"buy": "purchase", "purchased": "purchase", "bought": "purchase", "car": "automobile", "auto": "automobile", "big": "large", "huge": "large",
       "small": "little", "tiny": "little", "fast": "quick", "rapid": "quick", "quickly": "quick", "begin": "start", "commence": "start",
       "end": "finish", "stop": "finish", "terminate": "finish", "happy": "glad", "joyful": "glad", "sad": "unhappy", "doctor": "physician",
       "film": "movie", "cheap": "inexpensive", "smart": "intelligent", "clever": "intelligent", "ask": "request", "answer": "reply", "respond": "reply",
       "error": "bug", "fault": "bug", "defect": "bug", "begins": "start", "price": "cost", "money": "cash", "kid": "child", "children": "child"}


def _vec(text: str) -> Counter:
    toks = [stem(SYN.get(w, w)) for w in content_words(text)]
    toks = [SYN.get(t, t) for t in toks]
    v = Counter(toks)
    v.update(f"{a}_{b}" for a, b in zip(toks, toks[1:]))  # bigrams reward shared word order
    return v


def cosine(a: Counter, b: Counter) -> float:
    if not a or not b:
        return 0.0
    dot = sum(a[k] * b.get(k, 0) for k in a)
    return dot / (math.sqrt(sum(x * x for x in a.values())) * math.sqrt(sum(x * x for x in b.values())))


def semantic_similarity(params: dict[str, Any]) -> dict[str, Any]:
    a, b = split_pair(params, ("text_a", "text1", "sentence1", "sentence_a", "a", "first", "text"), ("text_b", "text2", "sentence2", "sentence_b", "b", "second", "other"))
    if not a or not b:
        return soft("need_two_texts", "Two texts are needed to compare (text_a and text_b, or two quoted sentences), so no similarity is given.", similarity=None)
    a, b = a[:MAX_CHARS], b[:MAX_CHARS]
    va, vb = _vec(a), _vec(b)
    if not va or not vb:
        return soft("no_content_words", "One of the texts has no content words, so no similarity is given.", similarity=None)
    sim = round(cosine(va, vb), 3)
    wa, wb = set(content_words(a)), set(content_words(b))
    jac = round(len(wa & wb) / len(wa | wb), 3) if wa | wb else 0.0
    verdict = "near_identical" if sim >= 0.9 else "highly_similar" if sim >= 0.6 else "related" if sim >= 0.3 else "different"
    shared = sorted(wa & wb)[:10]
    answer = (f"The texts are {verdict.replace('_', ' ')}: cosine similarity {sim:.2f} (0 unrelated, 1 identical)"
              + (f"; shared terms: {', '.join(shared)}." if shared else "; they share no content words.")
              + " This is lexical similarity with a small synonym list, not a neural embedding, so paraphrases with different vocabulary score low.")
    return ok(answer, 0.75, similarity=sim, cosine_similarity=sim, jaccard=jac, verdict=verdict, shared_terms=shared,
              method="TF cosine over stemmed words and bigrams (no embedding model)")


# ---- ENTITY_EXTRACTION_GENERAL -----------------------------------------------------------------------------------------
MONTHS = "January|February|March|April|May|June|July|August|September|October|November|December|Jan|Feb|Mar|Apr|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec"
PATTERNS: list[tuple[str, re.Pattern]] = [
    ("EMAIL", re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")),
    ("URL", re.compile(r"\bhttps?://[^\s<>\"']+[^\s<>\"'.,;:!?)]")),
    ("CVE", re.compile(r"\bCVE-\d{4}-\d{4,19}\b", re.I)),
    ("TX_HASH", re.compile(r"\b0x[0-9a-fA-F]{64}\b")),
    ("ETH_ADDRESS", re.compile(r"\b0x[0-9a-fA-F]{40}\b")),
    ("IP_ADDRESS", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")),
    ("DATE", re.compile(rf"\b\d{{4}}-\d{{2}}-\d{{2}}\b|\b(?:{MONTHS})\.? \d{{1,2}}(?:st|nd|rd|th)?(?:,? \d{{4}})?\b|\b\d{{1,2}}(?:st|nd|rd|th)? (?:{MONTHS})\.?(?:,? \d{{4}})?\b|\b(?:{MONTHS}) \d{{4}}\b")),
    ("MONEY", re.compile(r"(?:[$€£₹]\s?\d[\d,]*(?:\.\d+)?(?:\s?(?:million|billion|bn|m|k))?)|\b\d[\d,]*(?:\.\d+)?\s?(?:USD|EUR|GBP|INR|dollars|euros|rupees)\b", re.I)),
    ("PERCENT", re.compile(r"\b\d+(?:\.\d+)?\s?%")),
    ("PHONE", re.compile(r"(?<!\w)\+?\d[\d\s().-]{8,15}\d(?!\w)")),
    ("HASHTAG", re.compile(r"(?<!\w)#\w{2,}")),
    ("HANDLE", re.compile(r"(?<![\w.])@\w{2,}")),
]
ORG_SUFFIX = re.compile(r"\b(?:Inc|Ltd|LLC|LLP|Corp|Corporation|GmbH|PLC|Co|Company|Bank|University|Institute|Foundation|Group|Technologies|Systems|Association|Agency|Ministry|Department|Commission|Council)\b\.?")
TITLE = re.compile(r"^(?:Mr|Mrs|Ms|Dr|Prof|President|Senator|Judge|Sir|Mx)\.?$")
CAP_RUN = re.compile(r"\b[A-Z][\w'’-]*(?:\s+(?:of|de|van|von|the|and|&)?\s*[A-Z][\w'’-]*)*")
NOT_ENTITY = frozenset("The A An This That These Those It He She We They I You In On At For And But Or If When While After Before As By With From To Of Our Their His Her Its My Your Monday Tuesday Wednesday Thursday Friday Saturday Sunday".split())
PLACES = frozenset("""Afghanistan Argentina Australia Austria Belgium Brazil Canada Chile China Colombia Denmark Egypt England Finland France Germany Greece India Indonesia Iran Iraq Ireland Israel Italy Japan Kenya Korea Mexico Netherlands Nigeria Norway Pakistan Peru Philippines Poland Portugal Russia Scotland Singapore Spain Sweden Switzerland Thailand Turkey Ukraine Vietnam Wales
London Paris Berlin Madrid Rome Tokyo Beijing Delhi Mumbai Bangalore Moscow Dubai Sydney Toronto Chicago Boston Seattle Austin Miami Houston Dallas Denver Atlanta Texas California Florida Africa Asia Europe America Washington Brooklyn Manhattan Kyiv Lagos Nairobi Cairo Istanbul Seoul Bangkok Jakarta Lisbon Dublin Vienna Zurich Geneva Oslo Stockholm Helsinki Warsaw Prague Budapest Athens""".split())


ORG_LEADERS = frozenset("Bank University Institute Department Ministry Council Republic Kingdom Federal United State States Court House Church Ministry Office Bureau Board".split())


def _split_of(run: str, start: int) -> list[tuple[str, int]]:
    """'Jane Smith of Acme Corp' is a person and an organisation; 'Bank of America' is one organisation."""
    parts = re.split(r"(\s+of\s+)", run)
    if len(parts) >= 3 and run.split()[0] not in ORG_LEADERS:
        out, pos = [], start
        for seg in parts:
            if not re.fullmatch(r"\s+of\s+", seg):
                out.append((seg, pos))
            pos += len(seg)
        return out
    return [(run, start)]


def extract_entities(text: str) -> list[dict[str, Any]]:
    ents: list[dict[str, Any]] = []
    taken: list[tuple[int, int]] = []

    def free(s: int, e: int) -> bool:
        return all(e <= a or s >= b for a, b in taken)

    for typ, rx in PATTERNS:
        for m in rx.finditer(text):
            s, e = m.span()
            if typ == "PHONE" and (len(re.sub(r"\D", "", m.group())) < 9 or re.fullmatch(r"\d{4}-\d{2}-\d{2}", m.group().strip())):
                continue
            if free(s, e):
                taken.append((s, e))
                ents.append({"type": typ, "text": m.group(), "start": s, "end": e})
    runs = [(seg, off) for m in CAP_RUN.finditer(text) for seg, off in _split_of(m.group(), m.start())]
    for run, off in runs:
        s, e = off, off + len(run)
        toks = run.split()
        while toks and toks[0] in NOT_ENTITY:
            s += len(toks[0]) + 1
            toks = toks[1:]
        if not toks or not free(s, e):
            continue
        span = text[s:e].strip()
        s_end = s + len(span)
        if len(toks) == 1:
            tok = toks[0]
            if tok in PLACES:
                typ = "LOCATION"
            elif s == 0 or re.search(r"[.!?]\s+$", text[max(0, s - 3):s]) or len(tok) < 3 or tok in NOT_ENTITY:
                continue  # a lone capitalised sentence-start word is not evidence of a name
            else:
                typ = "ORGANIZATION" if tok.isupper() and len(tok) > 1 else "PROPER_NOUN"
        elif ORG_SUFFIX.search(span):
            typ = "ORGANIZATION"
        elif TITLE.match(toks[0]) or (len(toks) in (2, 3) and not any(t in PLACES for t in toks)):
            typ = "PERSON"
        elif all(t in PLACES for t in toks):
            typ = "LOCATION"
        else:
            typ = "ORGANIZATION" if len(toks) >= 3 else "PROPER_NOUN"
        taken.append((s, s_end))
        ents.append({"type": typ, "text": span, "start": s, "end": s_end})
    return sorted(ents, key=lambda x: x["start"])


def entity_extraction(params: dict[str, Any]) -> dict[str, Any]:
    text = pick_text(params, "text", "content", "document", "passage", "body", limit=MAX_CHARS)
    if not text:
        q = free_text(params)
        m = re.search(r":\s*(.{12,})$", q, re.S)
        text = m.group(1).strip().strip("\"“”'") if m else None
    if not text:
        return soft("no_text", "No text was supplied, so no entities are extracted.", entities=[], entity_count=0)
    ents = extract_entities(text)
    by_type = dict(Counter(e["type"] for e in ents))
    if not ents:
        return ok("No entities were found in the text.", 0.6, entities=[], entity_count=0, by_type={}, method="regular expressions and capitalisation rules (no language model)")
    shown = "; ".join(f"{e['type']}: {e['text']}" for e in ents[:12])
    answer = f"Found {len(ents)} entities. {shown}{'...' if len(ents) > 12 else ''}"
    return ok(answer, 0.75, entities=ents[:200], entity_count=len(ents), by_type=by_type, offsets="character offsets into the supplied text",
              method="regular expressions, a place gazetteer and capitalisation rules (no language model); person and organisation labels are heuristic")


# ---- TEXT_SUMMARIZATION_GENERAL ----------------------------------------------------------------------------------------
def text_summarization(params: dict[str, Any]) -> dict[str, Any]:
    text = pick_text(params, "text", "content", "document", "article", "body", limit=20000)
    if not text:
        q = free_text(params)
        m = re.search(r":\s*(.{80,})$", q, re.S)
        text = m.group(1) if m else (q if len(q.split()) >= 60 else None)
    if not text:
        return soft("no_text", "No source text was supplied, so no summary is given.", summary_sentences=[])
    sents = sentences(text)
    want = None
    try:
        raw_n = first(params, "sentences", "max_sentences", "length", "n")
        want = max(1, min(8, int(raw_n))) if raw_n else None
    except ValueError:
        want = None
    if len(sents) <= 2:
        return ok(text.strip(), 0.6, summary_sentences=sents, source_sentences=len(sents), compression=1.0, method="extractive (text is already short)")
    want = want or (2 if len(sents) <= 6 else 3 if len(sents) <= 15 else 4)
    freq = Counter(stem(w) for w in content_words(text))
    peak = max(freq.values()) if freq else 1
    scored = []
    for i, s in enumerate(sents):
        toks = [stem(w) for w in content_words(s)]
        if len(toks) < 3:
            continue
        sc = sum(freq[t] / peak for t in toks) / math.sqrt(len(toks))
        sc *= 1.3 if i == 0 else 1.1 if i == len(sents) - 1 else 1.0
        scored.append((sc, i, s))
    pick = sorted(sorted(scored, reverse=True)[:want], key=lambda t: t[1])
    summary = " ".join(s for _, _, s in pick)
    comp = round(len(summary) / max(len(text), 1), 2)
    return ok(summary, 0.7, summary_sentences=[s for _, _, s in pick], source_sentences=len(sents), compression=comp,
              method="extractive: top sentences by word-frequency score, original wording kept (no language model, nothing added)")


# ---- LLM_OUTPUT_EVALUATION_GENERAL -------------------------------------------------------------------------------------
REFUSAL = re.compile(r"\b(?:I can(?:'|’)?t (?:help|assist|do that)|I(?:'|’)?m (?:sorry|unable)|I cannot|as an ai(?: language model)?|I do not have (?:access|the ability))\b", re.I)
PLACEHOLDER = re.compile(r"lorem ipsum|\[(?:insert|your|name|placeholder)[^\]]*\]|\bTODO\b|<\s*(?:placeholder|insert)[^>]*>|\{\{[^}]+\}\}", re.I)
HEDGE = re.compile(r"\b(?:I think|I believe|probably|might be|possibly|perhaps|not sure|it seems)\b", re.I)


def _ngrams(toks: list[str], n: int) -> list[tuple[str, ...]]:
    return list(zip(*[toks[i:] for i in range(n)]))


def llm_output_evaluation(params: dict[str, Any]) -> dict[str, Any]:
    out = pick_text(params, "output", "answer", "response", "completion", "model_output", "result", limit=MAX_CHARS)
    task = pick_text(params, "task", "prompt", "question", "instruction", "reference", limit=4000) or ""
    if not out:
        return soft("no_output", "No model output was supplied, so there is nothing to evaluate.", rating=None, score=None, strengths=[], errors=[])
    strengths: list[str] = []
    errors: list[str] = []
    score = 0.5
    toks = words(out)
    n = len(toks)
    if n < 3:
        errors.append("The output is almost empty.")
        score -= 0.3
    cov = None
    tw = {stem(w) for w in content_words(task)}
    if tw:
        ow = {stem(w) for w in content_words(out)}
        cov = len(tw & ow) / len(tw)
        if cov >= 0.5:
            strengths.append(f"Addresses the task: {pct(cov)}% of the task's key terms appear in the output.")
            score += 0.2
        elif cov < 0.2:
            errors.append(f"Little overlap with the task: only {pct(cov)}% of its key terms appear, so the output may be off-topic.")
            score -= 0.25
    if REFUSAL.search(out):
        errors.append("Contains refusal or self-reference language (for example 'I cannot' or 'as an AI').")
        score -= 0.2
    if PLACEHOLDER.search(out):
        errors.append("Contains an unfilled placeholder (lorem ipsum, [insert ...], TODO or {{...}}).")
        score -= 0.25
    if n >= 12:
        g = _ngrams(toks, 4)
        rep = 1 - len(set(g)) / len(g) if g else 0
        if rep > 0.25:
            errors.append(f"Repetitive: {pct(rep)}% of 4-word sequences are repeats.")
            score -= 0.2
        else:
            strengths.append("No repetition loops.")
            score += 0.05
    if n >= 8 and not re.search(r"[.!?)\"'`\]}>:]\s*$", out.strip()) and not out.strip().endswith(("```",)):
        errors.append("Appears truncated: it does not end with sentence-final punctuation.")
        score -= 0.1
    if len(HEDGE.findall(out)) >= 3:
        errors.append("Heavily hedged wording (several 'I think / probably / might' phrases).")
        score -= 0.05
    t = task.lower()
    if re.search(r"\bjson\b", t):
        body = re.sub(r"^```(?:json)?|```$", "", out.strip(), flags=re.M).strip()
        try:
            json.loads(body)
            strengths.append("Valid JSON, as the task asked.")
            score += 0.15
        except ValueError:
            errors.append("The task asked for JSON but the output does not parse as JSON.")
            score -= 0.3
    m = re.search(r"\b(?:in|under|within|at most|no more than|max(?:imum)?(?: of)?)\s+(\d{1,4})\s+words\b", t)
    if m:
        lim = int(m.group(1))
        (strengths if n <= lim * 1.1 else errors).append(f"{n} words against a limit of {lim}." if n > lim * 1.1 else f"Within the {lim}-word limit ({n} words).")
        score += 0.1 if n <= lim * 1.1 else -0.2
    m = re.search(r"\b(\d{1,2})\s+(?:bullet|bullets|bullet points|items|points|steps)\b", t)
    if m:
        want = int(m.group(1))
        got = len(re.findall(r"^\s*(?:[-*•]|\d+[.)])\s+", out, re.M))
        (strengths if got == want else errors).append(f"Asked for {want} items, found {got}." if got != want else f"Exactly {want} list items, as asked.")
        score += 0.1 if got == want else -0.15
    if n >= 20 and not errors:
        strengths.append("Well-formed text with no structural problems detected.")
    score = round(max(0.0, min(1.0, score)), 2)
    rating = "excellent" if score >= 0.8 else "good" if score >= 0.6 else "fair" if score >= 0.4 else "poor"
    answer = (f"Rating: {rating} (score {score:.2f}). " + (" ".join(errors[:3]) if errors else "No structural problems found.")
              + " Structural checks only: factual accuracy and hallucination cannot be verified without a reference.")
    return ok(answer, 0.6, rating=rating, score=score, strengths=strengths, errors=errors, task_coverage=None if cov is None else round(cov, 2),
              word_count=n, method="deterministic checks: task-term coverage, repetition, truncation, placeholders, refusal language, JSON/length/list constraints")


# ---- AI_TEXT_DETECTION_GENERAL -----------------------------------------------------------------------------------------
AI_PHRASES = ["as an ai", "language model", "delve", "tapestry", "it is important to note", "it's important to note", "in conclusion", "furthermore", "moreover", "in today's",
              "rapidly evolving", "landscape", "navigate the", "multifaceted", "underscores", "testament to", "plays a crucial role", "a myriad of", "holistic", "leverage",
              "seamlessly", "foster", "comprehensive", "ever-evolving", "realm of", "embark", "unlock the", "in summary", "overall,", "ultimately,"]


def ai_text_detection(params: dict[str, Any]) -> dict[str, Any]:
    text = pick_text(params, "text", "content", "passage", "paragraph", "document", limit=MAX_CHARS)
    if not text:
        q = free_text(params)
        m = re.search(r"[\"“'](.{80,})[\"”']", q, re.S) or re.search(r":\s*(.{80,})$", q, re.S)
        text = m.group(1) if m else None
    if not text:
        return soft("no_text", "No text was supplied; authorship cannot be assessed without the text itself.", verdict=None, ai_likelihood=None, cues=[])
    toks = words(text)
    if len(toks) < 40:
        return soft("text_too_short", "The text is under 40 words, too short for any reliable authorship signal, so no verdict is given.", verdict=None, ai_likelihood=None, cues=[], word_count=len(toks))
    sents = sentences(text)
    lens = [len(words(s)) for s in sents if words(s)]
    mean = sum(lens) / len(lens)
    sd = math.sqrt(sum((x - mean) ** 2 for x in lens) / len(lens)) if len(lens) > 1 else 0.0
    cv = sd / mean if mean else 0.0
    ttr = len(set(toks)) / len(toks)
    low = text.lower()
    hits = [p for p in AI_PHRASES if p in low]
    contractions = len(re.findall(r"\b\w+['’](?:s|t|re|ve|ll|d|m)\b", text))
    first_person = len(re.findall(r"\b(?:i|my|me|we|our)\b", low))
    exclaim_or_slang = len(re.findall(r"!|\b(?:lol|tbh|gonna|kinda|wanna|ya|yeah|haha|omg)\b", low))
    cues: list[dict[str, Any]] = []
    s = 0.5
    if len(lens) >= 4:
        if cv < 0.3:
            s += 0.15; cues.append({"cue": "uniform sentence length", "direction": "ai", "value": round(cv, 2)})
        elif cv > 0.6:
            s -= 0.15; cues.append({"cue": "bursty sentence length", "direction": "human", "value": round(cv, 2)})
    if hits:
        s += min(0.3, 0.08 * len(hits)); cues.append({"cue": "stock phrases", "direction": "ai", "value": hits[:6]})
    if contractions == 0 and len(toks) > 80:
        s += 0.08; cues.append({"cue": "no contractions", "direction": "ai", "value": 0})
    elif contractions >= 3:
        s -= 0.1; cues.append({"cue": "contractions", "direction": "human", "value": contractions})
    if first_person >= 3:
        s -= 0.08; cues.append({"cue": "first-person voice", "direction": "human", "value": first_person})
    if exclaim_or_slang:
        s -= 0.1; cues.append({"cue": "exclamations or informal words", "direction": "human", "value": exclaim_or_slang})
    if ttr > 0.8 and len(toks) < 150:
        s -= 0.03
    if re.search(r"^\s*(?:[-*•]|\d+[.)])\s", text, re.M) and re.search(r"\*\*[^*]+\*\*", text):
        s += 0.1; cues.append({"cue": "bold-headed bullet structure", "direction": "ai", "value": True})
    s = round(max(0.05, min(0.95, s)), 2)
    verdict = "likely_ai" if s >= 0.65 else "likely_human" if s <= 0.35 else "uncertain"
    conf = round(min(0.6, 0.35 + abs(s - 0.5) * 0.6), 2)
    answer = (f"Verdict: {verdict.replace('_', ' ')} (AI likelihood {s:.2f}). "
              + ("Cues: " + "; ".join(f"{c['cue']} ({c['direction']})" for c in cues[:4]) + ". " if cues else "No strong cues either way. ")
              + "This is a stylometric heuristic; no detector is reliable enough to be proof of authorship.")
    return ok(answer, conf, verdict=verdict, ai_likelihood=s, cues=cues, word_count=len(toks), method="stylometric heuristics (sentence-length variation, stock phrases, contractions, voice); not a trained detector")


def run(handler, params: dict[str, Any], **ensure: Any) -> dict[str, Any]:
    out = handler(params)
    for k, v in ensure.items():
        out.setdefault(k, v)
    return out
