"""CONTRACT_OBLIGATION_AUDIT_GENERAL: deterministic extraction of obligations, deadlines and payment terms from contract text.

Rule-based (no language model). It reports what the text says: it cannot know whether an obligation was actually performed, so a
passed date is reported as `past_due_date` with 'no completion evidence in the text', never as a proven breach."""
from __future__ import annotations

import re
from datetime import date, timedelta
from typing import Any

from app.intents.common import first, free_text, ok, soft

MAX_CHARS = 20000
MONTHS = {m: i for i, m in enumerate("january february march april may june july august september october november december".split(), 1)}
MONTHS |= {k[:3]: v for k, v in list(MONTHS.items())} | {"sept": 9}
_DATE_PATTERNS = [
    (re.compile(r"\b(\d{4})-(\d{2})-(\d{2})\b"), lambda m: (int(m[1]), int(m[2]), int(m[3]))),
    (re.compile(r"\b(" + "|".join(MONTHS) + r")\.?\s+(\d{1,2})(?:st|nd|rd|th)?,?\s+(\d{4})\b", re.I), lambda m: (int(m[3]), MONTHS[m[1].lower()], int(m[2]))),
    (re.compile(r"\b(\d{1,2})(?:st|nd|rd|th)?\s+(?:day of\s+)?(" + "|".join(MONTHS) + r")\.?,?\s+(\d{4})\b", re.I), lambda m: (int(m[3]), MONTHS[m[2].lower()], int(m[1]))),
]
_MODAL = re.compile(r"\b(shall not|must not|may not|shall|must|will|agrees? to|is required to|are required to|undertakes? to|is obligated to|are obligated to|is responsible for|responsible for|(?:is|are|shall be) payable|(?:is|are) due)\b", re.I)
_WITHIN = re.compile(r"\bwithin\s+(\w+)\s*(?:\((\d+)\)\s*)?(business\s+|working\s+|calendar\s+)?(day|week|month|year)s?\s+(?:of|after|from|following)\s+([^.;,]{3,60})", re.I)
_NET = re.compile(r"\bnet\s*(\d{1,3})\b", re.I)
_AMOUNT = re.compile(r"(?:[$€£₹]\s?\d[\d,]*(?:\.\d+)?(?:\s?(?:million|billion|k|m))?|\b(?:USD|EUR|GBP|INR)\s?\d[\d,]*(?:\.\d+)?|\b\d[\d,]*(?:\.\d+)?\s?(?:USD|EUR|GBP|INR)\b)", re.I)
_DONE = re.compile(r"\b(was|were|has been|have been|had been)\s+(delivered|paid|completed|submitted|performed|provided|received)|\b(?:paid|delivered|completed|submitted) (?:on|in full)\b", re.I)
_WORDNUM = {w: i for i, w in enumerate("zero one two three four five six seven eight nine ten eleven twelve fifteen thirty sixty ninety".split())}
_WORDNUM |= {"fifteen": 15, "thirty": 30, "sixty": 60, "ninety": 90, "twenty": 20, "forty-five": 45, "forty": 40}
TYPES = [
    ("payment", re.compile(r"\b(pay|payment|invoice|fee|fees|remit|reimburse|compensat|royalt|deposit)\w*", re.I)),
    ("deliverable", re.compile(r"\b(deliver|provid|submit|supply|install|complet|perform|develop|implement|ship|furnish|render)\w*", re.I)),
    ("milestone", re.compile(r"\bmilestone|\bacceptance\b", re.I)),
    ("confidentiality", re.compile(r"\bconfidential|non-disclosure|proprietary\b", re.I)),
    ("notice_termination", re.compile(r"\b(notice|terminat|renew|cure)\w*", re.I)),
    ("warranty_liability", re.compile(r"\b(warrant|indemnif|liabilit|insur)\w*", re.I)),
]


def find_dates(text: str) -> list[date]:
    out = []
    for rx, conv in _DATE_PATTERNS:
        for m in rx.finditer(text):
            try:
                out.append(date(*conv(m)))
            except ValueError:
                pass
    return out


def _num(tok: str, digits: str | None) -> int | None:
    if digits:
        return int(digits)
    return int(tok) if tok.isdigit() else _WORDNUM.get(tok.lower())


def split_clauses(text: str) -> list[tuple[str | None, str]]:
    """-> [(clause number or None, sentence)]; tracks '4.2' / 'Section 4' style numbering."""
    out, number = [], None
    for line in re.split(r"\n+", text):
        line = line.strip()
        if not line:
            continue
        m = re.match(r"^(?:section\s+|clause\s+|article\s+)?(\d+(?:\.\d+)*)[.)]?\s+", line, re.I)
        if m:
            number = m.group(1)
        for sent in re.split(r"(?<=[.;])\s+(?=[A-Z(\"“])", line):
            if sent.strip():
                out.append((number, sent.strip()))
    return out


def audit(text: str, as_of: date) -> dict[str, Any]:
    obligations: list[dict[str, Any]] = []
    for number, sent in split_clauses(text):
        m = _MODAL.search(sent)
        if not m:
            continue
        cue = m.group(1).lower()
        prohibition = cue.endswith("not")
        subject = re.sub(r"^[\d.()a-z]{0,6}\s*", "", sent[: m.start()]).strip(" ,:;")
        subject = subject[-60:] if len(subject) > 60 else subject
        kind = "restriction" if prohibition else next((t for t, rx in TYPES if rx.search(sent)), "performance")
        due, due_basis = None, None
        dates = find_dates(sent)
        wm = _WITHIN.search(sent)
        if wm:
            n = _num(wm.group(1), wm.group(2))
            unit = wm.group(4).lower()
            due_basis = f"within {n} {(wm.group(3) or '').strip()} {unit}s of {wm.group(5).strip()}".replace("  ", " ")
            anchor = find_dates(wm.group(5))
            if n is not None and anchor:
                due = anchor[0] + timedelta(days={"day": 1, "week": 7, "month": 30, "year": 365}[unit] * n)
        net = _NET.search(sent)
        if net and not due_basis:
            due_basis = f"net {net.group(1)} days from invoice"
        if dates and due is None:
            due = max(dates) if re.search(r"\b(by|before|no later than|on or before|until|due)\b", sent, re.I) else dates[0]
            due_basis = due_basis or "explicit date in the clause"
        done = bool(_DONE.search(sent))
        if done:
            status = "completed_per_text"
        elif due and due < as_of:
            status = "past_due_date"
        elif due:
            status = "upcoming"
        else:
            status = "undated"
        amt = _AMOUNT.findall(sent)
        obligations.append({"clause": number, "type": kind, "party": subject or None, "obligation": sent[:300], "due_date": due.isoformat() if due else None,
                            "due_basis": due_basis, "amount": amt[0].strip() if amt else None, "status": status,
                            "days_remaining": (due - as_of).days if due and status == "upcoming" else None,
                            "days_past_due_date": (as_of - due).days if due and status == "past_due_date" else None})
    return {"obligations": obligations}


def run(params: dict[str, Any], today: date | None = None) -> dict[str, Any]:
    text = first(params, "contract", "text", "document", "contract_text", "agreement") or ""
    if not text:
        text = free_text(params)
        if ":" in text and len(text) > 60:
            text = text.split(":", 1)[1]
    if len(text.strip()) < 20:
        return soft("no_contract", "No contract text was supplied, so no obligations can be extracted. Supply the contract text.", verdict=None, obligations=[])
    as_of = today or date.today()
    if first(params, "as_of", "today", "date"):
        found = find_dates(first(params, "as_of", "today", "date") or "")
        as_of = found[0] if found else as_of
    truncated = len(text) > MAX_CHARS
    res = audit(text[:MAX_CHARS], as_of)
    ob = res["obligations"]
    if not ob:
        return ok("No obligations were identified: no clause uses obligation language (shall, must, will, agrees to, is required to).", 0.6,
                  verdict="no_obligations_found", obligations=[], clauses=[], obligation_count=0, as_of_date=as_of.isoformat())
    counts: dict[str, int] = {}
    for o in ob:
        counts[o["status"]] = counts.get(o["status"], 0) + 1
    by_type: dict[str, int] = {}
    for o in ob:
        by_type[o["type"]] = by_type.get(o["type"], 0) + 1
    past = [o for o in ob if o["status"] == "past_due_date"]
    up = sorted((o for o in ob if o["status"] == "upcoming"), key=lambda o: o["due_date"])
    verdict = "past_due_dates_found" if past else "obligations_found"
    answer = (f"Found {len(ob)} obligation(s) ({', '.join(f'{n} {t}' for t, n in sorted(by_type.items(), key=lambda kv: -kv[1]))}); as of {as_of.isoformat()}: "
              f"{counts.get('past_due_date', 0)} with a date already passed, {counts.get('upcoming', 0)} upcoming, {counts.get('undated', 0)} undated, "
              f"{counts.get('completed_per_text', 0)} stated as completed.")
    if past:
        answer += " Past-due dates: " + "; ".join(f"{(o['party'] or 'party')} - {o['type']} due {o['due_date']} ({o['days_past_due_date']} days ago)" for o in past[:3]) + \
                  ". The text gives no evidence these were completed; the contract text cannot show whether they were."
    if up:
        answer += f" Next due: {up[0]['type']} on {up[0]['due_date']} ({up[0]['days_remaining']} days)."
    answer += " Extracted by rules from the text supplied; not legal advice."
    if truncated:
        answer += f" Only the first {MAX_CHARS} characters were analysed."
    return ok(answer, 0.75, verdict=verdict, obligation_count=len(ob), obligations=ob[:50], clauses=sorted({o["clause"] for o in ob if o["clause"]}),
              counts_by_status=counts, counts_by_type=by_type, as_of_date=as_of.isoformat(), summary_note="rule-based extraction; no language model")
