"""REGULATORY_FILING_MONITOR_GENERAL: SEC EDGAR filings for an issuer (company name, ticker or CIK), from EDGAR's own submissions index."""
from __future__ import annotations

import re
import time
from datetime import date, timedelta
from typing import Any

from app.intents.common import first, free_text, ok, soft
from app.intents.sanctions import norm
from app.sources.base import Fetcher, SourceError

TICKERS = "https://www.sec.gov/files/company_tickers.json"
SUBMISSIONS = "https://data.sec.gov/submissions/CIK{cik:010d}.json"
# SEC rejects generic or browser-like agents; a descriptive product token is required and no personal contact is sent.
HEADERS = {"User-Agent": "VulnRank/0.1 (miner; contact via repository)", "Accept": "application/json"}
FORMS = ["10-K", "10-Q", "8-K", "20-F", "40-F", "6-K", "S-1", "S-3", "424B5", "DEF 14A", "13F-HR", "13D", "13G", "SC 13D", "SC 13G", "3", "4", "5", "11-K", "10-K/A", "10-Q/A", "8-K/A"]
ITEMS = {
    "1.01": "entry into a material agreement", "1.02": "termination of a material agreement", "1.03": "bankruptcy or receivership",
    "2.01": "completion of an acquisition or disposition", "2.02": "results of operations and financial condition", "2.03": "creation of a direct financial obligation",
    "2.05": "exit or disposal costs", "2.06": "material impairments", "3.01": "delisting notice", "3.02": "unregistered sales of equity",
    "4.01": "change of certifying accountant", "4.02": "non-reliance on previously issued financials", "5.01": "change in control",
    "5.02": "departure or appointment of directors or officers", "5.03": "amendments to articles or bylaws", "5.07": "shareholder vote results",
    "7.01": "Regulation FD disclosure", "8.01": "other events", "9.01": "financial statements and exhibits",
}
_cache: dict[str, Any] = {"at": 0.0, "rows": []}


async def _tickers(f: Fetcher, timeout: float, deadline: float | None) -> list[dict[str, Any]]:
    if _cache["rows"] and time.time() - _cache["at"] < 24 * 3600:
        return _cache["rows"]
    _, js = await f.get_json(TICKERS, headers=HEADERS, timeout=max(timeout, 15.0), deadline=deadline)
    rows = list((js or {}).values())
    if rows:
        _cache.update(at=time.time(), rows=rows)
    return rows


def resolve(rows: list[dict[str, Any]], entity: str) -> tuple[dict[str, Any] | None, str]:
    e = entity.strip()
    if e.isdigit():
        hit = next((r for r in rows if int(r["cik_str"]) == int(e)), None)
        return (hit or {"cik_str": int(e), "ticker": None, "title": None}), "cik"
    up = e.upper()
    hit = next((r for r in rows if r["ticker"].upper() == up), None)
    if hit:
        return hit, "ticker"
    qn = norm(e)
    if not qn:
        return None, "none"
    exact = [r for r in rows if norm(r["title"]) == qn]
    if exact:
        return exact[0], "exact name"
    suffix = {"inc", "corp", "corporation", "co", "company", "ltd", "plc", "holdings", "group", "the", "llc", "sa", "nv", "ag"}
    core = [t for t in qn if t not in suffix] or qn
    cands = [r for r in rows if [t for t in norm(r["title"]) if t not in suffix] == core]
    if not cands:
        cands = [r for r in rows if core == [t for t in norm(r["title"]) if t not in suffix][: len(core)]]
    return (cands[0], "name") if cands else (None, "none")  # the tickers file is ordered by market cap, so the first is the largest issuer


def parse_period(text: str | None, today: date) -> tuple[date | None, date | None, str | None]:
    if not text:
        return None, None, None
    t = text.lower()
    m = re.search(r"(\d{4}-\d{2}-\d{2})\s*(?:\.\.|to|-|–|and)\s*(\d{4}-\d{2}-\d{2})", t)
    if m:
        return date.fromisoformat(m.group(1)), date.fromisoformat(m.group(2)), f"{m.group(1)} to {m.group(2)}"
    m = re.search(r"(?:since|after|from)\s+(\d{4}-\d{2}-\d{2})", t)
    if m:
        return date.fromisoformat(m.group(1)), None, f"since {m.group(1)}"
    m = re.search(r"last\s+(\d{1,3})\s+(day|week|month|year)s?", t)
    if m:
        n = int(m.group(1)) * {"day": 1, "week": 7, "month": 30, "year": 365}[m.group(2)]
        return today - timedelta(days=n), None, f"last {m.group(1)} {m.group(2)}s"
    m = re.search(r"\b(?:q([1-4])\s*(20\d{2})|(20\d{2})\s*q([1-4]))\b", t)
    if m:
        q, y = int(m.group(1) or m.group(4)), int(m.group(2) or m.group(3))
        return date(y, 3 * q - 2, 1), (date(y + (q == 4), (3 * q) % 12 + 1, 1) - timedelta(days=1)), f"Q{q} {y}"
    m = re.search(r"\b(20\d{2}|19\d{2})\b", t)
    if m:
        y = int(m.group(1))
        return date(y, 1, 1), date(y, 12, 31), str(y)
    return None, None, None


def parse_form(params: dict[str, Any]) -> str | None:
    raw = first(params, "form", "form_type", "filing_type", "type")
    text = raw or free_text(params)
    if not text:
        return None
    up = text.upper()
    for form in sorted(FORMS, key=len, reverse=True):
        if re.search(rf"(?<![A-Z0-9-]){re.escape(form)}(?![A-Z0-9-])", up):
            return form
    return raw.upper() if raw else None


async def lookup(f: Fetcher, params: dict[str, Any], *, timeout: float, deadline: float | None, today: date | None = None, **_: Any) -> dict[str, Any]:
    today = today or date.today()
    text = free_text(params)
    entity = first(params, "entity", "company", "issuer", "ticker", "cik", "name")
    if not entity and text:
        m = re.search(r"\b(?:has|did|does)\s+(.+?)\s+(?:filed|file|submit|submitted|publish|published)\b", text, re.I) or \
            re.search(r"\b(?:for|by|from|of)\s+([A-Z][\w&.,' -]{1,50}?)(?:\s+(?:in|on|since|for|10|8|20|filed|between)\b|[?.,]|$)", text)
        entity = m.group(1).strip() if m else None
    if not entity:
        return soft("no_entity", "No issuer, ticker or CIK was supplied, so no filings can be listed.", filing_count=None, filings=[])
    form = parse_form(params)
    start, end, plabel = parse_period(first(params, "period", "dates", "date_range", "since") or text, today)
    try:
        rows = await _tickers(f, timeout, deadline)
        co, how = resolve(rows, entity)
        if not co:
            return soft("entity_not_found", f"No SEC registrant matching '{entity}' was found, so no filings are given. EDGAR covers US-listed and SEC-registered issuers only.",
                        entity=entity, filing_count=None, filings=[])
        cik = int(co["cik_str"])
        _, sub = await f.get_json(SUBMISSIONS.format(cik=cik), headers=HEADERS, timeout=max(timeout, 12.0), deadline=deadline)
        rec = sub["filings"]["recent"]
        n = len(rec["accessionNumber"])
    except SourceError as e:
        return soft("unavailable", f"SEC EDGAR was unavailable ({e.kind}); no filing information is given rather than a guess.", entity=entity, filing_count=None, filings=[])
    except (KeyError, TypeError):
        return soft("unavailable", "EDGAR returned an unexpected response; no filing information is given.", entity=entity, filing_count=None, filings=[])
    out = []
    for i in range(n):
        fm, fd = rec["form"][i], rec["filingDate"][i]
        d = date.fromisoformat(fd)
        if form and fm.upper() != form.upper():
            continue
        if (start and d < start) or (end and d > end):
            continue
        acc = rec["accessionNumber"][i]
        doc = rec["primaryDocument"][i]
        items = [x.strip() for x in (rec.get("items") or [""] * n)[i].split(",") if x.strip()]
        out.append({"form": fm, "filing_date": fd, "accepted": (rec.get("acceptanceDateTime") or [""] * n)[i] or None, "report_date": (rec.get("reportDate") or [""] * n)[i] or None,
                    "accession": acc, "url": f"https://www.sec.gov/Archives/edgar/data/{cik}/{acc.replace('-', '')}/{doc}" if doc else None,
                    "description": (rec.get("primaryDocDescription") or [""] * n)[i] or None,
                    "items": [{"item": it, "meaning": ITEMS.get(it)} for it in items] or None})
    out.sort(key=lambda r: r["filing_date"], reverse=True)
    name = sub.get("name") or co.get("title") or entity
    oldest = min(rec["filingDate"]) if n else None
    complete = not (start and oldest and sub["filings"].get("files") and date.fromisoformat(oldest) > start)
    desc = f"{form or 'filings'}{' in ' + plabel if plabel else ''}"
    if out:
        latest = out[0]
        answer = (f"{name} (CIK {cik:010d}) has {len(out)} {desc} on SEC EDGAR; the latest is a {latest['form']} filed {latest['filing_date']}"
                  f"{', accepted ' + latest['accepted'] if latest['accepted'] else ''}"
                  f"{' covering the period ending ' + latest['report_date'] if latest['report_date'] else ''}. {latest['url'] or ''}")
        if latest["items"]:
            answer += " Items reported: " + "; ".join(f"{x['item']} {x['meaning'] or ''}".strip() for x in latest["items"][:5]) + "."
    else:
        answer = f"No {desc} were found for {name} (CIK {cik:010d}) in EDGAR's recent submissions index."
    if not complete:
        answer += " The requested period starts before EDGAR's recent index, so the count may be incomplete."
    answer += " The filing text itself was not read; this reports what was filed and when."
    return ok(answer, 0.9 if complete else 0.6, entity=name, cik=f"{cik:010d}", ticker=co.get("ticker"), matched_by=how, form=form, period=plabel,
              filing_count=len(out), count_complete=complete, filings=out[:10], latest_filing=out[0] if out else None, urls=[r["url"] for r in out[:10] if r["url"]],
              source="SEC EDGAR")
