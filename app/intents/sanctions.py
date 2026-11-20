"""SANCTIONS_SCREENING_MATCH_GENERAL: fuzzy screening against the OFAC SDN and UN Security Council consolidated lists.

The lists are public government downloads, indexed in memory and refreshed every 12 hours. Only these two lists are
checked (the EU and UK lists need credentials or are not publicly downloadable); every answer says so. A screening hit is
a lead for a human reviewer, never a legal determination, and a missing list is reported as unchecked, never as clear."""
from __future__ import annotations

import asyncio
import csv
import difflib
import io
import re
import time
import unicodedata
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any

from app.clock import utc_iso
from app.intents.common import first, free_text, ok, soft
from app.sources.base import Fetcher, SourceError

OFAC_SDN = "https://www.treasury.gov/ofac/downloads/sdn.csv"
OFAC_ALT = "https://www.treasury.gov/ofac/downloads/alt.csv"
UN_LIST = "https://scsanctions.un.org/resources/xml/en/consolidated.xml"
REFRESH_SEC = 12 * 3600
RETRY_SEC = 120
POTENTIAL, STRONG = 0.85, 0.97
_REMARK_WALLET = re.compile(r"Digital Currency Address - ([A-Z0-9]{2,6})\s+([A-Za-z0-9]{20,})")
_YEAR = re.compile(r"\b(19\d{2}|20[0-2]\d)\b")


def norm(s: str) -> list[str]:
    s = unicodedata.normalize("NFKD", s)
    s = "".join(c for c in s if not unicodedata.combining(c)).lower()
    return [t for t in re.sub(r"[^a-z0-9]+", " ", s).split() if t]


@dataclass
class Entry:
    list_name: str
    ref: str
    name: str
    kind: str
    program: str = ""
    aliases: list[str] = field(default_factory=list)
    years: set[str] = field(default_factory=set)
    countries: set[str] = field(default_factory=set)
    wallets: dict[str, str] = field(default_factory=dict)


def _programs(p: str) -> str:
    p = p.strip()
    return "" if p in ("", "-0-") else ", ".join(x.strip("[] ") for x in p.split("] [") if x.strip("[] "))


def parse_ofac(sdn_csv: str, alt_csv: str | None) -> list[Entry]:
    out: dict[str, Entry] = {}
    for row in csv.reader(io.StringIO(sdn_csv)):
        if len(row) < 12:
            continue
        ref, name, typ, prog, remarks = row[0].strip(), row[1].strip(), row[2].strip(), row[3].strip(), row[11]
        if not ref.isdigit():
            continue
        e = Entry("OFAC SDN", ref, name, "entity" if typ in ("-0-", "") else typ.lower(), _programs(prog))
        e.years = set(_YEAR.findall(remarks.split("Digital Currency")[0])) if "DOB" in remarks else set()
        e.countries = {m.strip().lower() for m in re.findall(r"nationality ([A-Za-z ,]+?)(?:;|$)", remarks)}
        for cur, addr in _REMARK_WALLET.findall(remarks):
            e.wallets[addr.lower() if addr.startswith("0x") else addr] = cur
        out[ref] = e
    for row in csv.reader(io.StringIO(alt_csv or "")):
        if len(row) >= 4 and row[0].strip() in out and row[3].strip() not in ("", "-0-"):
            out[row[0].strip()].aliases.append(row[3].strip())
    return list(out.values())


def parse_un(xml_text: str) -> list[Entry]:
    root = ET.fromstring(xml_text)
    out: list[Entry] = []
    for kind, tag, alias_tag in (("individual", "INDIVIDUAL", "INDIVIDUAL_ALIAS"), ("entity", "ENTITY", "ENTITY_ALIAS")):
        for el in root.iter(tag):
            parts = [(el.findtext(k) or "").strip() for k in ("FIRST_NAME", "SECOND_NAME", "THIRD_NAME", "FOURTH_NAME")]
            name = " ".join(p for p in parts if p)
            if not name:
                continue
            e = Entry("UN Security Council", (el.findtext("REFERENCE_NUMBER") or el.findtext("DATAID") or "").strip(), name, kind,
                      (el.findtext("UN_LIST_TYPE") or "").strip())
            e.aliases = [(a.findtext("ALIAS_NAME") or "").strip() for a in el.findall(alias_tag) if (a.findtext("ALIAS_NAME") or "").strip()]
            for d in el.iter("INDIVIDUAL_DATE_OF_BIRTH"):
                e.years.update(_YEAR.findall(" ".join((x.text or "") for x in d.iter())))
            e.countries = {(n.text or "").strip().lower() for n in el.iter("VALUE") if (n.text or "").strip()}
            out.append(e)
    return out


class SanctionsIndex:
    def __init__(self, fetcher: Fetcher, timeout: float = 40.0):
        self.f, self.timeout = fetcher, timeout
        self.entries: list[Entry] = []
        self.tokens: dict[str, list[int]] = defaultdict(list)
        self.names: list[tuple[int, str, list[str]]] = []  # (entry idx, variant, sorted tokens)
        self.wallets: dict[str, int] = {}
        self.status: dict[str, dict[str, Any]] = {}
        self.loaded_at = 0.0
        self._task: asyncio.Future | None = None

    @property
    def fresh(self) -> bool:
        return bool(self.entries) and time.time() - self.loaded_at < REFRESH_SEC

    async def _load_ofac(self) -> list[Entry]:
        _, sdn = await self.f.get_text(OFAC_SDN, timeout=self.timeout)
        try:
            _, alt = await self.f.get_text(OFAC_ALT, timeout=self.timeout)
        except SourceError:
            alt = None  # aliases are an enrichment; the primary names still screen
        return parse_ofac(sdn or "", alt)

    async def _load_un(self) -> list[Entry]:
        _, xml = await self.f.get_text(UN_LIST, timeout=self.timeout)
        return parse_un(xml or "")

    async def _refresh(self) -> bool:
        results = await asyncio.gather(self._load_ofac(), self._load_un(), return_exceptions=True)
        entries: list[Entry] = []
        for name, res in zip(("OFAC SDN", "UN Security Council"), results):
            if isinstance(res, Exception):
                old = [e for e in self.entries if e.list_name == name]
                entries += old  # last-known-good
                self.status[name] = {"list": name, "status": "stale" if old else "unavailable", "entries": len(old),
                                     "note": f"refresh failed ({getattr(res, 'kind', type(res).__name__)})"}
            else:
                entries += res
                self.status[name] = {"list": name, "status": "available", "entries": len(res), "loaded_at": utc_iso()}
        failed = any(s["status"] != "available" for s in self.status.values())
        if entries:
            self._build(entries)
        self.loaded_at = time.time() - (REFRESH_SEC - RETRY_SEC if failed else 0)  # retry a failed list after RETRY_SEC, not 12 h
        return bool(entries)

    async def ensure(self, deadline: float | None = None) -> bool:
        """True when at least one list is loaded. The download runs in the background so a slow first load (tens of MB) never
        blocks past the request deadline; stale data is kept if a refresh fails."""
        if self.fresh:
            return True
        if self._task is None or self._task.done():
            self._task = asyncio.ensure_future(self._refresh())
        remaining = None if deadline is None else max(0.1, deadline - time.monotonic())
        done, _ = await asyncio.wait({self._task}, timeout=remaining)
        if done and not self._task.exception():
            return bool(self.entries)
        return bool(self.entries)  # still loading: serve last-known-good if there is any

    def _build(self, entries: list[Entry]) -> None:
        self.entries, self.tokens, self.names, self.wallets = entries, defaultdict(list), [], {}
        for i, e in enumerate(entries):
            for variant in {e.name, *e.aliases}:
                toks = norm(variant)
                if not toks:
                    continue
                self.names.append((i, variant, sorted(toks)))
                for t in set(toks):
                    self.tokens[t].append(len(self.names) - 1)
            for w in e.wallets:
                self.wallets[w.lower()] = i

    def search_wallet(self, addr: str) -> list[dict[str, Any]]:
        i = self.wallets.get(addr.lower())
        if i is None:
            return []
        e = self.entries[i]
        return [self._hit(e, e.name, 1.0, "exact digital-currency address")]

    @staticmethod
    def _hit(e: Entry, matched: str, score: float, basis: str) -> dict[str, Any]:
        return {"name": e.name, "matched_name": matched, "list": e.list_name, "score": round(score, 3), "basis": basis, "type": e.kind,
                "program": e.program, "reference": e.ref, "birth_years": sorted(e.years)[:5], "countries": sorted(e.countries)[:5]}

    def search(self, query: str, *, year: str | None = None, country: str | None = None, limit: int = 5) -> list[dict[str, Any]]:
        q = sorted(norm(query))
        if not q:
            return []
        hits: Counter[int] = Counter()
        for t in set(q):
            for idx in self.tokens.get(t, ()):
                hits[idx] += 1
        need = 1 if len(q) == 1 else max(1, (len(q) + 1) // 2)
        cands = [i for i, c in hits.most_common(4000) if c >= need]
        qj = " ".join(q)
        best: dict[int, tuple[float, str, str]] = {}
        for ni in cands:
            ei, variant, toks = self.names[ni]
            vj = " ".join(toks)
            if vj == qj:
                score, basis = 1.0, "exact name match"
            else:
                score = difflib.SequenceMatcher(None, qj, vj).ratio()
                basis = "fuzzy name match"
                if len(q) >= 2 and set(q) <= set(toks):
                    score, basis = max(score, 0.9), "all query name parts appear in listed name"
                elif len(toks) >= 2 and set(toks) <= set(q):
                    score, basis = max(score, 0.9), "all listed name parts appear in query"
                elif len(q) == 1 and len(q[0]) >= 5 and len(toks) >= 2 and q[0] in toks and len(self.tokens.get(q[0], ())) <= 150:
                    score, basis = max(score, 0.88), "query is a distinctive part of a listed name"
            e = self.entries[ei]
            if year and e.years:
                score += 0.04 if year in e.years else -0.15
            if country and e.countries and country.lower() in e.countries:
                score += 0.02
            if score >= POTENTIAL and (ei not in best or score > best[ei][0]):
                best[ei] = (min(score, 1.0), variant, basis)
        ranked = sorted(best.items(), key=lambda kv: -kv[1][0])[:limit]
        return [self._hit(self.entries[ei], v, s, b) for ei, (s, v, b) in ranked]


def parse_request(params: dict[str, Any]) -> tuple[str | None, str | None, str | None]:
    """-> (subject, birth year, country). Accepts 'Ivan Petrov, DOB 1974, Cyprus' style strings and plain names."""
    raw = first(params, "name", "entity", "subject", "person", "company", "wallet", "address", "party")
    year, country = first(params, "year_of_birth", "birth_year", "dob", "year"), first(params, "country", "nationality", "jurisdiction")
    if raw is None:
        text = free_text(params)
        m = re.search(r"[\"“'‘]([^\"”'’]{3,}?)[\"”'’]", text)
        raw = m.group(1) if m else (text.split(":", 1)[1].strip() if ":" in text else None)
    if not raw:
        return None, None, None
    parts = [p.strip() for p in raw.split(",") if p.strip()]
    name_parts = []
    for p in parts:
        y = re.fullmatch(r"(?:dob|born|b\.|year)?\s*:?\s*(?:\d{1,2}\s+\w+\s+)?(19\d{2}|20[0-2]\d)", p, re.I)
        if y:
            year = year or y.group(1)
        elif name_parts and not re.search(r"\d", p):
            country = country or p
        else:
            name_parts.append(p)
    name = " ".join(name_parts) or parts[0]
    if year:
        m = _YEAR.search(year)
        year = m.group(1) if m else None
    return name, year, country


async def screen(idx: SanctionsIndex, params: dict[str, Any], *, deadline: float | None = None, **_: Any) -> dict[str, Any]:
    subject, year, country = parse_request(params)
    if not subject:
        return soft("no_subject", "No person, company or wallet was supplied, so nothing was screened. Supply name.", matched=None, matches=[])
    if not await idx.ensure(deadline):
        loading = idx._task is not None and not idx._task.done()
        return soft("loading" if loading else "unavailable",
                    ("The sanctions lists are still being downloaded" if loading else "The sanctions lists could not be downloaded")
                    + ", so the subject was NOT screened; this is not a clear result. Retry shortly." if loading else
                    "The sanctions lists could not be downloaded, so the subject was NOT screened; this is not a clear result.",
                    matched=None, matches=[], lists_checked=list(idx.status.values()))
    lists = list(idx.status.values())
    tokens = re.findall(r"[A-Za-z0-9]{20,}", subject)
    if tokens:  # a digital-currency address: exact lookup only, never a fuzzy name search
        matches = [m for t in tokens for m in idx.search_wallet(t)]
        subject_kind = "wallet"
    else:
        matches, subject_kind = idx.search(subject, year=year, country=country), "name"
    partial = any(s["status"] != "available" for s in lists)
    cover = "OFAC SDN and UN Security Council consolidated lists" if not partial else "the available sanctions lists (one list could not be refreshed)"
    caveat = " The EU and UK lists were not checked. A hit is a lead for human review, not a legal determination."
    ctx = {"subject": subject, "subject_type": subject_kind, "birth_year": year, "country": country, "lists_checked": lists}
    if not matches:
        return ok(f"No match for '{subject}' was found in {cover}.{caveat}", 0.6 if partial else 0.85, matched=False, match_count=0, matches=[],
                  verdict="no_match", highest_score=0.0, **ctx)
    top = matches[0]
    strong = top["score"] >= STRONG
    verdict = "match" if strong else "potential_match"
    desc = "; ".join(f"{m['matched_name']} ({m['list']}, {m['type']}, {m['program'] or 'program n/a'}, score {m['score']:.2f})" for m in matches[:3])
    head = "Strong match" if strong else "Potential near-match"
    return ok(f"{head} for '{subject}' in {cover}: {desc}.{caveat}", 0.9 if strong else 0.65, matched=True, match_count=len(matches),
              matches=matches, verdict=verdict, highest_score=top["score"], **ctx)
