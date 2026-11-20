"""CORPORATE_REGISTRY_LOOKUP_GENERAL: legal-entity record from GLEIF (global Legal Entity Identifier register, keyless).

GLEIF holds the legal name, registration number, status, legal address, jurisdiction and incorporation date of entities
that have an LEI. It does NOT hold directors or beneficial owners, so those are reported as not available, never guessed.
An entity without an LEI is reported as not found in GLEIF (which is not proof that it does not exist)."""
from __future__ import annotations

import re
from typing import Any

from app.intents.common import first, free_text, ok, soft
from app.intents.sanctions import norm
from app.sources.base import Fetcher, SourceError

API = "https://api.gleif.org/api/v1"
COUNTRIES = {
    "united states": "US", "usa": "US", "us": "US", "america": "US", "united kingdom": "GB", "uk": "GB", "great britain": "GB", "england": "GB",
    "germany": "DE", "france": "FR", "india": "IN", "canada": "CA", "australia": "AU", "ireland": "IE", "netherlands": "NL", "spain": "ES",
    "italy": "IT", "switzerland": "CH", "sweden": "SE", "norway": "NO", "denmark": "DK", "finland": "FI", "japan": "JP", "china": "CN",
    "singapore": "SG", "hong kong": "HK", "brazil": "BR", "mexico": "MX", "south africa": "ZA", "uae": "AE", "united arab emirates": "AE",
    "luxembourg": "LU", "belgium": "BE", "austria": "AT", "poland": "PL", "portugal": "PT", "south korea": "KR", "cayman islands": "KY",
}
_LEI = re.compile(r"\b[0-9A-Z]{18}[0-9]{2}\b")
_NOISE = re.compile(r"\b(?:what|is|the|official|register|record|incorporation|status|registered|agent|address|for|of|company|number|find|lookup|look up|"
                    r"tell|me|about|details|information|legal|entity|and|uk|us)\b", re.I)


def country_code(v: str | None) -> str | None:
    if not v:
        return None
    v = v.strip()
    if re.fullmatch(r"[A-Za-z]{2}(-[A-Za-z0-9]{1,3})?", v):
        return v[:2].upper()
    return COUNTRIES.get(v.lower())


def _addr(a: dict[str, Any] | None) -> str | None:
    if not a:
        return None
    parts = [*(a.get("addressLines") or []), a.get("city"), a.get("region"), a.get("postalCode"), a.get("country")]
    return ", ".join(str(p) for p in parts if p) or None


def view(rec: dict[str, Any]) -> dict[str, Any]:
    at, ent, reg = rec["attributes"], rec["attributes"]["entity"], rec["attributes"].get("registration") or {}
    status = ent.get("status")
    return {
        "legal_name": (ent.get("legalName") or {}).get("name"), "lei": at.get("lei") or rec.get("id"),
        "registration_id": ent.get("registeredAs") or at.get("lei"), "active": status == "ACTIVE" if status else None,
        "status": status, "jurisdiction": ent.get("jurisdiction"), "registered_address": _addr(ent.get("legalAddress")),
        "headquarters_address": _addr(ent.get("headquartersAddress")), "incorporated": (ent.get("creationDate") or "")[:10] or None,
        "registration_authority": (ent.get("registeredAt") or {}).get("id"), "legal_form": ((ent.get("legalForm") or {}).get("id")),
        "category": ent.get("category"), "lei_status": reg.get("status"), "lei_next_renewal": (reg.get("nextRenewalDate") or "")[:10] or None,
        "lei_last_updated": (reg.get("lastUpdateDate") or "")[:10] or None,
    }


async def _records(f: Fetcher, params: dict[str, Any], timeout: float, deadline: float | None) -> list[dict[str, Any]]:
    _, js = await f.get_json(f"{API}/lei-records", params, timeout=timeout, deadline=deadline)
    return (js or {}).get("data") or []


async def find(f: Fetcher, name: str | None, *, lei: str | None, reg_id: str | None, cc: str | None, timeout: float,
               deadline: float | None) -> tuple[list[dict[str, Any]], str]:
    """-> (records, how). Exact LEI / registration number first, then exact legal name, then fuzzy name completions."""
    page = {"page[size]": 15}
    geo = {"filter[entity.legalAddress.country]": cc} if cc else {}
    if lei:
        return await _records(f, {"filter[lei]": lei}, timeout, deadline), "lei"
    if reg_id:
        recs = await _records(f, {"filter[entity.registeredAs]": reg_id, **geo, **page}, timeout, deadline)
        if recs:
            return recs, "registration number"
    if not name:
        return [], "none"
    recs = await _records(f, {"filter[entity.legalName]": name, **geo, **page}, timeout, deadline)
    if recs:
        return recs, "exact legal name"
    _, js = await f.get_json(f"{API}/fuzzycompletions", {"field": "entity.legalName", "q": name}, timeout=timeout, deadline=deadline)
    leis = [((d.get("relationships") or {}).get("lei-records") or {}).get("data", {}).get("id") for d in (js or {}).get("data", [])[:8]]
    leis = [x for x in leis if x]
    if not leis:
        return [], "fuzzy"
    return await _records(f, {"filter[lei]": ",".join(leis), **geo, **page}, timeout, deadline), "fuzzy legal name"


def pick(recs: list[dict[str, Any]], name: str | None, cc: str | None) -> tuple[dict[str, Any], list[dict[str, Any]], float]:
    """Choose the best record; return (best, other candidates, confidence)."""
    qn = norm(name or "")

    def key(r):
        v = view(r)
        nm = norm(v["legal_name"] or "")
        exact = nm == qn
        sim = len(set(nm) & set(qn)) / max(len(set(nm) | set(qn)), 1)
        return (exact, v["active"] is True, sim, v["lei_status"] == "ISSUED")
    ranked = sorted(recs, key=key, reverse=True)
    best = ranked[0]
    top = key(best)
    rivals = [r for r in ranked[1:] if key(r)[:2] == top[:2] and key(r)[2] >= top[2] - 0.01]
    conf = 0.9 if top[0] and not rivals else 0.7 if top[0] else 0.5
    if rivals and not cc:
        conf = min(conf, 0.6)
    return best, ranked[1:6], conf


async def lookup(f: Fetcher, params: dict[str, Any], *, timeout: float, deadline: float | None, **_: Any) -> dict[str, Any]:
    name = first(params, "company", "entity", "name", "legal_name", "organization", "organisation")
    lei = first(params, "lei")
    reg_id = first(params, "registration_id", "company_number", "registration_number", "number")
    cc = country_code(first(params, "jurisdiction", "country", "country_code"))
    text = free_text(params)
    if text and not (name or lei or reg_id):
        m = _LEI.search(text)
        lei = m.group(0) if m else None
        quoted = re.search(r"[\"“']([^\"”']{3,})[\"”']", text)
        name = quoted.group(1) if quoted else (_NOISE.sub(" ", text).strip(" ?.!:,") or None)
        reg_id = reg_id or (re.search(r"\b(?:number|no\.?)\s*([A-Z0-9]{5,})\b", text, re.I) or [None, None])[1]
        cc = cc or next((c for k, c in COUNTRIES.items() if re.search(rf"\b{re.escape(k)}\b", text.lower())), None)
    if name and not lei and _LEI.fullmatch(name.strip().upper()):
        lei, name = name.strip().upper(), None
    if not (name or lei or reg_id):
        return soft("no_company", "No company name, registration number or LEI was supplied, so no register record can be given.",
                    legal_name=None, registration_id=None)
    try:
        recs, how = await find(f, name, lei=lei, reg_id=reg_id, cc=cc, timeout=timeout, deadline=deadline)
    except SourceError as e:
        return soft("unavailable", f"The legal-entity register (GLEIF) was unavailable ({e.kind}); no record is given rather than a guess.",
                    legal_name=None, registration_id=None)
    if not recs:
        who = name or lei or reg_id
        return soft("not_found", f"No legal entity matching '{who}' was found in GLEIF. GLEIF only lists entities that hold an LEI, so this is not proof "
                    "the company does not exist; a national company register may hold it.", legal_name=None, registration_id=None, searched=how)
    best, others, conf = pick(recs, name, cc)
    v = view(best)
    if name and how.startswith("exact") and norm(v["legal_name"] or "") != norm(name):
        how = "closest legal-name match"  # GLEIF's name filter is a prefix search, not an equality test
        answer_prefix = f"No entity is registered under exactly '{name}'; the closest GLEIF record is: "
    else:
        answer_prefix = ""
    status = "active" if v["active"] else (v["status"] or "unknown").lower()
    answer = (answer_prefix + f"{v['legal_name']} (LEI {v['lei']}) is {status}"
              f"{', registration number ' + v['registration_id'] if v['registration_id'] and v['registration_id'] != v['lei'] else ''}"
              f"{', incorporated ' + v['incorporated'] if v['incorporated'] else ''}. Registered address: {v['registered_address'] or 'not published'}. "
              f"Jurisdiction {v['jurisdiction'] or 'n/a'}. Source: GLEIF ({how}). Directors and beneficial owners are not held by GLEIF.")
    if others and conf < 0.7:
        answer += " Other similarly named entities exist; add jurisdiction to disambiguate."
    return ok(answer, conf, **v, matched_by=how, candidates=[{"legal_name": view(r)["legal_name"], "lei": view(r)["lei"], "jurisdiction": view(r)["jurisdiction"],
                                                               "status": view(r)["status"]} for r in others[:4]],
              not_available=["directors", "beneficial_owners"], source="GLEIF")
