"""VENDOR_VERIFY_GENERAL: combined supplier check from public evidence: EU VAT (VIES), legal-entity register (GLEIF), sanctions lists."""
from __future__ import annotations

import asyncio
import re
from typing import Any

from app.intents import registry, sanctions
from app.intents.common import first, free_text, ok, soft
from app.intents.sanctions import norm
from app.sources.base import Fetcher, SourceError

VIES = "https://ec.europa.eu/taxation_customs/vies/rest-api/ms/{cc}/vat/{num}"
VAT = re.compile(r"\b(AT|BE|BG|CY|CZ|DE|DK|EE|EL|ES|FI|FR|HR|HU|IE|IT|LT|LU|LV|MT|NL|PL|PT|RO|SE|SI|SK|XI)[\s-]?([0-9A-Z]{7,12})\b")
NOT_CHECKED = ["bank account ownership", "quality and security certifications (for example ISO 27001)", "tax identifiers outside the EU VAT system"]


def parse_vat(raw: str | None) -> tuple[str, str] | None:
    m = VAT.search((raw or "").upper().replace(".", ""))
    return (m.group(1), m.group(2)) if m else None


async def _vat(f: Fetcher, cc: str, num: str, timeout: float, deadline: float | None) -> dict[str, Any]:
    status, js = await f.get_json(VIES.format(cc=cc, num=num), timeout=timeout, deadline=deadline)
    if status == 404 or not isinstance(js, dict) or "isValid" not in js:
        raise SourceError("malformed", "VIES returned no verdict")
    err = js.get("userError")
    if err not in ("VALID", "INVALID"):
        raise SourceError("http_error", f"VIES said {err}")
    hide = lambda v: None if v in (None, "", "---") else v  # noqa: E731  (member states may withhold name and address)
    return {"valid": bool(js["isValid"]), "name": hide(js.get("name")), "address": hide(js.get("address"))}


async def verify(f: Fetcher, idx: sanctions.SanctionsIndex, params: dict[str, Any], *, timeout: float, deadline: float | None, **_: Any) -> dict[str, Any]:
    vendor = first(params, "vendor", "supplier", "company", "name", "vendor_name")
    vat_raw = first(params, "vat_number", "vat", "tax_id", "vat_id")
    text = free_text(params)
    if text and not vendor:
        q = re.search(r"[\"“']([^\"”']{2,})[\"”']", text)
        vendor = q.group(1) if q else None
        m = re.search(r"(?:vendor|supplier)\s+([A-Z][\w&.,' -]{1,60}?)(?:\s+before|\s*[:,(]|$)", text)
        vendor = vendor or (m.group(1).strip() if m else None)
    vat = parse_vat(vat_raw) or parse_vat(text)
    if not vendor and not vat:
        return soft("no_vendor", "No vendor name or VAT number was supplied, so nothing was verified.", verdict=None, valid=None)

    async def run_vat():
        return await _vat(f, vat[0], vat[1], timeout, deadline) if vat else None

    async def run_registry():
        if not vendor:
            return None
        recs, how = await registry.find(f, vendor, lei=None, reg_id=None, cc=None, timeout=timeout, deadline=deadline)
        return (registry.view(registry.pick(recs, vendor, None)[0]), how) if recs else ("none", how)

    async def run_sanctions():
        return await sanctions.screen(idx, {"name": vendor}, deadline=deadline) if vendor else None

    vat_r, reg_r, san_r = await asyncio.gather(run_vat(), run_registry(), run_sanctions(), return_exceptions=True)
    checks: list[dict[str, Any]] = []
    flags: list[str] = []
    valid = registered_name = registered_address = None

    if vat:
        if isinstance(vat_r, Exception):
            checks.append({"check": "EU VAT (VIES)", "status": "unavailable", "detail": f"VIES could not be reached ({getattr(vat_r, 'kind', 'error')})."})
        else:
            valid, registered_name, registered_address = vat_r["valid"], vat_r["name"], vat_r["address"]
            if not valid:
                flags.append("VAT number is not valid")
            elif registered_name and vendor and not (set(norm(vendor)) & set(norm(registered_name))):
                flags.append(f"VAT registered name '{registered_name}' does not match '{vendor}'")
            checks.append({"check": "EU VAT (VIES)", "status": "valid" if valid else "invalid",
                           "detail": f"{vat[0]}{vat[1]} is {'registered' if valid else 'NOT registered'}"
                                     + (f" to {registered_name}" if registered_name else " (name withheld by the member state)")})
    if vendor:
        if isinstance(reg_r, Exception):
            checks.append({"check": "Legal-entity register (GLEIF)", "status": "unavailable", "detail": "GLEIF could not be reached."})
        elif reg_r and reg_r[0] == "none":
            checks.append({"check": "Legal-entity register (GLEIF)", "status": "not_found",
                           "detail": "No entity with this name holds an LEI (many legitimate small firms do not)."})
        elif reg_r:
            v = reg_r[0]
            if v["active"] is False:
                flags.append(f"register status of {v['legal_name']} is {v['status']}")
            registered_name = registered_name or v["legal_name"]
            registered_address = registered_address or v["registered_address"]
            checks.append({"check": "Legal-entity register (GLEIF)", "status": "found", "detail": f"{v['legal_name']}, status {v['status']}, LEI {v['lei']}"})
        if isinstance(san_r, Exception) or san_r is None or san_r.get("matched") is None:
            checks.append({"check": "Sanctions (OFAC SDN, UN)", "status": "unavailable", "detail": "Sanctions lists could not be checked; NOT cleared."})
        elif san_r["matched"]:
            flags.append(f"sanctions screening {san_r['verdict'].replace('_', ' ')} (top score {san_r['highest_score']:.2f})")
            checks.append({"check": "Sanctions (OFAC SDN, UN)", "status": san_r["verdict"], "detail": san_r["answer"].split(" The EU")[0]})
        else:
            checks.append({"check": "Sanctions (OFAC SDN, UN)", "status": "no_match", "detail": "No match in the OFAC SDN or UN consolidated lists."})

    statuses = {c["check"]: c["status"] for c in checks}
    sanc = statuses.get("Sanctions (OFAC SDN, UN)")
    hard_fail = valid is False or sanc in ("match", "potential_match")
    positives = [c for c in checks if c["status"] in ("valid", "found", "no_match")]
    unchecked = [c for c in checks if c["status"] == "unavailable"]
    if hard_fail:
        verdict = "failed" if (valid is False or sanc == "match") else "needs_review"
    elif flags or unchecked:
        verdict = "needs_review"
    elif positives and (valid or statuses.get("Legal-entity register (GLEIF)") == "found") and sanc == "no_match":
        verdict = "verified"
    else:
        verdict = "needs_review"
    conf = {"verified": 0.8, "failed": 0.85, "needs_review": 0.55}[verdict]
    parts = "; ".join(f"{c['check']}: {c['detail'].rstrip('.')}" for c in checks)
    answer = (f"Vendor verdict: {verdict.replace('_', ' ')}"
              f"{' (' + '; '.join(flags) + ')' if flags else ''}. {parts}. Not checked (no public source): {', '.join(NOT_CHECKED)}. "
              "This is evidence from public registers, not legal advice.")
    return ok(answer, conf, verdict=verdict, vendor=vendor, vat_number=f"{vat[0]}{vat[1]}" if vat else None, valid=valid,
              registered_name=registered_name, registered_address=registered_address, checks=checks, flags=flags, not_checked=NOT_CHECKED)
