"""EMAIL_SECURITY_GENERAL: SPF, DKIM, DMARC and MX records of a domain, read through two DNS-over-HTTPS resolvers (Google, Cloudflare).

`lookup_ok` is true only when the requested record exists and is syntactically valid, false when both resolvers agree it is missing or
invalid, and null when the resolvers failed or disagree. Message-header and attachment analysis are not supported and the answer says so."""
from __future__ import annotations

import asyncio
import re
from typing import Any

from app.intents.common import first, free_text, ok, soft
from app.intents.dns import RESOLVERS, _ask, parse_name
from app.sources.base import Fetcher

DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "s1", "mail", "dkim"]
LOOKUP_MECH = re.compile(r"(?:^|\s)[+\-~?]?(?:include:|a(?::|/|\s|$)|mx(?::|/|\s|$)|ptr|exists:|redirect=)", re.I)


async def _txt(f: Fetcher, name: str, rtype: str, timeout: float, deadline: float | None) -> tuple[list[str] | None, bool, int]:
    """-> (records or None if no resolver answered, nxdomain agreed, resolvers answering)."""
    res = await asyncio.gather(*(_ask(f, label, url, name, rtype, timeout, deadline) for label, url in RESOLVERS.items()), return_exceptions=True)
    good = [r for r in res if isinstance(r, dict)]
    if not good:
        return None, False, 0
    sets = [{_unquote(x) for x in r["records"]} for r in good]  # Google quotes TXT data, Cloudflare does not
    recs = sorted(set().union(*sets))
    if len(sets) == 2 and sets[0] != sets[1] and sets[0] and sets[1]:
        recs = sorted(sets[0] & sets[1]) or recs
    return recs, all(r["nxdomain"] for r in good), len(good)


def _unquote(rec: str) -> str:
    return re.sub(r'"\s*"', "", rec).strip().strip('"')


def check_spf(records: list[str]) -> dict[str, Any]:
    spf = [r for r in map(_unquote, records) if r.lower().startswith("v=spf1")]
    if not spf:
        return {"present": False, "valid": False, "issues": ["No SPF record (v=spf1) is published."]}
    issues = []
    if len(spf) > 1:
        issues.append("More than one SPF record is published; receivers treat that as a permanent error.")
    rec = spf[0]
    m = re.search(r"\s([+\-~?]?)all\b", rec, re.I)
    policy = {"-": "fail (-all)", "~": "softfail (~all)", "?": "neutral (?all)", "+": "pass-all (+all)", "": "pass-all (+all)"}.get(m.group(1)) if m else None
    if m is None and "redirect=" not in rec.lower():
        issues.append("No terminating 'all' mechanism or redirect.")
    elif m and m.group(1) in ("+", ""):
        issues.append("'+all' authorises every sender on the internet.")
    elif m and m.group(1) == "?":
        issues.append("'?all' gives no protection against spoofing.")
    n = len(LOOKUP_MECH.findall(rec))
    if n > 10:
        issues.append(f"{n} DNS-lookup mechanisms in this record alone; SPF allows at most 10 in total (RFC 7208).")
    return {"present": True, "valid": not any("permanent error" in i or "terminating" in i or "authorises every" in i or "at most 10" in i for i in issues), "record": rec[:300],
            "policy": policy, "lookup_mechanisms": n, "issues": issues}


def check_dmarc(records: list[str]) -> dict[str, Any]:
    d = [r for r in map(_unquote, records) if r.lower().startswith("v=dmarc1")]
    if not d:
        return {"present": False, "valid": False, "issues": ["No DMARC record (v=DMARC1) is published at _dmarc."]}
    rec = d[0]
    tags = {k.strip().lower(): v.strip() for k, _, v in (p.partition("=") for p in rec.split(";") if "=" in p)}
    pol = tags.get("p", "").lower()
    issues = []
    if pol not in ("none", "quarantine", "reject"):
        issues.append("The required p= policy tag is missing or invalid.")
    elif pol == "none":
        issues.append("Policy p=none only monitors; spoofed mail is still delivered.")
    if "rua" not in tags:
        issues.append("No rua= aggregate-report address, so failures are not reported.")
    if tags.get("pct") and tags["pct"].isdigit() and int(tags["pct"]) < 100:
        issues.append(f"pct={tags['pct']}: the policy applies to only part of the mail.")
    return {"present": True, "valid": pol in ("none", "quarantine", "reject"), "record": rec[:300], "policy": pol or None, "has_reports": "rua" in tags, "issues": issues}


async def lookup(f: Fetcher, params: dict[str, Any], *, timeout: float, deadline: float | None) -> dict[str, Any]:
    text = free_text(params)
    raw = first(params, "domain", "host", "name", "email", "sender") or text
    em = re.search(r"[\w.+-]+@([\w.-]+\.[a-z]{2,})", raw or "", re.I)
    if em:
        domain = parse_name(em.group(1))
    elif first(params, "domain", "host", "name"):
        domain = parse_name(first(params, "domain", "host", "name") or "")
    else:
        m = re.search(r"\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})\b", text, re.I)
        domain = parse_name(m.group(1)) if m else None
    if not domain:
        return soft("no_domain", "No domain was identified, so no mail-authentication result is given.", lookup_ok=None)
    want = (first(params, "record_type", "type", "record") or "").upper()
    if not want:
        want = next((t for t in ("SPF", "DKIM", "DMARC", "MX") if re.search(rf"\b{t}\b", text.upper()) and not all(re.search(rf"\b{x}\b", text.upper()) for x in ("SPF", "DKIM", "DMARC"))), "ALL")
    want = "ALL" if want in ("", "ANY", "TXT") else want
    selector = first(params, "selector", "dkim_selector")
    probes = [selector] if selector else DKIM_SELECTORS
    spf_t = _txt(f, domain, "TXT", timeout, deadline)
    dmarc_t = _txt(f, "_dmarc." + domain, "TXT", timeout, deadline)
    mx_t = _txt(f, domain, "MX", timeout, deadline)
    dkim_t = [_txt(f, f"{s}._domainkey.{domain}", "TXT", timeout, deadline) for s in probes] if want in ("ALL", "DKIM") else []
    spf_r, dmarc_r, mx_r, *dkim_r = await asyncio.gather(spf_t, dmarc_t, mx_t, *dkim_t)
    if spf_r[0] is None and dmarc_r[0] is None and mx_r[0] is None:
        return soft("unavailable", "Both DNS resolvers failed, so no mail-authentication result is given (not reported as missing).", lookup_ok=None, domain=domain)
    spf = check_spf(spf_r[0]) if spf_r[0] is not None else {"present": None, "valid": None, "issues": ["SPF lookup failed."]}
    dmarc = check_dmarc(dmarc_r[0]) if dmarc_r[0] is not None else {"present": None, "valid": None, "issues": ["DMARC lookup failed."]}
    mx = None if mx_r[0] is None else mx_r[0]
    null_mx = bool(mx and all(re.match(r"^0\s+\.?$", m) for m in mx))
    dkim_found = []
    for s, r in zip(probes, dkim_r):
        if r[0] and any(re.search(r"(?:^|;)\s*p=\s*[A-Za-z0-9+/=\s]{20,}", _unquote(x)) for x in r[0]):
            dkim_found.append(s)
    dkim = {"present": True if dkim_found else (None if selector is None else False), "selectors_found": dkim_found, "selectors_probed": probes if dkim_t else [],
            "issues": [] if dkim_found else (["No DKIM key found at the probed selectors; the real selector may be different, so this does not prove DKIM is absent."] if dkim_t else [])}
    results = {"SPF": spf["valid"], "DMARC": dmarc["valid"], "DKIM": True if dkim_found else (False if selector else None), "MX": None if mx is None else bool(mx) and not null_mx}
    lookup_ok = (results["SPF"] and results["DMARC"]) if want == "ALL" and results["SPF"] is not None and results["DMARC"] is not None else (
        False if want == "ALL" and (results["SPF"] is False or results["DMARC"] is False) else (None if want == "ALL" else results.get(want)))
    grade = "A"
    penalty = (0 if spf["valid"] else 3) + (0 if dmarc["valid"] else 3) + (1 if dmarc.get("policy") == "none" else 0) + (1 if spf.get("policy") and spf["policy"].startswith(("neutral", "pass-all")) else 0)
    grade = "ABCDEF"[min(5, penalty)]
    parts = [f"SPF: {'valid, ' + spf['policy'] if spf.get('valid') and spf.get('policy') else 'valid' if spf.get('valid') else 'missing or invalid'}",
             f"DMARC: {'valid, p=' + str(dmarc.get('policy')) if dmarc.get('valid') else 'missing or invalid'}",
             f"DKIM: {'found (' + ', '.join(dkim_found) + ')' if dkim_found else 'not found at probed selectors'}"]
    answer = (f"{domain}: " + "; ".join(parts) + f". Mail-authentication grade {grade}. "
              + ("Not checked: message headers, spoofing in a specific email, attachments (supply a domain, not a message).") )
    issues = [i for c in (spf, dmarc, dkim) for i in c.get("issues", [])]
    return ok(answer, 0.9 if spf_r[2] + dmarc_r[2] >= 4 else 0.7, domain=domain, lookup_ok=lookup_ok, checked=want, spf=spf, dkim=dkim, dmarc=dmarc, mx_present=results["MX"], null_mx=null_mx,
              grade=grade, issues=issues, resolvers="Google Public DNS and Cloudflare")
