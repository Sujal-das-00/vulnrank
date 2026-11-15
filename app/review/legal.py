"""Evaluate the rules table against evidence signals. Deterministic; no model; every statement comes from rules.yaml."""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from app.review.evidence import Signals
from app.review.findings import SEV_SCORE, Finding

RULES_PATH = Path(__file__).with_name("rules.yaml")
JURISDICTIONS = ("eu", "india", "us")
SECTORS = ("saas", "ecommerce")
_PAGE_SIGNALS = {"privacy_policy", "terms", "refund_policy", "provider_identity", "grievance_officer", "cookie_consent", "do_not_sell", "unsubscribe"}
_CONF_FACTOR = {"high": 1.0, "medium": 0.9, "low": 0.65}
_SEC_LEGAL = {
    "eu": "EU GDPR Art. 32 (security of processing): ceiling up to EUR 10M or 2% of worldwide turnover (Art. 83(4)) if personal data is affected.",
    "india": "India DPDP Act s.8(5) (reasonable security safeguards): ceiling up to INR 250 crore; applies in full about May 2027.",
    "us": "California CCPA Civ. Code 1798.150: USD 107-799 per consumer per incident if California residents' data is breached through unreasonable security.",
}


@lru_cache(maxsize=1)
def load_rules() -> dict[str, Any]:
    return yaml.safe_load(RULES_PATH.read_text(encoding="utf-8"))


@dataclass
class LegalResult:
    checklist: list[dict[str, Any]] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    exposure: list[dict[str, Any]] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)


def infer_sector(sig: Signals) -> str:
    return "ecommerce" if sig.has("checkout") else "saas"


def _basis(rule: dict, regime: dict, today: str) -> dict:
    return {"law": regime["name"], "citation": rule["cite"], "url": regime["url"], "verification": regime["verification"],
            **({"note": regime["note"]} if regime.get("note") else {}), "table_as_of": load_rules()["as_of"]}


def evaluate(sig: Signals, jurisdictions: list[str], sector: str, *, today: dt.date | None = None) -> LegalResult:
    cfg = load_rules()
    today = today or dt.date.today()
    res = LegalResult()
    regimes = cfg["regimes"]
    used: dict[str, dict] = {}
    for rule in cfg["rules"]:
        if not set(rule["jurisdictions"]) & set(jurisdictions) or sector not in rule["sectors"]:
            continue
        reg = regimes[rule["regime"]]
        present, absent = rule.get("present", []), rule.get("absent", [])
        triggered = all(sig.has(p) for p in present)
        missing = all(not sig.has(a) for a in absent)
        fired = triggered and missing and bool(present or absent)
        item = {"id": rule["id"], "title": rule["title"] if fired else rule["check"],
                "law": reg["name"], "citation": rule["cite"], "jurisdictions": [j for j in rule["jurisdictions"] if j in jurisdictions]}
        eff = rule.get("effective_from")
        upcoming = bool(eff and dt.date.fromisoformat(eff) > today)
        if not triggered:
            item.update(status="not_applicable", note="Condition not met (nothing detected that triggers this duty).")
        elif not fired:
            ev = [e for a in absent for e in sig.evidence(a)][:2]
            item.update(status="passed", evidence=ev)
        else:
            conf = rule.get("confidence", "medium")
            if (set(absent) | set(present)) & _PAGE_SIGNALS and not sig.has_web_ui:
                conf = "low"
            sev = rule["severity"]
            score = SEV_SCORE[sev] * _CONF_FACTOR[conf]
            fix = rule["fix"]
            note = None
            if upcoming:
                score *= 0.4
                note = f"Applies from about {eff}; prepare now."
            item.update(status="upcoming" if upcoming else "not_detected", severity=sev, confidence=conf, fix=fix, **({"note": note} if note else {}))
            ev = [e for p in present for e in sig.evidence(p)][:3]
            if ev:
                item["evidence"] = ev
            if rule["id"] == "any-contact-consistency":
                item["evidence"] = sig.evidence("mixed_contacts")
            if not sig.has_web_ui and (set(absent) & _PAGE_SIGNALS):
                item["caveat"] = "No web pages or templates were found in this scan, so this may live in another repository or service."
            res.findings.append(Finding(
                f"legal:{rule['id']}", "compliance", "legal_check", rule["title"] + (" (upcoming)" if upcoming else ""), sev if not upcoming else "info", fix,
                score=score, confidence=conf, evidence=item.get("evidence", []), basis=_basis(rule, reg, cfg["as_of"]),
                tags=[rule["regime"]] + (["upcoming"] if upcoming else []),
                detail={**({"caveat": item["caveat"]} if item.get("caveat") else {}), **({"applies_from": eff} if upcoming else {})}))
            if rule.get("exposure", True) is False:
                res.checklist.append(item)
                continue
            u = used.setdefault(rule["regime"], {"regime": reg["name"], "ceiling": reg["ceiling"], "source": reg["url"], "verification": reg["verification"],
                                                 "gaps": 0, "upcoming": 0, "worst": "info"})
            u["upcoming" if upcoming else "gaps"] += 1
            if not upcoming and SEV_SCORE[sev] > SEV_SCORE[u["worst"]]:
                u["worst"] = sev
        res.checklist.append(item)
    res.exposure = sorted(used.values(), key=lambda u: -SEV_SCORE[u["worst"]])
    res.findings.sort(key=lambda f: -f.score)
    return res


def attach_security_relevance(findings: list[Finding], jurisdictions: list[str]) -> None:
    """High/critical security findings (and any KEV-listed one) get the legal provisions that make them matter."""
    notes = [_SEC_LEGAL[j] for j in JURISDICTIONS if j in jurisdictions]
    for f in findings:
        if f.category == "security" and (f.severity in ("critical", "high") or "CISA-KEV" in f.tags) and notes:
            f.detail["legal_relevance"] = notes + (["A confirmed-exploited (CISA KEV) flaw left unpatched is the kind of fact cited when arguing security was not 'reasonable'."]
                                                   if "CISA-KEV" in f.tags else [])


def parse_jurisdictions(text: str) -> list[str]:
    import re
    t = text.lower()
    out = []
    if re.search(r"\b(eu|europe|european|gdpr|germany|france|spain|italy|netherlands|ireland)\b", t):
        out.append("eu")
    if re.search(r"\b(india|indian|dpdp|inr|bharat)\b", t):
        out.append("india")
    if re.search(r"\b(us|usa|u\.s\.|united states|america|california|ccpa|cpra)\b", t):
        out.append("us")
    return out


def parse_sector(text: str) -> str | None:
    import re
    t = text.lower()
    if re.search(r"e-?commerce|online (shop|store)|webshop|marketplace|retail|storefront", t):
        return "ecommerce"
    if re.search(r"\bsaas\b|software as a service|b2b software|subscription software|web app", t):
        return "saas"
    return None
