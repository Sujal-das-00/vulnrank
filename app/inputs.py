"""Turn loose inputs (Telegraph query params / free-text question / JSON body) into findings."""
from __future__ import annotations

import re
from typing import Any

from pydantic import ValidationError

from app.ids import FIND_RE, extract_cve_ids, normalize_cve_id
from app.models import Asset, Finding, ItemError, Preferences, RawTriageRequest

_TOKEN_SPLIT = re.compile(r"[,;\s]+")

_EXPOSED = re.compile(r"\b(internet|public|externally|externally-)[ -]?(facing|exposed|reachable)\b|\bexposed to the internet\b", re.I)
_ISOLATED = re.compile(r"\b(isolated|air[- ]?gapped|not (reachable|exposed)|offline)\b", re.I)
_INTERNAL = re.compile(r"\b(internal[- ]only|internal network|intranet|behind (a |the )?(vpn|firewall))\b", re.I)
_CRIT = re.compile(r"\b(business|mission)[- ]critical\b|\bcrown jewels?\b|\bpayments?\b|\bcritical (asset|service|system|server)\b", re.I)
_ENV = {"production": re.compile(r"\bprod(uction)?\b", re.I), "staging": re.compile(r"\bstag(e|ing)\b", re.I),
        "development": re.compile(r"\bdev(elopment)?\b", re.I), "test": re.compile(r"\b(test|qa|sandbox)\b", re.I)}


def infer_asset_from_text(text: str) -> tuple[Asset | None, list[str]]:
    """Conservative keyword inference from a free-text question. Always reported as inferred."""
    notes: list[str] = []
    kw: dict[str, Any] = {}
    if _EXPOSED.search(text):
        kw["exposure"] = "internet"; notes.append("exposure=internet (phrase in question)")
    elif _ISOLATED.search(text):
        kw["exposure"] = "isolated"; notes.append("exposure=isolated (phrase in question)")
    elif _INTERNAL.search(text):
        kw["exposure"] = "internal"; notes.append("exposure=internal (phrase in question)")
    if _CRIT.search(text):
        kw["criticality"] = "critical"; notes.append("criticality=critical (phrase in question)")
    for env, rx in _ENV.items():
        if rx.search(text):
            kw["environment"] = env; notes.append(f"environment={env} (word in question)"); break
    return (Asset(**kw) if kw else None), notes


def _bool(v: Any) -> bool | None:
    if v is None or v == "":
        return None
    if isinstance(v, bool):
        return v
    s = str(v).strip().lower()
    if s in ("1", "true", "yes", "y"):
        return True
    if s in ("0", "false", "no", "n"):
        return False
    raise ValueError(f"not a boolean: {v!r}")


def findings_from_query(params: dict[str, Any]) -> tuple[list[Finding], list[ItemError], list[str], Preferences]:
    """Telegraph path: `cve_id` (one or many) and/or `question` free text, optional asset params."""
    errors: list[ItemError] = []
    notes: list[str] = []
    ids: dict[str, None] = {}
    explicit = [params.get(k) for k in ("cve_id", "cve", "vulnerability", "vulnerabilities", "cve_ids") if params.get(k)]
    for raw in explicit:
        for tok in _TOKEN_SPLIT.split(str(raw).strip()):
            if not tok:
                continue
            try:
                ids.setdefault(normalize_cve_id(tok), None)
            except ValueError:
                found = extract_cve_ids(tok)
                if found:
                    for f in found:
                        ids.setdefault(f, None)
                else:
                    errors.append(ItemError(input=tok[:40], field="cve_id", code="invalid_cve_id",
                                            message="Not a valid CVE identifier (expected CVE-YYYY-NNNN)."))
    text = " ".join(str(params[k]) for k in ("question", "query") if params.get(k))
    for f in extract_cve_ids(text):
        ids.setdefault(f, None)

    asset_kw: dict[str, Any] = {}
    try:
        for k in ("criticality", "environment", "exposure"):
            if params.get(k):
                asset_kw[k] = str(params[k]).strip().lower()
        ie = _bool(params.get("internet_exposed"))
        if ie is not None:
            asset_kw["internet_exposed"] = ie
        if params.get("asset_id"):
            asset_kw["asset_id"] = str(params["asset_id"])[:128]
        asset = Asset(**asset_kw) if asset_kw else None
    except (ValidationError, ValueError) as e:
        errors.append(ItemError(field="asset", code="invalid_asset_context", message=str(e).splitlines()[0][:200]))
        asset = None
    if asset is None and text:
        asset, inf = infer_asset_from_text(text)
        if inf:
            notes.append("Asset context inferred from question text: " + "; ".join(inf) + ".")
    findings = [Finding(cve_id=c, asset=asset) for c in ids]
    prefs = Preferences()
    return findings, errors, notes, prefs


def findings_from_body(raw: RawTriageRequest, max_batch: int) -> tuple[list[Finding], list[ItemError]]:
    findings: list[Finding] = []
    errors: list[ItemError] = []
    if len(raw.findings) > max_batch:
        errors.append(ItemError(field="findings", code="batch_too_large",
                                message=f"Batch of {len(raw.findings)} exceeds the limit of {max_batch}; extra items were not analysed."))
    for idx, item in enumerate(raw.findings[:max_batch]):
        try:
            findings.append(Finding.model_validate(item))
        except ValidationError as e:
            for err in e.errors():
                loc = ".".join(str(x) for x in err["loc"]) or "finding"
                errors.append(ItemError(index=idx, input=str(item.get("cve_id", ""))[:40] if isinstance(item, dict) else None,
                                        field=loc, code=err["type"], message=err["msg"][:200]))
    return findings, errors
