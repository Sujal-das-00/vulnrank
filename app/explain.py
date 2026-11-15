"""Deterministic, template-based explanations. No LLM; every sentence maps to a signal."""
from __future__ import annotations

from typing import Any

from app.scoring import ScoreInputs, ScoreResult


def why_ranked_here(i: ScoreInputs, r: ScoreResult, kev: dict | None, epss_pct: float | None,
                    cvss_sev: str | None) -> list[str]:
    out: list[str] = []
    if r.status == "insufficient_evidence":
        return ["Not enough evidence from the configured sources to rank this finding responsibly."]
    if i.kev_listed:
        extra = ""
        if kev:
            if kev.get("date_added"):
                extra += f", added {kev['date_added']}"
            if kev.get("due_date"):
                extra += f", CISA remediation due {kev['due_date']}"
        out.append("Listed in the CISA Known Exploited Vulnerabilities catalogue" + extra + ".")
        if i.kev_ransomware:
            out.append("CISA reports known ransomware campaign use.")
    elif i.kev_listed is False:
        out.append("Not listed in the queried CISA KEV snapshot (absence is not proof of no exploitation).")
    if i.epss is not None:
        pct = f" (top {max(0.01, (1 - epss_pct) * 100):.2g}% of scored CVEs)" if epss_pct is not None else ""
        out.append(f"EPSS estimates a {i.epss * 100:.2f}% chance of exploitation activity in the next 30 days{pct}.")
    if i.cvss is not None:
        prov = "" if i.cvss_authoritative else " (provisional, not the NVD primary score)"
        out.append(f"CVSS base score {i.cvss:.1f}{' / ' + cvss_sev if cvss_sev else ''}{prov}.")
    if i.exploit_ref:
        out.append("NVD tags at least one public reference for this CVE as an exploit.")
    a = i.asset
    if a.exposure == "internet":
        out.append("The affected asset is internet-facing.")
    elif a.exposure == "isolated":
        out.append("The affected asset is isolated, which lowers urgency.")
    elif a.exposure == "internal":
        out.append("The affected asset is internal-only.")
    if a.criticality in ("critical", "high"):
        out.append(f"The affected asset is {a.criticality}-criticality.")
    elif a.criticality == "low":
        out.append("The affected asset is low-criticality, which lowers urgency.")
    if a.environment in ("development", "test", "staging"):
        out.append(f"The asset is in a {a.environment} environment, which lowers urgency.")
    for f in r.floors_applied:
        out.append("Priority floor applied: " + f + ".")
    return out


def recommended_action(r: ScoreResult, i: ScoreInputs, kev: dict | None) -> str:
    if r.status == "insufficient_evidence":
        return "Verify the CVE identifier and re-run when upstream sources are reachable; do not deprioritise on this result."
    if i.kev_listed:
        act = ""
        if kev and kev.get("required_action"):
            act = f" CISA required action: {str(kev['required_action'])[:280]}"
        due = f" (CISA due date {kev['due_date']})" if kev and kev.get("due_date") else ""
        return ("Remediate immediately: apply the vendor patch or vendor-recommended mitigation" + due
                + ", then validate exposure and confirm remediation." + act)
    return {
        "critical": "Patch or mitigate within days: apply the vendor fix, restrict exposure meanwhile, and verify remediation.",
        "high": "Schedule remediation in the next patch cycle; reduce exposure in the interim if feasible.",
        "medium": "Fix during routine maintenance; re-evaluate if EPSS rises or the CVE is added to KEV.",
        "low": "Track in the backlog; re-evaluate if exploitation evidence or asset context changes.",
    }[r.priority]


def fmt_pct(x: float | None) -> str:
    return "n/a" if x is None else f"{x * 100:.2f}%"


def _kev_phrase(it: dict[str, Any]) -> str:
    k = it.get("kev_listed")
    if k is None:
        return "CISA KEV: could not be checked (unknown, not a negative)"
    if not k:
        return "CISA KEV: not listed (absence is not proof of no exploitation)"
    extra = ", ".join(x for x in (f"added {it['kev_added']}" if it.get("kev_added") else "",
                                  f"CISA due {it['kev_due']}" if it.get("kev_due") else "",
                                  "known ransomware use" if it.get("ransomware") else "") if x)
    return "CISA KEV: LISTED (known exploited)" + (f" - {extra}" if extra else "")


def _facts(it: dict[str, Any]) -> str:
    if it["priority"] == "insufficient_evidence":
        return f"{it['cve_id']}: insufficient evidence to rank (" + "; ".join(it.get("uncertainty", [])[:2]) + ")."
    cvss = "CVSS unavailable"
    if it.get("cvss_base_score") is not None:
        basis = "NVD primary CVSS v3.1" if it.get("cvss_authoritative") else "provisional CVSS (not NVD primary)"
        cvss = f"{basis} base score {it['cvss_base_score']:.1f} ({it.get('severity', '').lower()})"
    epss = "EPSS unavailable"
    if it.get("epss") is not None:
        pct = f", percentile {it['epss_percentile'] * 100:.0f}" if it.get("epss_percentile") is not None else ""
        epss = f"FIRST EPSS {it['epss'] * 100:.2f}% 30-day exploitation probability{pct}"
    return (f"{it['cve_id']}: {it['priority'].upper()} priority (risk score {it['risk_score']:.1f}/100, "
            f"{it['confidence_label']} confidence, evidence coverage {it['evidence_coverage']:.0%}). "
            f"{cvss}. {_kev_phrase(it)}. {epss}.")


def summary_text(items: list[dict[str, Any]], notes: list[str], limitations: list[str], focus: str | None = None) -> str:
    """Concise plain-text answer (a few hundred bytes per finding): decision first, then evidence, then caveats."""
    if not items:
        return "No valid CVE identifiers were supplied, so nothing could be prioritised."
    lines: list[str] = []
    if len(items) == 1:
        it = items[0]
        lines.append(_facts(it))
        if it.get("asset_phrase"):
            lines.append(it["asset_phrase"])
        if it.get("recommended_action"):
            lines.append("Action: " + it["recommended_action"].split(" CISA required action")[0])
        if it.get("uncertainty"):
            lines.append("Caveats: " + " ".join(it["uncertainty"][:2]))
    else:
        lines.append(f"Remediation order for {len(items)} findings, highest priority first:")
        for it in items[:10]:
            lines.append(f"{it['rank']}. " + _facts(it))
        if len(items) > 10:
            lines.append(f"(+{len(items) - 10} more in `ranking`)")
        if focus:
            lines.append(f"Top-level cvss_base_score is for the requested CVE {focus}.")
        lines.append("Action for #1: " + (items[0].get("recommended_action") or "").split(" CISA required action")[0])
    lines.extend(limitations[:3])
    lines.append("Priority is a heuristic (score_version v1), not a probability of compromise; confirm asset applicability.")
    return "\n".join(lines)
