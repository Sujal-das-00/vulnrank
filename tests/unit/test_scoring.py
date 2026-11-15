import pytest

from app.scoring import AssetContext, ScoreInputs, rank_key, score


def S(**kw):
    return score(ScoreInputs(**kw))


def test_deterministic():
    a = S(cvss=8.1, epss=0.2, kev_listed=False, asset=AssetContext("high", "internet", "production"))
    b = S(cvss=8.1, epss=0.2, kev_listed=False, asset=AssetContext("high", "internet", "production"))
    assert a == b


def test_formula_all_signals():
    # severity 80, exploitation (0.5*50 + 0.3*100)/0.8=68.75 (no exploit ref -> unknown, dropped), crit 75, exp 100
    r = S(cvss=8.0, epss=0.5, kev_listed=True, asset=AssetContext("high", "internet", "production"))
    expected = 0.30 * 80 + 0.35 * 68.75 + 0.20 * 75 + 0.15 * 100
    assert r.base_score == pytest.approx(expected, abs=0.01)


def test_missing_signal_is_not_zero():
    with_epss = S(cvss=8.0, epss=0.0, kev_listed=False)
    without = S(cvss=8.0, epss=None, kev_listed=False)
    # known EPSS=0 and unknown EPSS are different situations and must be reported differently
    assert any("EPSS probability not available" in u for u in without.uncertainty)
    assert not any("EPSS" in u for u in with_epss.uncertainty)


def test_kev_unavailable_is_not_negative():
    r = S(cvss=9.0, epss=0.1, kev_listed=None)
    assert any("KEV could not be checked" in u for u in r.uncertainty)
    notlisted = S(cvss=9.0, epss=0.1, kev_listed=False)
    assert r.confidence_label == "medium" and notlisted.confidence_label == "high"


def test_kev_floor_and_ransomware_floor():
    low = S(cvss=3.0, epss=0.01, kev_listed=True)
    assert low.risk_score >= 70 and low.priority == "high"
    ran = S(cvss=3.0, epss=0.01, kev_listed=True, kev_ransomware=True)
    assert ran.risk_score >= 80 and ran.priority == "critical"
    assert low.floors_applied and ran.floors_applied


def test_kev_internet_critical_prod_floor():
    r = S(cvss=5.0, epss=0.02, kev_listed=True, asset=AssetContext("critical", "internet", "production"))
    assert r.priority == "critical"
    r2 = S(cvss=5.0, epss=0.02, kev_listed=True, asset=AssetContext("critical", "internet", "development"))
    assert not any("internet-facing" in f for f in r2.floors_applied)


def test_high_cvss_isolated_low_crit_no_exploit_ranks_below_moderate_kev():
    a = S(cvss=9.8, epss=0.01, kev_listed=False, asset=AssetContext("low", "isolated", "development"))
    b = S(cvss=6.5, epss=0.3, kev_listed=True, asset=AssetContext("critical", "internet", "production"))
    assert b.risk_score > a.risk_score and a.priority in ("low", "medium") and b.priority == "critical"


def test_cvss_9_does_not_auto_win():
    a = S(cvss=9.8, epss=0.001, kev_listed=False, asset=AssetContext("low", "isolated", "test"))
    b = S(cvss=7.0, epss=0.9, kev_listed=True, asset=AssetContext("high", "internet", "production"))
    assert b.risk_score > a.risk_score


def test_same_cve_different_assets():
    prod = S(cvss=8.0, epss=0.4, kev_listed=False, asset=AssetContext("critical", "internet", "production"))
    dev = S(cvss=8.0, epss=0.4, kev_listed=False, asset=AssetContext("low", "isolated", "development"))
    assert prod.risk_score > dev.risk_score + 15


def test_no_context_renormalises_and_reports():
    r = S(cvss=7.5, epss=0.1, kev_listed=False)
    dims = {c.dimension: c for c in r.components}
    assert dims["criticality"].status == "not_assessed" and dims["exposure"].status == "not_assessed"
    assert sum(c.effective_weight for c in r.components) == pytest.approx(1.0, abs=0.001)
    assert any("No asset context" in u for u in r.uncertainty)


def test_partial_context_defaults_are_flagged():
    r = S(cvss=7.5, epss=0.1, kev_listed=False, asset=AssetContext(criticality="high"))
    assert {c.dimension: c.status for c in r.components}["exposure"] == "defaulted"
    assert r.confidence_label == "medium"


def test_missing_cvss_provisional_from_other_dimensions():
    r = S(cvss=None, epss=0.8, kev_listed=True)
    assert r.status == "scored" and r.confidence_label == "medium"
    assert any("No CVSS" in u for u in r.uncertainty)


def test_provisional_cvss_lowers_confidence():
    r = S(cvss=7.0, cvss_authoritative=False, epss=0.1, kev_listed=False)
    assert r.confidence_label == "medium" and any("provisional" in u for u in r.uncertainty)


def test_insufficient_evidence():
    r = S()
    assert r.status == "insufficient_evidence" and r.risk_score is None and r.priority == "insufficient_evidence"
    r2 = S(cvss=None, epss=None, kev_listed=None, asset=AssetContext("critical", "internet", "production"))
    assert r2.status == "insufficient_evidence"  # asset context alone is not evidence about the vulnerability


def test_confidence_low_when_two_material_missing():
    assert S(cvss=9.0, epss=None, kev_listed=None).confidence_label == "low"


def test_exploit_reference_raises_exploitation():
    base = S(cvss=7.0, epss=0.1, kev_listed=False)
    ref = S(cvss=7.0, epss=0.1, kev_listed=False, exploit_ref=True)
    assert ref.risk_score > base.risk_score


def test_tie_break_order():
    keys = [rank_key(50, False, 0.1, "CVE-2020-0002"), rank_key(50, True, 0.1, "CVE-2020-0003"),
            rank_key(50, True, 0.5, "CVE-2020-0004"), rank_key(50, True, 0.5, "CVE-2020-0001"),
            rank_key(None, None, None, "CVE-2019-0001")]
    order = [k[3] for k in sorted(keys)]
    assert order == ["CVE-2020-0001", "CVE-2020-0004", "CVE-2020-0003", "CVE-2020-0002", "CVE-2019-0001"]


def test_score_bounds():
    r = S(cvss=10, epss=1.0, kev_listed=True, kev_ransomware=True, exploit_ref=True, asset=AssetContext("critical", "internet", "production"))
    assert 0 <= r.risk_score <= 100


def test_not_in_kev_alone_is_insufficient():
    r = S(cvss=None, epss=None, kev_listed=False)
    assert r.status == "insufficient_evidence"
