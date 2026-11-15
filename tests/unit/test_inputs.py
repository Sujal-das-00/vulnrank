from app.inputs import findings_from_body, findings_from_query, infer_asset_from_text
from app.models import RawTriageRequest


def test_query_multi_and_invalid():
    f, errs, notes, _ = findings_from_query({"cve_id": "cve-2021-44228, CVE-2024-3094 bogus CVE-2021-44228"})
    assert [x.cve_id for x in f] == ["CVE-2021-44228", "CVE-2024-3094"]
    assert errs and errs[0].code == "invalid_cve_id" and errs[0].input == "bogus"


def test_query_question_text_and_inference():
    f, errs, notes, _ = findings_from_query({"question": "Rank CVE-2021-44228 and CVE-2024-3094 on an internet-facing payments service in production"})
    assert len(f) == 2 and f[0].asset.exposure == "internet" and f[0].asset.environment == "production"
    assert f[0].asset.criticality == "critical" and notes and "inferred" in notes[0]


def test_explicit_params_beat_inference():
    f, _, notes, _ = findings_from_query({"cve_id": "CVE-2021-44228", "criticality": "low", "internet_exposed": "false", "question": "internet-facing"})
    assert f[0].asset.criticality == "low" and f[0].asset.effective_exposure() == "internal" and not notes


def test_bad_asset_value_is_reported():
    f, errs, *_ = findings_from_query({"cve_id": "CVE-2021-44228", "criticality": "catastrophic"})
    assert f and any(e.code == "invalid_asset_context" for e in errs)


def test_body_per_item_errors_not_silent():
    raw = RawTriageRequest(findings=[{"cve_id": "CVE-2021-44228"}, {"cve_id": "nope"}, {"cve_id": "CVE-2024-3094", "asset": {"criticality": "bogus"}}, {"cve_id": "CVE-2023-1234", "evil": 1}])
    f, errs = findings_from_body(raw, 100)
    assert len(f) == 1 and {e.index for e in errs} == {1, 2, 3}


def test_body_batch_limit():
    raw = RawTriageRequest(findings=[{"cve_id": f"CVE-2021-{1000 + i}"} for i in range(5)])
    f, errs = findings_from_body(raw, 3)
    assert len(f) == 3 and any(e.code == "batch_too_large" for e in errs)


def test_isolated_inference():
    a, _ = infer_asset_from_text("an air-gapped dev box")
    assert a.exposure == "isolated" and a.environment == "development"


def test_kev_product_match_is_conservative():
    from app.sources.kev import match_products
    by_id = {
        "CVE-2021-44228": {"product": "Log4j2", "vendor": "Apache", "date_added": "2021-12-10", "ransomware": True},
        "CVE-2020-0001": {"product": "Windows", "vendor": "Microsoft", "date_added": "2020-01-01"},
        "CVE-2023-0001": {"product": "Exchange Server", "vendor": "Microsoft", "date_added": "2023-01-01"},
        "CVE-2022-0001": {"product": "Server", "vendor": "X", "date_added": "2022-01-01"},
    }
    assert [c for c, _ in match_products(by_id, "should I patch log4j now?")] == ["CVE-2021-44228"]
    assert [c for c, _ in match_products(by_id, "is our server affected by remote code?")] == []
    assert [c for c, _ in match_products(by_id, "exchange outage")] == ["CVE-2023-0001"]
