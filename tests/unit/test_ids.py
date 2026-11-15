import pytest

from app.ids import extract_cve_ids, normalize_cve_id


@pytest.mark.parametrize("raw,exp", [("cve-2021-44228", "CVE-2021-44228"), ("  CVE-2024-3094 ", "CVE-2024-3094"),
                                      ("CVE‑2021‑44228", "CVE-2021-44228"), ("CVE-2026-114713", "CVE-2026-114713")])
def test_normalize_ok(raw, exp):
    assert normalize_cve_id(raw) == exp


@pytest.mark.parametrize("bad", ["", "CVE-21-1", "CVE-2021-12", "2021-44228", "CVE-2021-44228; rm -rf /", "https://x/CVE-2021-44228", "CVE-1900-12345", None])
def test_normalize_rejects(bad):
    with pytest.raises(ValueError):
        normalize_cve_id(bad)


def test_extract_dedup_order():
    t = "Rank cve-2024-3094, CVE-2021-44228 and CVE-2024-3094 again; ignore XCVE-2020-1234567 and CVE-2020-123"
    assert extract_cve_ids(t) == ["CVE-2024-3094", "CVE-2021-44228"]
