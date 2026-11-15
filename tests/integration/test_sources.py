"""Source clients against recorded-shape fixtures: success, not-found, timeout, rate-limit, malformed, stale."""
import httpx
import pytest

from app.sources.base import AVAILABLE, NOT_FOUND, STALE, UNAVAILABLE, SourceError
from tests.conftest import EPSS, KEV, NVD, cvedb_url
from tests.fixtures import data

C = "CVE-2021-44228"


async def test_nvd_success_primary_selected(svc, mock):
    mock.get(NVD).respond(200, json=data.nvd(C, primary=10.0, secondary=9.0, exploit_ref=True))
    r = await svc.nvd.fetch(C)
    assert r.status == AVAILABLE and r.retrieved_at and r.source_url.endswith(C)
    from app.sources.nvd import select_cvss
    sel = select_cvss(r.data)
    assert sel["score"] == 10.0 and sel["authoritative"] and sel["version"] == "3.1"
    assert r.data["exploit_refs"] and r.data["cwes"] == ["CWE-502"]


async def test_nvd_secondary_only_is_provisional(svc, mock):
    mock.get(NVD).respond(200, json=data.nvd(C, primary=None, secondary=6.1))
    from app.sources.nvd import select_cvss
    sel = select_cvss((await svc.nvd.fetch(C)).data)
    assert sel["score"] == 6.1 and sel["authoritative"] is False


async def test_nvd_not_found(svc, mock):
    mock.get(NVD).respond(200, json=data.NVD_EMPTY)
    assert (await svc.nvd.fetch("CVE-2099-0001")).status == NOT_FOUND


async def test_nvd_timeout_is_unavailable_not_negative(svc, mock):
    mock.get(NVD).mock(side_effect=httpx.ConnectTimeout("boom"))
    r = await svc.nvd.fetch(C)
    assert r.status == UNAVAILABLE and r.data is None


async def test_nvd_rate_limited_retries_then_unavailable(svc, mock):
    route = mock.get(NVD).respond(429, headers={"Retry-After": "0"})
    r = await svc.nvd.fetch(C)
    assert r.status == UNAVAILABLE and route.call_count == 2  # 1 try + 1 retry


async def test_nvd_retry_then_success(svc, mock):
    mock.get(NVD).mock(side_effect=[httpx.Response(503), httpx.Response(200, json=data.nvd(C))])
    assert (await svc.nvd.fetch(C)).status == AVAILABLE


async def test_nvd_malformed(svc, mock):
    mock.get(NVD).respond(200, text="<html>not json</html>")
    assert (await svc.nvd.fetch(C)).status == UNAVAILABLE


async def test_nvd_stale_cache_served_when_refresh_fails(svc, mock):
    mock.get(NVD).respond(200, json=data.nvd(C))
    first = await svc.nvd.fetch(C)
    # expire the entry then fail upstream
    e = svc.cache_.get(f"nvd:{C}"); e.expires_at = 0
    mock.get(NVD).respond(500)
    r = await svc.nvd.fetch(C)
    assert r.status == STALE and r.data == first.data and "last-known-good" in r.note


async def test_kev_listed_and_not_listed_and_unavailable(svc, mock):
    mock.get(KEV).respond(200, json=data.kev({C: {"ransomware": True, "due": "2021-12-24"}}))
    a = await svc.kev.lookup(C)
    b = await svc.kev.lookup("CVE-2024-3094")
    assert a.data["listed"] is True and a.data["ransomware"] and a.data["due_date"] == "2021-12-24"
    assert b.status == AVAILABLE and b.data["listed"] is False and "does not prove" in b.note


async def test_kev_unavailable_is_not_unlisted(svc, mock):
    mock.get(KEV).mock(side_effect=httpx.ReadTimeout("slow"))
    r = await svc.kev.lookup(C)
    assert r.status == UNAVAILABLE and r.data is None


async def test_kev_stale_snapshot(svc, mock):
    mock.get(KEV).respond(200, json=data.kev({C: {}}))
    await svc.kev.lookup(C)
    svc.cache_.get("kev:catalogue").expires_at = 0
    mock.get(KEV).respond(503)
    r = await svc.kev.lookup(C)
    assert r.status == STALE and r.data["listed"] is True


async def test_kev_malformed(svc, mock):
    mock.get(KEV).respond(200, json={"nope": 1})
    assert (await svc.kev.lookup(C)).status == UNAVAILABLE


async def test_epss_batch_and_not_found_and_range(svc, mock):
    mock.get(EPSS).respond(200, json=data.epss({C: (0.97, 1.0)}))
    out = await svc.epss.fetch_many([C, "CVE-2026-0001"])
    assert out[C].data["probability"] == 0.97
    assert out["CVE-2026-0001"].status == NOT_FOUND


async def test_epss_out_of_range_rejected(svc, mock):
    mock.get(EPSS).respond(200, json=data.epss({C: (1.7, 1.0)}))
    assert (await svc.epss.fetch_many([C]))[C].status == UNAVAILABLE


async def test_epss_failure_unavailable(svc, mock):
    mock.get(EPSS).respond(500)
    assert (await svc.epss.fetch_many([C]))[C].status == UNAVAILABLE


async def test_cvedb(svc, mock):
    mock.get(cvedb_url(C)).respond(200, json=data.cvedb(C, 9.8))
    assert (await svc.cvedb.fetch(C)).data["cvss_v3"] == 9.8
    mock.get(cvedb_url("CVE-2099-1")).respond(404, json={"detail": "CVE not found"})
    assert (await svc.cvedb.fetch("CVE-2099-1")).status == NOT_FOUND


async def test_ssrf_guard_blocks_unlisted_hosts(svc):
    with pytest.raises(SourceError) as ei:
        await svc.nvd.f.get_json("https://evil.example/x")
    assert ei.value.kind == "blocked"
    with pytest.raises(SourceError):
        await svc.nvd.f.get_json("http://services.nvd.nist.gov/x")  # http, not https


async def test_circuit_breaker_opens(svc, mock):
    svc.nvd.f.threshold = 2
    mock.get(NVD).respond(500)
    for _ in range(2):
        await svc.nvd.fetch("CVE-2021-0001")
    r = await svc.nvd.fetch("CVE-2021-0002")
    assert r.status == UNAVAILABLE and "circuit_open" in r.note
