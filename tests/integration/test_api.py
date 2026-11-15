"""End-to-end through FastAPI with upstreams mocked."""
import httpx
import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from tests.conftest import EPSS, KEV, NVD, cvedb_url
from tests.fixtures import data

LOG4J, XZ, MID, ISO = "CVE-2021-44228", "CVE-2024-3094", "CVE-2023-1111", "CVE-2022-2222"


def nvd_router(mock, table: dict[str, dict]):
    def handler(request: httpx.Request):
        cve = request.url.params["cveId"]
        return httpx.Response(200, json=table.get(cve, data.NVD_EMPTY))
    mock.get(NVD).mock(side_effect=handler)


@pytest.fixture
def client(settings, mock):
    app = create_app(settings)
    with TestClient(app) as c:
        yield c


def happy(mock):
    nvd_router(mock, {LOG4J: data.nvd(LOG4J, 10.0, exploit_ref=True), MID: data.nvd(MID, 6.5),
                      ISO: data.nvd(ISO, 9.8), XZ: data.nvd(XZ, 10.0)})
    mock.get(KEV).respond(200, json=data.kev({LOG4J: {"ransomware": True}, MID: {}}))
    mock.get(EPSS).respond(200, json=data.epss({LOG4J: (0.99999, 1.0), MID: (0.3, 0.9), ISO: (0.01, 0.4), XZ: (0.9, 0.99)}))


def test_health_makes_no_external_calls(client, mock):
    assert client.get("/health").json() == {"status": "ok"}
    assert not [c for c in mock.calls if "nist.gov" in str(c.request.url) or "cisa" in str(c.request.url)]


def test_telegraph_single_cve_contract(client, mock):
    happy(mock)
    r = client.get("/vuln-triage", params={"cve_id": "cve-2021-44228"})
    assert r.status_code == 200
    j = r.json()
    assert j["cvss_base_score"] == 10.0 and j["cvss_is_nvd_primary"] is True and j["cve_id"] == LOG4J
    assert j["kev_listed"] is True and j["epss_probability"] == 0.99999 and j["priority"] == "critical"
    assert j["severity"] == "CRITICAL" and j["summary"] and j["evidence"]
    ev = {(e["source_name"], e["field"]): e for e in j["evidence"]}
    assert ev[("CISA KEV", "kev_listed")]["retrieved_at"] and ev[("NVD", "cvss_base_score")]["source_url"].endswith(LOG4J)


def test_nvd_down_uses_labelled_fallback(client, mock):
    mock.get(NVD).mock(side_effect=httpx.ReadTimeout("slow"))
    mock.get(cvedb_url(LOG4J)).respond(200, json=data.cvedb(LOG4J, 10.0))
    mock.get(KEV).respond(200, json=data.kev({}))
    mock.get(EPSS).respond(200, json=data.epss({LOG4J: (0.5, 0.9)}))
    j = client.get("/vuln-triage", params={"cve_id": LOG4J}).json()
    assert j["cvss_base_score"] == 10.0 and j["cvss_is_nvd_primary"] is False and "CVEDB" in j["cvss_source"]
    assert j["confidence_label"] == "medium" and j["source_status"]["NVD"] == "unavailable"
    assert any("fallback" in u.lower() or "provisional" in u.lower() for u in j["uncertainty"])


def test_kev_down_is_unknown_not_false(client, mock):
    nvd_router(mock, {LOG4J: data.nvd(LOG4J, 9.0)})
    mock.get(KEV).mock(side_effect=httpx.ConnectTimeout("x"))
    mock.get(EPSS).respond(200, json=data.epss({LOG4J: (0.2, 0.8)}))
    j = client.get("/vuln-triage", params={"cve_id": LOG4J}).json()
    assert j["kev_listed"] is None and j["source_status"]["CISA KEV"] == "unavailable"
    assert any("KEV" in u for u in j["uncertainty"])


def test_all_sources_down_is_soft_and_not_fabricated(client, mock):
    mock.get(NVD).respond(503)
    mock.get(cvedb_url(LOG4J)).respond(503)
    mock.get(KEV).respond(503)
    mock.get(EPSS).respond(503)
    r = client.get("/vuln-triage", params={"cve_id": LOG4J})
    j = r.json()
    assert r.status_code == 200 and j["status"] == "insufficient_evidence"
    assert j["cvss_base_score"] is None and j["answer"] and "guess" in j["answer"]


def test_unknown_cve_is_soft_not_found(client, mock):
    nvd_router(mock, {})
    mock.get(cvedb_url("CVE-2099-0001")).respond(404, json={})
    mock.get(KEV).respond(200, json=data.kev({}))
    mock.get(EPSS).respond(200, json=data.epss({}))
    r = client.get("/vuln-triage", params={"cve_id": "CVE-2099-0001"})
    j = r.json()
    assert r.status_code == 200 and j["status"] == "cve_not_found" and j["cvss_base_score"] is None and "CVE-2099-0001" in j["answer"]


@pytest.mark.parametrize("q", [{}, {"cve_id": "hello"}, {"cve_id": "CVE-1-2"}, {"cve_id": "x; rm -rf /"}])
def test_invalid_input_is_soft_never_empty(client, mock, q):
    mock.get(KEV).respond(200, json=data.kev({}))
    r = client.get("/vuln-triage", params=q)
    j = r.json()
    assert r.status_code == 200 and j["status"] == "no_cve_identified" and j["cvss_base_score"] is None and j["answer"]


def test_product_question_without_cve_returns_kev_candidates(client, mock):
    mock.get(KEV).respond(200, json=data.kev({LOG4J: {}}))
    r = client.get("/vuln-triage", params={"question": "should I patch log4j now?"})
    j = r.json()
    assert r.status_code == 200 and j["cvss_base_score"] is None
    assert j["status"] == "no_cve_identified" and isinstance(j["kev_candidates"], list)


def test_portfolio_ranking_story(client, mock):
    """Demo story: moderate-CVSS KEV on exposed critical asset beats high-CVSS on isolated low asset."""
    happy(mock)
    body = {"request_id": "r1", "findings": [
        {"cve_id": ISO, "asset": {"asset_id": "dev-box", "environment": "development", "criticality": "low", "exposure": "isolated"}},
        {"cve_id": MID, "asset": {"asset_id": "pay-api", "environment": "production", "criticality": "critical", "internet_exposed": True}},
        {"cve_id": LOG4J, "asset": {"asset_id": "pay-api", "environment": "production", "criticality": "critical", "internet_exposed": True}},
        {"cve_id": "bogus"},
        {"cve_id": LOG4J, "asset": {"asset_id": "pay-api", "environment": "production", "criticality": "critical", "internet_exposed": True}},
    ]}
    r = client.post("/v1/triage", json=body)
    assert r.status_code == 200
    j = r.json()
    order = [p["cve_id"] for p in j["priorities"]]
    assert order == [LOG4J, MID, ISO]
    assert j["priorities"][0]["duplicates_merged"] == 1
    assert j["priorities"][1]["priority"] == "critical" and j["priorities"][2]["priority"] in ("low", "medium")
    assert j["errors"] and j["errors"][0]["index"] == 3 and j["request_id"] == "r1"
    assert j["summary"]["total_submitted"] == 5 and j["summary"]["successfully_analysed"] == 3
    assert [p["rank"] for p in j["priorities"]] == [1, 2, 3]
    for p in j["priorities"]:
        assert p["score_breakdown"]["components"] and p["why_ranked_here"] and p["score_version"] == "v1"


def test_deterministic_across_runs(client, mock):
    happy(mock)
    body = {"findings": [{"cve_id": c} for c in (XZ, MID, LOG4J, ISO)]}
    a = client.post("/v1/triage", json=body).json()
    b = client.post("/v1/triage", json=body).json()
    strip = lambda j: [(p["cve_id"], p["risk_score"], p["rank"]) for p in j["priorities"]]
    assert strip(a) == strip(b)


def test_telegraph_multi_cve_question(client, mock):
    happy(mock)
    q = f"Rank {ISO}, {MID} and {LOG4J} on an internet-facing payments service in production"
    j = client.get("/vuln-triage", params={"question": q}).json()
    assert [r["cve_id"] for r in j["ranking"]][0] == LOG4J and j["cve_id"] == LOG4J
    assert len(j["ranking"]) == 3 and "inferred" in j["summary"]


def test_batch_limit_and_body_validation(client, mock):
    r = client.post("/v1/triage", json={"findings": []})
    assert r.status_code == 422
    r = client.post("/v1/triage", json={"findings": [{"cve_id": "nope"}]})
    assert r.status_code == 422 and r.json()["error"] == "no_valid_findings"
    r = client.post("/v1/triage", content=b"x" * 300_000, headers={"content-type": "application/json"})
    assert r.status_code == 413


def test_top_n_and_no_remediation(client, mock):
    happy(mock)
    j = client.post("/v1/triage", json={"findings": [{"cve_id": c} for c in (LOG4J, MID, ISO)],
                                         "preferences": {"top_n": 1, "include_remediation": False}}).json()
    assert len(j["priorities"]) == 1 and j["priorities"][0]["recommended_action"] is None
    assert any("top 1" in l for l in j["limitations"])


def test_score_model_endpoint(client):
    j = client.get("/v1/score-model").json()
    assert j["score_version"] == "v1" and abs(sum(j["dimension_weights"].values()) - 1) < 1e-9


def test_top_level_describes_requested_cve_not_rank1(client, mock):
    """Regression: cve_id=X plus a question mentioning a higher-ranked Y must still report X's CVSS."""
    happy(mock)
    j = client.get("/vuln-triage", params={"cve_id": XZ, "question": f"Rank {XZ} and {LOG4J}"}).json()
    assert j["cve_id"] == XZ and j["cvss_base_score"] == 10.0 and j["top_level_basis"] == "requested_cve"
    assert j["ranking"][0]["cve_id"] == LOG4J  # rank-1 is still Log4Shell, listed in ranking
    j2 = client.get("/vuln-triage", params={"cve_id": f"{MID},{ISO}"}).json()
    assert j2["top_level_basis"] == "rank_1" and j2["cve_id"] == MID  # several explicit ids -> rank 1


def test_telegraph_answer_is_compact_and_score_first(client, mock):
    happy(mock)
    r = client.get("/vuln-triage", params={"cve_id": LOG4J})
    assert list(r.json())[0] == "cvss_base_score" and "details" not in r.json()
    assert len(r.content) < 6000, len(r.content)
    assert len(r.json()["summary"]) < 1200


def test_same_cve_on_two_assets_without_ids_not_merged(client, mock):
    happy(mock)
    j = client.post("/v1/triage", json={"findings": [
        {"cve_id": MID, "asset": {"criticality": "critical", "internet_exposed": True, "environment": "production"}},
        {"cve_id": MID, "asset": {"criticality": "low", "exposure": "isolated", "environment": "development"}}]}).json()
    assert len(j["priorities"]) == 2 and j["priorities"][0]["risk_score"] > j["priorities"][1]["risk_score"]
    assert all(p["duplicates_merged"] == 0 for p in j["priorities"])
