import io
import zipfile

import httpx
import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from tests.conftest import EPSS, KEV, NVD
from tests.fixtures import data

LOG4J = "CVE-2021-44228"
AKIA = "AKIA" + "IOSFODNN7EXAMPLE"


def zip_bytes(files: dict[str, str]) -> bytes:
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        for k, v in files.items():
            z.writestr("shop-main/" + k, v)
    return b.getvalue()


SHOP_REPO = {
    "requirements.txt": "log4j==2.14.0\n",
    "app/config.py": f'AWS_KEY = "{AKIA}"\nDEBUG = True\n',
    "templates/index.html": '<html><head><script src="https://www.googletagmanager.com/gtag/js"></script></head><body>add to cart '
                            '<a href="mailto:care@shop.example">care@shop.example</a></body></html>',
}


@pytest.fixture
def client(settings, mock):
    app = create_app(settings)
    with TestClient(app) as c:
        async def resolver(host):
            return {"shop.example": ["93.184.216.34"], "internal.example": ["10.0.0.9"]}.get(host) or (_ for _ in ()).throw(OSError("nx"))
        c.app.state.review.safe.resolver = resolver
        yield c


def upstream(mock):
    mock.get(NVD).respond(200, json=data.nvd(LOG4J, 10.0, exploit_ref=True))
    mock.get(KEV).respond(200, json=data.kev({LOG4J: {"ransomware": True}}))
    mock.get(EPSS).respond(200, json=data.epss({LOG4J: (0.97, 1.0)}))
    mock.post("https://api.osv.dev/v1/querybatch").respond(200, json={"results": [{"vulns": [{"id": "GHSA-jfh8-c2jp-5v3q"}]}]})
    mock.get("https://api.osv.dev/v1/vulns/GHSA-jfh8-c2jp-5v3q").respond(200, json={
        "id": "GHSA-jfh8-c2jp-5v3q", "aliases": [LOG4J], "summary": "Log4Shell RCE", "database_specific": {"severity": "CRITICAL"},
        "affected": [{"package": {"name": "log4j"}, "ranges": [{"events": [{"fixed": "2.17.1"}]}]}]})


def test_repo_review_end_to_end(client, mock):
    upstream(mock)
    mock.get("https://codeload.github.com/acme/shop/zip/HEAD").respond(200, content=zip_bytes(SHOP_REPO))
    r = client.get("/launch-review", params={"target": "github.com/acme/shop", "country": "EU, India", "sector": "ecommerce"})
    assert r.status_code == 200
    j = r.json()
    assert j["verdict"] == "Insecure" and isinstance(j["vulnerability_count"], int) and j["vulnerability_count"] >= 3
    assert LOG4J in j["issues"] and j["summary"] and j["launch_readiness"] == "blocked"
    first = j["fix_first"][0]
    assert first["rank"] == 1 and first["category"] == "security" and LOG4J in first["cves"] and "2.17.1" in first["fix"]
    assert first["detail"]["kev_listed"] is True and any("GDPR Art. 32" in s for s in first["detail"]["legal_relevance"])
    text = r.text
    assert AKIA not in text and "IOSFODNN7EXAMPLE" not in text         # secrets are never echoed
    ids = {c["id"]: c["status"] for c in j["compliance"]["checklist"]}
    assert ids["eu-cookie-consent"] == "not_detected" and ids["eu-privacy-notice"] == "not_detected"
    assert "us-privacy-policy" not in ids                               # not requested
    assert j["target"]["jurisdictions"] == ["eu", "india"] and j["target"]["sector"] == "ecommerce"
    assert j["scan_coverage"]["repo"]["fetched"] and j["scan_coverage"]["dependencies"]["osv"] == "ok"
    assert "not legal advice" in j["disclaimer"].lower() and j["compliance"]["legal_exposure"]


def test_site_review_headers_and_policy_pages(client, mock):
    home = ('<html lang="en"><body><a href="/privacy">Privacy Policy</a> <a href="/refund-policy">Returns</a>'
            '<img src="http://cdn.shop.example/a.png"></body></html>')
    mock.get("https://93.184.216.34/").respond(200, text=home, headers={"content-type": "text/html", "set-cookie": "sid=abc; Path=/"})
    mock.get("https://93.184.216.34/privacy").respond(200, text="<html lang=en>We value privacy. Contact privacy@shop.example</html>", headers={"content-type": "text/html"})
    mock.get("https://93.184.216.34/refund-policy").respond(200, text="<html lang=en>14-day right of withdrawal</html>", headers={"content-type": "text/html"})
    j = client.get("/launch-review", params={"target": "https://shop.example eu ecommerce"}).json()
    assert j["scan_coverage"]["site"]["fetched"] and j["scan_coverage"]["site"]["pages_read"] == 3
    ids = {c["id"]: c["status"] for c in j["compliance"]["checklist"]}
    assert ids["eu-privacy-notice"] == "passed" and ids["eu-withdrawal-info"] == "passed"
    sec = {f["id"] for f in j["fix_first"] if f["category"] == "security"}
    assert {"site:no-hsts", "site:cookie-flags", "site:mixed-content"} <= sec
    assert j["verdict"] == "Needs changes"


def test_unreachable_targets_are_soft_and_never_scanned_as_secure(client, mock):
    mock.get("https://codeload.github.com/acme/private/zip/HEAD").respond(404)
    j = client.get("/launch-review", params={"target": "github.com/acme/private"}).json()
    assert j["verdict"] is None and j["vulnerability_count"] is None and j["scan_coverage"]["repo"]["fetched"] is False
    j2 = client.get("/launch-review", params={"target": "http://internal.example/"}).json()
    assert j2["verdict"] is None and "non-public" in j2["scan_coverage"]["site"]["reason"]
    j3 = client.get("/launch-review", params={"target": "http://169.254.169.254/latest"}).json()
    assert j3["verdict"] is None and j3["scan_coverage"]["site"]["fetched"] is False


def test_no_target_gets_helpful_200(client):
    r = client.get("/launch-review", params={"target": "please review my app"})
    j = r.json()
    assert r.status_code == 200 and j["status"] == "no_target" and "github.com/owner/repo" in j["answer"]
    assert client.get("/launch-review").json()["status"] == "no_target"


def test_clean_repo_is_secure_only_when_something_was_scanned(client, mock):
    mock.get("https://codeload.github.com/acme/clean/zip/HEAD").respond(200, content=zip_bytes({"README.md": "hello"}))
    j = client.get("/launch-review", params={"target": "github.com/acme/clean us saas"}).json()
    assert j["verdict"] == "Secure" and j["vulnerability_count"] == 0 and j["launch_readiness"] == "conditional"
    pn = next(c for c in j["compliance"]["checklist"] if c["id"] == "us-privacy-policy")
    assert pn["status"] == "not_detected" and pn["confidence"] == "low" and "No web pages" in pn["caveat"]
