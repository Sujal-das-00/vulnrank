import httpx
import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.review.deps import parse_manifests
from app.review.target import looks_like_code, parse_target
from tests.conftest import EPSS, KEV, NVD
from tests.fixtures import data
from tests.review.test_launch_review_api import LOG4J, upstream


@pytest.fixture
def client(settings, mock):
    with TestClient(create_app(settings)) as c:
        yield c


def test_target_shapes():
    t = parse_target("lodash 4.17.15 on npm")
    assert t.packages == [("npm", "lodash", "4.17.15")] and not t.snippet and t.reviewable and not t.legal_requested
    t = parse_target("is django==3.2.0 and left-pad@1.3.0 safe?")
    assert ("PyPI", "django", "3.2.0") in t.packages and ("?", "left-pad", "1.3.0") in t.packages
    t = parse_target("Review:\n```python\nimport os\nos.system(cmd)\n```")
    assert t.snippet and "os.system" in t.snippet and not t.packages
    d = parse_target("diff --git a/x.py b/x.py\n@@ -1 +1 @@\n+x = eval(input())\n-y = 1")
    assert d.snippet.strip() == "x = eval(input())"
    # phrasing seen in real routed asks (bounties issue #187)
    assert parse_target("npm package lodash version 4.17.15").packages == [("npm", "lodash", "4.17.15")]
    assert parse_target("PyPI package django version 3.2.0").packages == [("PyPI", "django", "3.2.0")]
    assert parse_target("Is the Python version 3.8 supported?").packages == []
    assert not parse_target("hello there").reviewable
    assert not looks_like_code("is flask 2.0 safe")


def test_non_app_manifests_are_ignored():
    pk, _, man = parse_manifests({"requirements.txt": "flask==2.0.0\n", "examples/celery/requirements.txt": "old==0.1.0\n", "docs/requirements.txt": "x==1.0.0\n"})
    assert [p[1] for p in pk] == ["flask"] and man == ["requirements.txt"]


def test_package_version_question(client, mock):
    upstream(mock)
    j = client.get("/launch-review", params={"target": "Is log4j 2.14.0 on maven safe? lodash@4.17.15"}).json()
    assert j["verdict"] == "Insecure" and LOG4J in j["issues"] and j["priority"] == "critical" and j["confidence"] == 0.9
    assert j["scan_coverage"]["dependencies"]["osv"] == "ok" and j["compliance"]["checklist"] == [] and "needs a repository" in j["compliance"]["note"]
    assert j["target"]["packages"] and "KEV" in str(j["fix_first"][0]["tags"])


def test_clean_package_is_secure_with_known_ecosystem(client, mock):
    mock.post("https://api.osv.dev/v1/querybatch").respond(200, json={"results": [{}]})
    j = client.get("/launch-review", params={"target": "django==5.1.2"}).json()
    assert j["verdict"] == "Secure" and j["vulnerability_count"] == 0 and j["fix_first"] == []


def test_osv_outage_means_not_determined_not_secure(client, mock):
    mock.post("https://api.osv.dev/v1/querybatch").respond(503)
    j = client.get("/launch-review", params={"target": "flask==2.0.0"}).json()
    assert j["verdict"] is None and j["vulnerability_count"] is None and j["confidence"] == 0.0


def test_code_snippet_is_reviewed_and_secret_not_echoed(client):
    code = ("def f(u, cur):\n    cur.execute(f\"select * from t where id={u}\")\n    requests.get(u, verify=False)\n"
            "    key = 'AKIA" + "IOSFODNN7EXAMPLE'\n")
    j = client.get("/launch-review", params={"target": "Review this:\n" + code}).json()
    assert j["verdict"] == "Insecure" and j["vulnerability_count"] >= 3
    assert {"CWE-89", "CWE-295", "CWE-798"} <= set(j["issues"])
    assert "IOSFODNN7EXAMPLE" not in str(j) and j["compliance"]["checklist"] == []
    assert j["scan_coverage"]["snippet"]["lines"] >= 4


def test_clean_snippet_is_secure_but_caveated(client):
    j = client.get("/launch-review", params={"target": "```python\ndef add(a, b):\n    return a + b\n```"}).json()
    assert j["verdict"] == "Secure" and "not a proof" in j["summary"]


def test_contact_heuristic_never_adds_a_penalty_ceiling():
    import datetime as dt
    from app.review.evidence import Doc, extract_signals
    from app.review.legal import evaluate
    sig = extract_signals([Doc("a.html", "file", "<html lang=en>support@acme.com me@gmail.com privacy policy</html>")])
    res = evaluate(sig, ["eu"], "saas", today=dt.date(2026, 11, 16))
    assert any(c["id"] == "any-contact-consistency" and c["status"] == "not_detected" for c in res.checklist)
    assert all(e["gaps"] == 0 or e["worst"] != "low" for e in res.exposure)
    assert not any("low" == e["worst"] for e in res.exposure)


def test_budget_exhaustion_returns_partial_not_error(settings, mock):
    import dataclasses
    s = dataclasses.replace(settings, review_deadline_sec=0.2)
    mock.get("https://codeload.github.com/acme/slow/zip/HEAD").mock(side_effect=httpx.ReadTimeout("slow"))
    with TestClient(create_app(s)) as c:
        j = c.get("/launch-review", params={"target": "github.com/acme/slow"}).json()
    assert j["verdict"] is None and j["scan_coverage"]["repo"]["fetched"] is False


def test_slow_triage_degrades_to_advisory_labels_not_to_nothing(client, mock):
    import asyncio
    upstream(mock)

    async def slow(*a, **k):
        await asyncio.sleep(30)
    client.app.state.review.triage.run = slow
    client.app.state.review.s = __import__("dataclasses").replace(client.app.state.review.s, review_deadline_sec=4.0)
    j = client.get("/launch-review", params={"target": "log4j==2.14.0"}).json()
    assert j["verdict"] == "Insecure" and j["vulnerability_count"] == 1          # advisory label CRITICAL still reported
    assert "advisory labels" in j["scan_coverage"]["triage"]
    assert j["fix_first"][0]["confidence"] == "medium" and j["scan_seconds"] < 6
