import httpx
import pytest
import respx

from app.review.deps import _detail_from_osv, parse_manifests, scan_dependencies
from app.review.secrets import scan_code_patterns, scan_secrets
from app.sources.base import Fetcher

AKIA = "AKIA" + "IOSFODNN7EXAMPLE"  # split so this file itself is not a secret


def test_parse_manifests_pins_and_unpinned():
    files = {
        "requirements.txt": "flask==2.0.1\nrequests>=2\n# c\nnumpy[extra]==1.2.3 ; python_version>'3'\n-r other.txt\n",
        "web/package-lock.json": '{"packages":{"":{},"node_modules/lodash":{"version":"4.17.15"},"node_modules/a/node_modules/b":{"version":"1.0.0"}}}',
        "web/package.json": '{"dependencies":{"lodash":"^4.0.0"}}',
        "go.mod": "module x\nrequire (\n\tgithub.com/gin-gonic/gin v1.7.0\n)\n",
        "Gemfile.lock": "GEM\n  specs:\n    rails (6.0.0)\n      actionpack (= 6.0.0)\n",
    }
    pkgs, unpinned, manifests = parse_manifests(files)
    names = {(e, n, v) for e, n, v, _ in pkgs}
    assert ("PyPI", "flask", "2.0.1") in names and ("PyPI", "numpy", "1.2.3") in names
    assert ("npm", "lodash", "4.17.15") in names and ("npm", "b", "1.0.0") in names
    assert ("Go", "github.com/gin-gonic/gin", "1.7.0") in names and ("RubyGems", "rails", "6.0.0") in names
    assert unpinned == 1  # requests>=2 ; package.json skipped because a lockfile exists
    assert not any(p[3] == "web/package.json" for p in pkgs)


def test_osv_detail_fixed_and_label():
    d = _detail_from_osv({"id": "GHSA-x", "aliases": ["CVE-2021-44228"], "summary": "RCE", "database_specific": {"severity": "CRITICAL"},
                          "affected": [{"package": {"name": "Flask"}, "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.2.5"}]}]}]})
    assert d.cves == ["CVE-2021-44228"] and d.label == "critical" and d.fixed == {"flask": ["2.2.5"]}


def test_secrets_redacted_and_placeholders_ignored():
    files = {"app/config.py": f'AWS="{AKIA}"\nPASSWORD = "changeme"\napi_key = "s3cr3t-value-123456"\n',
             "tests/test_x.py": f'k="{AKIA}"', ".env": "A=1", ".env.example": "A=1"}
    out = {f.id: f for f in scan_secrets(files)}
    aws = out["secret:aws-access-key"]
    assert aws.severity == "critical" and "IOSFODNN7EXAMPLE" not in str(aws.to_dict()) and aws.evidence[0]["match"].startswith("AKIA")
    assert len(aws.evidence) == 1 and aws.evidence[0]["path"] == "app/config.py"
    assert "secret:generic-secret" in out and out["secret:generic-secret"].evidence[0]["line"] == 3
    assert "secret-env-file:.env" in out and "secret-env-file:.env.example" not in out


def test_only_test_path_secret_is_low():
    out = scan_secrets({"tests/test_x.py": f'k="{AKIA}"'})
    assert out[0].severity == "low" and out[0].confidence == "low"


def test_code_patterns_and_scope():
    files = {"a.py": "import requests\nrequests.get(u, verify=False)\ncur.execute(f\"select * from t where id={x}\")\nx = eval(user)\nDEBUG = True\n",
             "b.js": "el.innerHTML = userInput;\nconst s = 'safe';",
             "tests/t.py": "requests.get(u, verify=False)", "c.md": "verify=False in docs"}
    ids = {f.id: f for f in scan_code_patterns(files)}
    assert {"code:tls-verify-off", "code:sql-string-format", "code:eval-exec", "code:debug-on", "code:xss-sink"} <= set(ids)
    assert ids["code:tls-verify-off"].evidence[0]["path"] == "a.py" and ids["code:tls-verify-off"].detail["locations"] == 1


@pytest.mark.asyncio
@respx.mock
async def test_scan_dependencies_end_to_end_with_triage_stub():
    from app.models import Priority
    respx.post("https://api.osv.dev/v1/querybatch").respond(200, json={"results": [{"vulns": [{"id": "GHSA-aaaa"}]}, {}]})
    respx.get("https://api.osv.dev/v1/vulns/GHSA-aaaa").respond(200, json={
        "id": "GHSA-aaaa", "aliases": ["CVE-2021-44228"], "summary": "Log4Shell", "database_specific": {"severity": "CRITICAL"},
        "affected": [{"package": {"name": "log4j"}, "ranges": [{"events": [{"fixed": "2.17.1"}]}]}]})

    async def triage(ids):
        assert ids == ["CVE-2021-44228"]
        sig = {"kev": {"listed": True}, "cvss": {"score": 10.0}, "epss": {"probability": 0.97}}
        return {"CVE-2021-44228": Priority.model_construct(status="scored", priority="critical", risk_score=95.0, signals=sig, why_ranked_here=["KEV-listed"])}
    async with httpx.AsyncClient() as c:
        scan = await scan_dependencies({"requirements.txt": "log4j==2.14.0\nflask==2.0.0\n"}, Fetcher(c, retries=0), triage)
    assert scan.vuln_count == 1 and scan.coverage["osv"] == "ok"
    f = scan.findings[0]
    assert f.severity == "critical" and f.score == 95.0 and "CISA-KEV" in f.tags and "2.17.1" in f.fix and f.cves == ["CVE-2021-44228"]


@pytest.mark.asyncio
@respx.mock
async def test_osv_outage_is_reported_not_hidden():
    respx.post("https://api.osv.dev/v1/querybatch").respond(503)
    async with httpx.AsyncClient() as c:
        scan = await scan_dependencies({"requirements.txt": "flask==2.0.0\n"}, Fetcher(c, retries=0, backoff_base=0), lambda ids: None)
    assert scan.coverage["osv"].startswith("unavailable") and scan.vuln_count == 0 and scan.findings == []
