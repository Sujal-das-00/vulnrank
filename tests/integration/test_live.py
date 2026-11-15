"""Manual smoke tests against the real upstream APIs:  pytest -m live -s"""
import httpx
import pytest

from app.config import Settings
from app.main import build_service
from app.models import Finding

pytestmark = pytest.mark.live


async def test_live_log4shell():
    s = Settings(cache_db_path=None, warm_enabled=False)
    async with httpx.AsyncClient() as c:
        svc, *_ = build_service(s, c)
        r = await svc.run([Finding(cve_id="CVE-2021-44228")])
    p = r.priorities[0]
    print(r.source_status, p.signals["cvss"], p.signals["kev"], p.signals["epss"])
    assert p.signals["cvss"]["score"] == 10.0 and p.signals["kev"]["listed"] is True and p.priority == "critical"
