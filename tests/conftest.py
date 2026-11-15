from __future__ import annotations

import httpx
import pytest
import respx

from app.config import Settings
from app.main import build_service

NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS = "https://api.first.org/data/v1/epss"


def cvedb_url(c: str) -> str:
    return f"https://cvedb.shodan.io/cve/{c}"


@pytest.fixture
def settings() -> Settings:
    return Settings(cache_db_path=None, warm_enabled=False, backoff_base_sec=0.0, source_retries=1,
                    nvd_soft_timeout_sec=0.3, nvd_timeout_sec=2.0, source_timeout_sec=1.0, request_deadline_sec=5.0,
                    nvd_rate_calls=1000)


@pytest.fixture
def mock():
    with respx.mock(assert_all_called=False) as m:
        yield m


@pytest.fixture
async def svc(settings, mock):
    async with httpx.AsyncClient() as client:
        service, cache, fetcher = build_service(settings, client)
        service.fetcher, service.cache_ = fetcher, cache
        yield service
