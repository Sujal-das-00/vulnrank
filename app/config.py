"""Runtime configuration. Everything tunable comes from the environment."""
from __future__ import annotations

import os
from dataclasses import dataclass

ENGINE_VERSION = "0.1.0"
SCORE_VERSION = "v1"


def _float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, default))
    except ValueError:
        return default


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    nvd_api_key: str | None = None
    cache_db_path: str | None = "data/cache.sqlite3"
    max_batch_size: int = 100
    request_deadline_sec: float = 12.0
    # NVD keyless allows ~5 requests / rolling 30s; with a key ~50.
    nvd_rate_calls: int = 5
    nvd_rate_period_sec: float = 30.0
    nvd_soft_timeout_sec: float = 1.5  # after this, race a fallback source (target latency < 2s)
    nvd_timeout_sec: float = 25.0     # NVD keyless is often 10s+; background refresh keeps going
    source_timeout_sec: float = 6.0
    warm_enabled: bool = True
    warm_budget_fraction: float = 0.5  # share of the NVD rate budget the warmer may use
    source_retries: int = 2
    backoff_base_sec: float = 0.4
    breaker_threshold: int = 5
    breaker_cooldown_sec: float = 30.0
    # cache TTLs (seconds)
    ttl_kev: int = 6 * 3600
    ttl_epss: int = 12 * 3600
    ttl_nvd: int = 24 * 3600
    ttl_not_found: int = 3600
    ttl_cvedb: int = 12 * 3600
    max_concurrency: int = 4
    log_level: str = "INFO"

    @classmethod
    def from_env(cls) -> "Settings":
        key = os.getenv("NVD_API_KEY") or None
        db = os.getenv("CACHE_DB_PATH", "data/cache.sqlite3") or None
        return cls(
            nvd_api_key=key,
            cache_db_path=db,
            max_batch_size=_int("MAX_BATCH_SIZE", 100),
            request_deadline_sec=_float("REQUEST_DEADLINE_SEC", 12.0),
            nvd_rate_calls=50 if key else 5,
            warm_enabled=os.getenv("WARM_ENABLED", "1") != "0",
            log_level=os.getenv("LOG_LEVEL", "INFO"),
        )
