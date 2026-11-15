"""Tiny TTL cache: in-memory front, optional SQLite persistence.

Only public enrichment data is ever stored here (never customer findings or asset context).
The SQLite file is a cache, not a record: losing it just costs a few upstream calls.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


@dataclass
class CacheEntry:
    value: Any
    stored_at: float
    expires_at: float

    def fresh(self, now: float) -> bool:
        return now < self.expires_at


class Cache:
    def __init__(self, path: str | None = None, clock: Callable[[], float] = time.time):
        self._mem: dict[str, CacheEntry] = {}
        self._clock = clock
        self._lock = threading.Lock()
        self._db: sqlite3.Connection | None = None
        if path:
            try:
                Path(path).parent.mkdir(parents=True, exist_ok=True)
                self._db = sqlite3.connect(path, check_same_thread=False)
                self._db.execute("PRAGMA journal_mode=WAL")
                self._db.execute(
                    "CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT NOT NULL,"
                    " stored_at REAL NOT NULL, expires_at REAL NOT NULL)"
                )
                self._db.commit()
            except Exception:  # cache must never take the service down
                self._db = None

    def now(self) -> float:
        return self._clock()

    def get(self, key: str) -> CacheEntry | None:
        with self._lock:
            hit = self._mem.get(key)
            if hit:
                return hit
            if self._db:
                try:
                    row = self._db.execute(
                        "SELECT v, stored_at, expires_at FROM kv WHERE k=?", (key,)
                    ).fetchone()
                except Exception:
                    row = None
                if row:
                    entry = CacheEntry(json.loads(row[0]), row[1], row[2])
                    self._mem[key] = entry
                    return entry
        return None

    def set(self, key: str, value: Any, ttl: float) -> CacheEntry:
        now = self._clock()
        entry = CacheEntry(value, now, now + ttl)
        with self._lock:
            self._mem[key] = entry
            if self._db:
                try:
                    self._db.execute(
                        "INSERT OR REPLACE INTO kv (k, v, stored_at, expires_at) VALUES (?,?,?,?)",
                        (key, json.dumps(value), entry.stored_at, entry.expires_at),
                    )
                    self._db.commit()
                except Exception:
                    pass
        return entry
