"""SQLite-backed cache for OSINT enrichment results.

OSINT enrichers (DNS, RDAP) make network requests that are slow and rate-limited.
Their results change rarely, so they are cached per host with a configurable TTL
(``osint.cache_ttl_hours``, default 6h). Heuristic analyzers are pure offline
string computation and are intentionally NOT cached — there is no network or CPU
cost worth saving.

The cache is fail-open: any SQLite or OS error is swallowed and treated as a cache
miss (on read) or a no-op (on write). A cache problem must never block analysis.

Thread-safe: a single connection (``check_same_thread=False``) is guarded by a lock
so the cache is safe to share across the batch ThreadPoolExecutor.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Optional

from barb.models import Signal

_APP_DIR = Path.home() / ".barb"
_DEFAULT_DB = _APP_DIR / "cache.db"
_DIR_MODE = 0o700
_FILE_MODE = 0o600

_SCHEMA = """
CREATE TABLE IF NOT EXISTS osint_cache (
    host         TEXT PRIMARY KEY,
    signals_json TEXT NOT NULL,
    cached_at    REAL NOT NULL
)
"""


class OsintCache:
    """Per-host cache of OSINT enricher signals, backed by SQLite."""

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self._db_path = db_path or _DEFAULT_DB
        self._lock = threading.Lock()
        self._conn: Optional[sqlite3.Connection] = None
        self._connect()

    def _connect(self) -> None:
        """Open the SQLite connection and ensure schema + secure file permissions."""
        try:
            self._db_path.parent.mkdir(mode=_DIR_MODE, parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(self._db_path), check_same_thread=False, timeout=5.0)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute(_SCHEMA)
            self._conn.commit()
            try:
                self._db_path.chmod(_FILE_MODE)
            except OSError:
                pass  # Permission tightening is best-effort
        except (sqlite3.Error, OSError):
            self._conn = None  # Fail-open: behave as a disabled cache

    def get(self, host: str, ttl_seconds: float) -> Optional[list[Signal]]:
        """Return cached signals for ``host`` if present and fresh, else ``None``.

        A cached empty list is a valid hit (the host was enriched and produced no
        signals) and is returned as ``[]``, distinct from a miss (``None``).
        """
        if self._conn is None:
            return None
        key = host.lower()
        try:
            with self._lock:
                row = self._conn.execute(
                    "SELECT signals_json, cached_at FROM osint_cache WHERE host = ?",
                    (key,),
                ).fetchone()
        except sqlite3.Error:
            return None
        if row is None:
            return None
        signals_json, cached_at = row
        if time.time() - cached_at >= ttl_seconds:
            return None  # Expired
        try:
            raw = json.loads(signals_json)
            return [Signal.model_validate(item) for item in raw]
        except (json.JSONDecodeError, ValueError, TypeError):
            return None  # Corrupt row — treat as miss

    def set(self, host: str, signals: list[Signal]) -> None:
        """Store ``signals`` for ``host`` with the current timestamp."""
        if self._conn is None:
            return
        key = host.lower()
        try:
            payload = json.dumps([s.model_dump(mode="json") for s in signals])
        except (TypeError, ValueError):
            return
        try:
            with self._lock:
                self._conn.execute(
                    "INSERT OR REPLACE INTO osint_cache (host, signals_json, cached_at) VALUES (?, ?, ?)",
                    (key, payload, time.time()),
                )
                self._conn.commit()
        except sqlite3.Error:
            pass  # Fail-open

    def clear(self) -> None:
        """Remove all cached entries."""
        if self._conn is None:
            return
        try:
            with self._lock:
                self._conn.execute("DELETE FROM osint_cache")
                self._conn.commit()
        except sqlite3.Error:
            pass

    def close(self) -> None:
        """Close the underlying connection."""
        if self._conn is not None:
            try:
                self._conn.close()
            finally:
                self._conn = None


_default_cache: Optional[OsintCache] = None
_default_lock = threading.Lock()


def get_cache() -> OsintCache:
    """Return the process-wide default OSINT cache (lazily created)."""
    global _default_cache
    with _default_lock:
        if _default_cache is None:
            _default_cache = OsintCache()
        return _default_cache
