"""
Chronos-DFIR Enrichment Cache — SQLite TTL-based cache for IOC lookups.

Stores API responses with per-provider TTL to avoid hitting rate limits.
Thread-safe for use with asyncio.to_thread().
"""

import sqlite3
import json
import time
import threading
import logging
import os
from typing import Optional

logger = logging.getLogger("chronos.enrichment.cache")

# Default TTLs per provider (hours)
DEFAULT_TTLS = {
    "ip_api": 168,       # 7 days — geo rarely changes
    "abuseipdb": 24,     # 1 day
    "virustotal": 12,    # 12 hours
    "urlhaus": 6,        # 6 hours — fast-moving threat data
    "urlscan": 12,       # 12 hours
    "hibp": 48,          # 2 days
}


class EnrichmentCache:
    """SQLite-backed TTL cache for threat intelligence API results."""

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            base = os.environ.get("CHRONOS_DATA_DIR", "chronos_output")
            os.makedirs(base, exist_ok=True)
            db_path = os.path.join(base, ".enrichment_cache.db")

        self._db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self):
        with self._lock:
            conn = sqlite3.connect(self._db_path, check_same_thread=False)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ioc_cache (
                    ioc_value   TEXT NOT NULL,
                    ioc_type    TEXT NOT NULL,
                    provider    TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    fetched_at  REAL NOT NULL,
                    ttl_hours   INTEGER NOT NULL,
                    PRIMARY KEY (ioc_value, ioc_type, provider)
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_cache_expiry
                ON ioc_cache (fetched_at, ttl_hours)
            """)
            conn.commit()
            conn.close()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self._db_path, check_same_thread=False)

    def get(self, ioc_value: str, ioc_type: str, provider: str) -> Optional[dict]:
        """Get cached result if exists and not expired. Returns None if miss."""
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    """SELECT result_json, fetched_at, ttl_hours
                       FROM ioc_cache
                       WHERE ioc_value = ? AND ioc_type = ? AND provider = ?""",
                    (ioc_value, ioc_type, provider)
                ).fetchone()

                if row is None:
                    return None

                result_json, fetched_at, ttl_hours = row
                age_hours = (time.time() - fetched_at) / 3600

                if age_hours > ttl_hours:
                    # Expired — delete and return miss
                    conn.execute(
                        """DELETE FROM ioc_cache
                           WHERE ioc_value = ? AND ioc_type = ? AND provider = ?""",
                        (ioc_value, ioc_type, provider)
                    )
                    conn.commit()
                    return None

                return json.loads(result_json)
            finally:
                conn.close()

    def set(self, ioc_value: str, ioc_type: str, provider: str,
            result: dict, ttl_hours: Optional[int] = None):
        """Store or update a cached result."""
        if ttl_hours is None:
            ttl_hours = DEFAULT_TTLS.get(provider, 24)

        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """INSERT OR REPLACE INTO ioc_cache
                       (ioc_value, ioc_type, provider, result_json, fetched_at, ttl_hours)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (ioc_value, ioc_type, provider,
                     json.dumps(result, default=str), time.time(), ttl_hours)
                )
                conn.commit()
            finally:
                conn.close()

    def clear_expired(self) -> int:
        """Remove all expired entries. Returns count of deleted rows."""
        with self._lock:
            conn = self._connect()
            try:
                now = time.time()
                cursor = conn.execute(
                    """DELETE FROM ioc_cache
                       WHERE (? - fetched_at) / 3600.0 > ttl_hours""",
                    (now,)
                )
                conn.commit()
                deleted = cursor.rowcount
                if deleted > 0:
                    logger.info(f"Cache cleanup: {deleted} expired entries removed")
                return deleted
            finally:
                conn.close()

    def stats(self) -> dict:
        """Return cache statistics."""
        with self._lock:
            conn = self._connect()
            try:
                now = time.time()
                total = conn.execute("SELECT COUNT(*) FROM ioc_cache").fetchone()[0]
                expired = conn.execute(
                    "SELECT COUNT(*) FROM ioc_cache WHERE (? - fetched_at) / 3600.0 > ttl_hours",
                    (now,)
                ).fetchone()[0]
                by_provider = {}
                for row in conn.execute(
                    "SELECT provider, COUNT(*) FROM ioc_cache GROUP BY provider"
                ):
                    by_provider[row[0]] = row[1]
                return {
                    "total_entries": total,
                    "expired_entries": expired,
                    "active_entries": total - expired,
                    "by_provider": by_provider,
                }
            finally:
                conn.close()
