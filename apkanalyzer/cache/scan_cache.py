"""
Incremental scan cache backed by SQLite.

Keyed by SHA-256 hash of the APK file.  If the same APK binary is submitted
again (or re-scanned via CLI) the cached report is returned instantly.

Cache location: ~/.apkanalyzer/cache.db  (user-local, survives across runs)
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import threading
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_DEFAULT_DB = Path.home() / ".apkanalyzer" / "cache.db"

# New deployments use a composite key so the same APK can be re-cached
# under different rule versions without colliding. Old single-PK databases
# are migrated in _init_db().
_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS scan_cache (
    sha256         TEXT NOT NULL,
    rules_version  TEXT NOT NULL DEFAULT '',
    apk_name       TEXT,
    scanned_at     TEXT DEFAULT (datetime('now')),
    report_json    TEXT NOT NULL,
    PRIMARY KEY (sha256, rules_version)
);
"""

_INDEX = "CREATE INDEX IF NOT EXISTS idx_scanned ON scan_cache(scanned_at);"


class ScanCache:
    """Thread-safe SQLite scan cache."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        self._db_path = Path(db_path) if db_path else _DEFAULT_DB
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(_CREATE_TABLE)
                conn.execute(_INDEX)
                # Migrate older databases that were keyed on sha256 alone.
                cols = {r["name"] for r in conn.execute("PRAGMA table_info(scan_cache)").fetchall()}
                if "rules_version" not in cols:
                    # Old schema; drop and recreate. Cached reports from a
                    # different rule set would be stale anyway.
                    conn.execute("DROP TABLE scan_cache")
                    conn.execute(_CREATE_TABLE)
                    conn.execute(_INDEX)
                conn.commit()
            finally:
                conn.close()

    # Cached rules-digest. Computed once per process; YAML edits during a
    # long-running web server require a process restart to invalidate, which
    # matches our deployment model (cache lives on disk, server is reloaded
    # by SIGHUP / supervisor).
    _RULES_DIGEST: Optional[str] = None

    @classmethod
    def _current_rules_version(cls) -> str:
        """
        Cache key component that captures both the package's RULES_VERSION
        constant *and* the actual YAML rule content. Editing a YAML file
        without bumping the constant must still invalidate cached reports;
        otherwise users get stale results when they tune detectors.
        """
        # Imported lazily so cache can be loaded without the full package.
        from apkanalyzer import RULES_VERSION

        if cls._RULES_DIGEST is None:
            cls._RULES_DIGEST = cls._compute_rules_digest()
        return f"{RULES_VERSION}:{cls._RULES_DIGEST}"

    @staticmethod
    def _compute_rules_digest() -> str:
        """SHA-256 over the sorted (path, contents) of every rules/*.yaml file.
        Returns "0" if the rules directory is missing — keeps cache usable
        for environments that ship without YAML rules."""
        # Resolve the rules directory the same way RuleEngine does.
        rules_dir = Path(__file__).resolve().parent.parent.parent / "rules"
        if not rules_dir.is_dir():
            return "0"
        h = hashlib.sha256()
        try:
            for yaml_file in sorted(rules_dir.glob("*.yaml")):
                h.update(yaml_file.name.encode("utf-8"))
                h.update(b"\0")
                try:
                    h.update(yaml_file.read_bytes())
                except OSError:
                    continue
                h.update(b"\0")
        except OSError:
            return "0"
        return h.hexdigest()[:16]

    @classmethod
    def reset_rules_digest(cls) -> None:
        """Invalidate the in-memory rules digest. Test hook / SIGHUP path."""
        cls._RULES_DIGEST = None

    @staticmethod
    def _sha256(apk_path: str) -> str:
        h = hashlib.sha256()
        with open(apk_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    def get(self, apk_path: str) -> Optional[dict]:
        """Return cached report dict if the APK was previously scanned under
        the current rule set, else None."""
        try:
            sha = self._sha256(apk_path)
        except OSError:
            return None
        rules_version = self._current_rules_version()

        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT report_json FROM scan_cache "
                    "WHERE sha256 = ? AND rules_version = ?",
                    (sha, rules_version),
                ).fetchone()
                if row:
                    logger.debug("Cache hit for %s (%s, rules=%s)",
                                 apk_path, sha[:12], rules_version)
                    return json.loads(row["report_json"])
            except Exception as exc:
                logger.warning("Cache read error: %s", exc)
            finally:
                conn.close()
        return None

    def put(self, apk_path: str, report: dict) -> None:
        """Store a report in the cache keyed by APK SHA-256 + rules_version."""
        try:
            sha = self._sha256(apk_path)
        except OSError:
            return

        apk_name = Path(apk_path).name
        rules_version = self._current_rules_version()
        try:
            report_json = json.dumps(report, default=str)
        except Exception as exc:
            logger.warning("Cache serialise error: %s", exc)
            return

        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """INSERT OR REPLACE INTO scan_cache
                       (sha256, rules_version, apk_name, report_json)
                       VALUES (?, ?, ?, ?)""",
                    (sha, rules_version, apk_name, report_json),
                )
                conn.commit()
                logger.debug("Cached report for %s (%s, rules=%s)",
                             apk_name, sha[:12], rules_version)
            except Exception as exc:
                logger.warning("Cache write error: %s", exc)
            finally:
                conn.close()

    def list_entries(self) -> list[dict]:
        """Return all cached entries as a list of dicts (no report body)."""
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT sha256, rules_version, apk_name, scanned_at "
                    "FROM scan_cache ORDER BY scanned_at DESC"
                ).fetchall()
                return [dict(r) for r in rows]
            except Exception as exc:
                logger.warning("Cache list error: %s", exc)
                return []
            finally:
                conn.close()

    def invalidate(self, apk_path: str) -> None:
        """Remove every cached entry for the given APK (across rule versions)."""
        try:
            sha = self._sha256(apk_path)
        except OSError:
            return
        with self._lock:
            conn = self._connect()
            try:
                conn.execute("DELETE FROM scan_cache WHERE sha256 = ?", (sha,))
                conn.commit()
            finally:
                conn.close()

    def clear(self) -> None:
        """Wipe the entire cache."""
        with self._lock:
            conn = self._connect()
            try:
                conn.execute("DELETE FROM scan_cache")
                conn.commit()
            finally:
                conn.close()
