"""
Persistent state for the web app's scan registry.

Replaces the in-memory `_scans: dict` so that scan status survives a server
restart and so that multiple gunicorn workers can see each other's state.

Live state (queues, callbacks) cannot be serialised, so it stays in memory;
this module only persists durable fields: status, error, filename, timestamps,
and a pointer to the on-disk report.

Schema
------
scans(scan_id TEXT PK, filename TEXT, package TEXT, status TEXT,
      error TEXT, started_at INTEGER, completed_at INTEGER,
      total INTEGER, critical INTEGER, high INTEGER, grade TEXT,
      report_path TEXT)
"""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path
from typing import Optional

_DEFAULT_DB = Path(__file__).parent / "scan_store.db"

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id      TEXT PRIMARY KEY,
    filename     TEXT,
    package      TEXT,
    status       TEXT NOT NULL DEFAULT 'queued',
    error        TEXT,
    started_at   INTEGER,
    completed_at INTEGER,
    total        INTEGER DEFAULT 0,
    critical     INTEGER DEFAULT 0,
    high         INTEGER DEFAULT 0,
    medium       INTEGER DEFAULT 0,
    low          INTEGER DEFAULT 0,
    grade        TEXT,
    target_sdk   TEXT,
    min_sdk      TEXT,
    duration     INTEGER DEFAULT 0,
    by_owasp     TEXT,
    report_path  TEXT
);
"""

_INDEX = "CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started_at);"

# Columns added after the original v1 schema. We try to add them on every
# open; SQLite raises OperationalError if the column already exists, which
# we silently swallow. Cheaper than maintaining a migration table for a
# single-file SQLite store.
_ADD_COLUMNS = [
    "ALTER TABLE scans ADD COLUMN medium INTEGER DEFAULT 0",
    "ALTER TABLE scans ADD COLUMN low INTEGER DEFAULT 0",
    "ALTER TABLE scans ADD COLUMN target_sdk TEXT",
    "ALTER TABLE scans ADD COLUMN min_sdk TEXT",
    "ALTER TABLE scans ADD COLUMN duration INTEGER DEFAULT 0",
    "ALTER TABLE scans ADD COLUMN by_owasp TEXT",
]


class ScanStore:
    def __init__(self, db_path: Optional[str] = None) -> None:
        self._db_path = Path(db_path) if db_path else _DEFAULT_DB
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with self._connect() as conn:
            conn.execute(_CREATE_TABLE)
            conn.execute(_INDEX)
            for stmt in _ADD_COLUMNS:
                try:
                    conn.execute(stmt)
                except sqlite3.OperationalError:
                    pass  # column already present
            conn.commit()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def insert(self, scan_id: str, filename: str, started_at: int) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO scans (scan_id, filename, status, started_at) "
                "VALUES (?, ?, 'queued', ?)",
                (scan_id, filename, started_at),
            )
            conn.commit()

    def update_status(
        self,
        scan_id: str,
        status: str,
        error: Optional[str] = None,
        package: Optional[str] = None,
        completed_at: Optional[int] = None,
        total: Optional[int] = None,
        critical: Optional[int] = None,
        high: Optional[int] = None,
        medium: Optional[int] = None,
        low: Optional[int] = None,
        grade: Optional[str] = None,
        target_sdk: Optional[str] = None,
        min_sdk: Optional[str] = None,
        duration: Optional[int] = None,
        by_owasp: Optional[str] = None,
        report_path: Optional[str] = None,
    ) -> None:
        sets = ["status = ?"]
        args: list = [status]
        for col, val in (
            ("error", error), ("package", package),
            ("completed_at", completed_at),
            ("total", total), ("critical", critical),
            ("high", high), ("medium", medium), ("low", low),
            ("grade", grade),
            ("target_sdk", target_sdk), ("min_sdk", min_sdk),
            ("duration", duration), ("by_owasp", by_owasp),
            ("report_path", report_path),
        ):
            if val is not None:
                sets.append(f"{col} = ?")
                args.append(val)
        args.append(scan_id)

        with self._lock, self._connect() as conn:
            conn.execute(
                f"UPDATE scans SET {', '.join(sets)} WHERE scan_id = ?",
                args,
            )
            conn.commit()

    def get(self, scan_id: str) -> Optional[dict]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM scans WHERE scan_id = ?", (scan_id,)
            ).fetchone()
            return dict(row) if row else None

    def list_recent(self, limit: int = 100, status: Optional[str] = None) -> list[dict]:
        """
        Most recent first. Pass status='done' to limit to completed scans
        (the listing routes only want to surface those).
        """
        with self._connect() as conn:
            if status:
                rows = conn.execute(
                    "SELECT * FROM scans WHERE status = ? ORDER BY started_at DESC LIMIT ?",
                    (status, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM scans ORDER BY started_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            return [dict(r) for r in rows]
