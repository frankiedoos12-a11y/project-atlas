"""Local SQLite store: scan history, cached VirusTotal reports, quarantine records."""

from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from atlas.vt_client import Report

SCHEMA = """
CREATE TABLE IF NOT EXISTS vt_cache (
    kind TEXT NOT NULL,
    target TEXT NOT NULL,
    report TEXT NOT NULL,
    fetched_at TEXT NOT NULL,
    PRIMARY KEY (kind, target)
);
CREATE TABLE IF NOT EXISTS vt_extra (
    kind TEXT NOT NULL,
    target TEXT NOT NULL,
    data TEXT NOT NULL,
    fetched_at TEXT NOT NULL,
    PRIMARY KEY (kind, target)
);
CREATE TABLE IF NOT EXISTS vt_usage (
    day TEXT NOT NULL,
    kind TEXT NOT NULL,
    requests INTEGER NOT NULL DEFAULT 0,
    throttled INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (day, kind)
);
CREATE TABLE IF NOT EXISTS seen_findings (
    key TEXT PRIMARY KEY,
    first_seen TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scanned_at TEXT NOT NULL,
    path TEXT NOT NULL,
    sha256 TEXT,
    verdict TEXT NOT NULL,
    reasons TEXT NOT NULL,
    source_url TEXT,
    action TEXT
);
CREATE TABLE IF NOT EXISTS quarantine (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    quarantined_at TEXT NOT NULL,
    original_path TEXT NOT NULL,
    stored_path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    reason TEXT NOT NULL,
    restored_at TEXT
);
CREATE TABLE IF NOT EXISTS autoruns (
    key TEXT PRIMARY KEY,
    category TEXT NOT NULL,
    name TEXT NOT NULL,
    command TEXT NOT NULL,
    path TEXT,
    verdict TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS file_hashes (
    path TEXT PRIMARY KEY,
    size INTEGER NOT NULL,
    mtime REAL NOT NULL,
    sha256 TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS cleanup_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cleaned_at TEXT NOT NULL,
    category TEXT NOT NULL,
    label TEXT NOT NULL,
    target TEXT,
    how TEXT NOT NULL,
    bytes INTEGER NOT NULL
);
"""

# Columns added after v0.2.0; older databases get them on open.
AUTORUN_DETAIL_COLUMNS = {
    "location": "TEXT", "enabled": "INTEGER", "signer": "TEXT", "sig_status": "TEXT",
    "reasons": "TEXT", "vt_link": "TEXT", "sha256": "TEXT", "checked_at": "TEXT",
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        # The tray, the window and the command line can all use the database at once.
        self._conn = sqlite3.connect(path, check_same_thread=False, timeout=30)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        existing = {r["name"] for r in self._conn.execute("PRAGMA table_info(autoruns)")}
        for column, sql_type in AUTORUN_DETAIL_COLUMNS.items():
            if column not in existing:
                self._conn.execute(f"ALTER TABLE autoruns ADD COLUMN {column} {sql_type}")
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    # --- VirusTotal cache -------------------------------------------------

    def cached_report(self, kind: str, target: str, max_age_hours: int) -> Report | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT report, fetched_at FROM vt_cache WHERE kind = ? AND target = ?", (kind, target)
            ).fetchone()
        if row is None:
            return None
        if _now() - datetime.fromisoformat(row["fetched_at"]) > timedelta(hours=max_age_hours):
            return None
        return Report(**json.loads(row["report"]))

    def cache_report(self, report: Report) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO vt_cache (kind, target, report, fetched_at) VALUES (?, ?, ?, ?)",
                (report.kind, report.target, json.dumps(asdict(report)), _now().isoformat()),
            )

    def forget_report(self, kind: str, target: str) -> None:
        """Drop a cached report so the next lookup asks VirusTotal again."""
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM vt_cache WHERE kind = ? AND target = ?", (kind, target))
            self._conn.execute("DELETE FROM vt_extra WHERE target = ?", (target,))

    def cached_extra(self, kind: str, target: str, max_age_hours: int):
        """Other VirusTotal answers kept as JSON (e.g. "behaviour"), or None if missing or stale."""
        with self._lock:
            row = self._conn.execute(
                "SELECT data, fetched_at FROM vt_extra WHERE kind = ? AND target = ?", (kind, target)
            ).fetchone()
        if row is None or _now() - datetime.fromisoformat(row["fetched_at"]) > timedelta(hours=max_age_hours):
            return None
        return json.loads(row["data"])

    def cache_extra(self, kind: str, target: str, data) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO vt_extra (kind, target, data, fetched_at) VALUES (?, ?, ?, ?)",
                (kind, target, json.dumps(data), _now().isoformat()),
            )

    # --- VirusTotal usage (the quota meter) ----------------------------------

    def count_vt_request(self, kind: str, status: int) -> None:
        """One request Atlas sent to VirusTotal, counted per local day and kind ("files", "domains", ...)."""
        day = datetime.now().strftime("%Y-%m-%d")
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO vt_usage (day, kind, requests, throttled) VALUES (?, ?, 1, ?)"
                " ON CONFLICT(day, kind) DO UPDATE SET requests = requests + 1, throttled = throttled + excluded.throttled",
                (day, kind, int(status == 429)))

    def vt_usage(self, since_day: str) -> dict[str, tuple[int, int]]:
        """kind -> (requests, of which throttled) from since_day (YYYY-MM-DD) on."""
        with self._lock:
            rows = self._conn.execute("SELECT kind, SUM(requests), SUM(throttled) FROM vt_usage WHERE day >= ?"
                                      " GROUP BY kind", (since_day,)).fetchall()
        return {r[0]: (r[1], r[2]) for r in rows}

    # --- Findings already reported (system checks) -----------------------------

    def new_findings(self, keys: list[str]) -> list[str]:
        """Which of these keys haven't been seen before. Records them all as seen."""
        now = _now().isoformat()
        with self._lock, self._conn:
            seen = {r[0] for r in self._conn.execute("SELECT key FROM seen_findings")}
            fresh = [k for k in dict.fromkeys(keys) if k not in seen]
            self._conn.executemany("INSERT OR IGNORE INTO seen_findings (key, first_seen) VALUES (?, ?)",
                                   [(k, now) for k in fresh])
        return fresh

    def has_seen_findings(self) -> bool:
        with self._lock:
            return self._conn.execute("SELECT 1 FROM seen_findings LIMIT 1").fetchone() is not None

    # --- Scan history -----------------------------------------------------

    def record_scan(self, path: str, sha256: str | None, verdict: str, reasons: list[str],
                    source_url: str | None, action: str | None) -> int:
        with self._lock, self._conn:
            cur = self._conn.execute(
                "INSERT INTO scans (scanned_at, path, sha256, verdict, reasons, source_url, action)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (_now().isoformat(), path, sha256, verdict, json.dumps(reasons), source_url, action),
            )
            return cur.lastrowid

    def recent_scans(self, limit: int = 20) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()

    # --- Quarantine -------------------------------------------------------

    def add_quarantine(self, original: str, stored: str, sha256: str, reason: str) -> int:
        with self._lock, self._conn:
            cur = self._conn.execute(
                "INSERT INTO quarantine (quarantined_at, original_path, stored_path, sha256, reason)"
                " VALUES (?, ?, ?, ?, ?)",
                (_now().isoformat(), original, stored, sha256, reason),
            )
            return cur.lastrowid

    def quarantined(self, include_restored: bool = False) -> list[sqlite3.Row]:
        sql = "SELECT * FROM quarantine"
        if not include_restored:
            sql += " WHERE restored_at IS NULL"
        with self._lock:
            return self._conn.execute(sql + " ORDER BY id DESC").fetchall()

    def get_quarantine(self, qid: int) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute("SELECT * FROM quarantine WHERE id = ?", (qid,)).fetchone()

    # --- Startup items -----------------------------------------------------

    def autoruns_seen(self) -> dict[str, str]:
        """Startup items recorded last time: key -> command."""
        with self._lock:
            return {r["key"]: r["command"] for r in self._conn.execute("SELECT key, command FROM autoruns")}

    def sync_autoruns(self, entries, results: dict) -> None:
        """Record the current startup items and forget ones that have gone.

        `results` maps entry key -> ScanResult for the items just checked; items not in it
        keep their previous verdict and details. first_seen dates are kept.
        """
        now = _now().isoformat()
        with self._lock, self._conn:
            for e in entries:
                self._conn.execute(
                    "INSERT INTO autoruns (key, category, name, command, path, location, enabled, first_seen, last_seen)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
                    " ON CONFLICT(key) DO UPDATE SET command = excluded.command, path = excluded.path,"
                    " location = excluded.location, enabled = excluded.enabled, last_seen = excluded.last_seen",
                    (e.key, e.category, e.name, e.command, str(e.path) if e.path else None, e.location,
                     int(e.enabled), now, now),
                )
                r = results.get(e.key)
                if r is not None:
                    sig = r.signature
                    link = r.file_report.gui_link if r.file_report and r.file_report.found else None
                    self._conn.execute(
                        "UPDATE autoruns SET verdict = ?, signer = ?, sig_status = ?, reasons = ?, vt_link = ?,"
                        " sha256 = ?, checked_at = ? WHERE key = ?",
                        (r.verdict.value, sig.signer if sig else None, sig.status if sig else None,
                         json.dumps(r.reasons), link, r.sha256, now, e.key),
                    )
            self._conn.execute("DELETE FROM autoruns WHERE last_seen < ?", (now,))

    # --- File hashes (duplicate finder) -------------------------------------

    def cached_hash(self, path: str, size: int, mtime: float) -> str | None:
        """A file's SHA-256 from an earlier scan, if the file hasn't changed since."""
        with self._lock:
            row = self._conn.execute("SELECT sha256 FROM file_hashes WHERE path = ? AND size = ? AND mtime = ?",
                                     (path, size, mtime)).fetchone()
        return row[0] if row else None

    def cache_hash(self, path: str, size: int, mtime: float, sha256: str) -> None:
        with self._lock, self._conn:
            self._conn.execute("INSERT OR REPLACE INTO file_hashes (path, size, mtime, sha256) VALUES (?, ?, ?, ?)",
                               (path, size, mtime, sha256))

    # --- Cleanup -----------------------------------------------------------

    def record_cleanup(self, category: str, label: str, target: str | None, how: str, size: int) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO cleanup_log (cleaned_at, category, label, target, how, bytes) VALUES (?, ?, ?, ?, ?, ?)",
                (_now().isoformat(), category, label, target, how, size),
            )

    def cleanup_totals(self) -> tuple[int, int]:
        """(items removed, bytes freed) across all cleanups."""
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*), COALESCE(SUM(bytes), 0) FROM cleanup_log").fetchone()
        return row[0], row[1]

    def autorun_rows(self) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute("SELECT * FROM autoruns").fetchall()

    def set_autorun_enabled(self, key: str, on: bool) -> None:
        with self._lock, self._conn:
            self._conn.execute("UPDATE autoruns SET enabled = ? WHERE key = ?", (int(on), key))

    def autorun_first_seen(self) -> dict[str, str]:
        with self._lock:
            return {r["key"]: r["first_seen"] for r in self._conn.execute("SELECT key, first_seen FROM autoruns")}

    def mark_restored(self, qid: int) -> None:
        with self._lock, self._conn:
            self._conn.execute("UPDATE quarantine SET restored_at = ? WHERE id = ?", (_now().isoformat(), qid))
