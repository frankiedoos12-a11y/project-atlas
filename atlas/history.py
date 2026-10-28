"""Recently visited sites, read from each browser's own history file (for threat-intel matching).

Read-only: the history database is copied to a temporary file first (the browser keeps the
original locked while it runs), and nothing leaves this PC.
"""

from __future__ import annotations

import logging
import os
import shutil
import sqlite3
import tempfile
import time
from pathlib import Path
from urllib.parse import urlsplit

from atlas.browsers import chromium_profiles, firefox_profiles

log = logging.getLogger(__name__)

CHROME_EPOCH = 11644473600  # seconds between 1601-01-01 (Chrome's clock) and 1970-01-01
MAX_URLS = 20000


def _query(db: Path, sql: str, args: tuple) -> list[tuple]:
    if not db.is_file():
        return []
    fd, tmp = tempfile.mkstemp(prefix="atlas_history_", suffix=".sqlite")
    os.close(fd)
    try:
        shutil.copyfile(db, tmp)
        conn = sqlite3.connect(f"file:{tmp}?mode=ro", uri=True)
        try:
            return conn.execute(sql, args).fetchall()
        finally:
            conn.close()
    except (OSError, sqlite3.Error) as exc:
        log.info("Couldn't read %s: %s", db, exc)
        return []
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass


def visited(days: int = 30) -> dict[str, str]:
    """url -> where it was seen (e.g. "Chrome (Profile 2) history"), for visits in the last `days` days."""
    since = time.time() - days * 86400
    found: dict[str, str] = {}
    for p in chromium_profiles():
        rows = _query(p.path / "History", "SELECT url FROM urls WHERE last_visit_time > ? ORDER BY last_visit_time"
                      " DESC LIMIT ?", (int((since + CHROME_EPOCH) * 1_000_000), MAX_URLS))
        for (url,) in rows:
            found.setdefault(url, f"{p.label} history")
    for p in firefox_profiles():
        rows = _query(p.path / "places.sqlite", "SELECT url FROM moz_places WHERE last_visit_date > ? ORDER BY"
                      " last_visit_date DESC LIMIT ?", (int(since * 1_000_000), MAX_URLS))
        for (url,) in rows:
            found.setdefault(url, f"{p.label} history")
    return {u: w for u, w in found.items() if u.lower().startswith(("http://", "https://"))}


def hosts(urls: dict[str, str]) -> dict[str, str]:
    """host -> where, from a url -> where map."""
    found: dict[str, str] = {}
    for url, where in urls.items():
        host = (urlsplit(url).hostname or "").lower()
        if host:
            found.setdefault(host, where)
    return found
