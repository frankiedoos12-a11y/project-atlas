"""Google Threat Intelligence: recent threat reports about Windows, matched against this PC.

With a VirusTotal Enterprise / Google Threat Intelligence key, Atlas downloads the indicators
(file hashes, domains, URLs, IP addresses) and ATT&CK techniques from Google's own Windows
threat reports of the last few months, and keeps them in its local database. Matching is then
done on this PC, against things Atlas already knows: files it has hashed (running programs,
DLLs, drivers, startup items, downloads), sites in your browser history, download sources and
live connections. No lookups are spent on the matching itself.

The reports are licensed to the key's owner: they are fetched at run time and stay on this PC.
On a key without GTI access everything here quietly does nothing.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from datetime import datetime, timezone

from atlas.db import Store
from atlas.findings import NOTE, WARN, Finding
from atlas.vt_client import VTClient, VTError

log = logging.getLogger(__name__)

REPORT_FILTER = 'collection_type:report origin:"Google Threat Intelligence" operating_systems:windows'
PAGE = 40
MAX_PAGES = 10  # per indicator list in one report
SYNC_HOURS = 20  # "once a day", with some slack
REPORT_LINK = "https://www.virustotal.com/gui/collection/{id}"
# Indicator lists in a report, and what Atlas calls them. Files come back as full objects so that
# reports listing only an MD5 still give the SHA-256 when VirusTotal knows the file.
LISTS = {"files": "files", "domains": "relationships/domains", "urls": "relationships/urls",
         "ip_addresses": "relationships/ip_addresses", "attack_techniques": "relationships/attack_techniques"}


def link(report_id: str) -> str:
    return REPORT_LINK.format(id=report_id)


def available(vt: VTClient | None, store: Store) -> bool:
    """Does this key reach Google Threat Intelligence reports? Remembered for a day."""
    if vt is None:
        return False
    cached = store.cached_extra("gti", "available", 24)
    if cached is not None:
        return bool(cached)
    try:
        vt.api_get("/collections", {"filter": REPORT_FILTER, "limit": 1, "attributes": "name"})
        ok = True
    except VTError as exc:
        if exc.status not in (401, 403):
            raise  # offline or VirusTotal trouble: try again next time
        ok = False
    store.cache_extra("gti", "available", ok)
    log.info("Google Threat Intelligence %s with this key", "available" if ok else "not available")
    return ok


def last_sync(store: Store) -> datetime | None:
    data = store.cached_extra("gti", "last-sync", 24 * 365)
    return datetime.fromisoformat(data) if data else None


def due(store: Store) -> bool:
    last = last_sync(store)
    return last is None or (datetime.now(timezone.utc) - last).total_seconds() > SYNC_HOURS * 3600


def _all(vt: VTClient, path: str, params: dict) -> list[dict]:
    items, cursor = [], None
    for _ in range(MAX_PAGES):
        body = vt.api_get(path, dict(params, limit=PAGE, **({"cursor": cursor} if cursor else {})))
        if not body:
            break
        items += body.get("data") or []
        cursor = (body.get("meta") or {}).get("cursor")
        if not cursor:
            break
    return items


def indicators(vt: VTClient, report_id: str, counters: dict) -> tuple[list[tuple[str, str]], list[str]]:
    """(kind, value) indicators and ATT&CK technique IDs listed in one report."""
    iocs: list[tuple[str, str]] = []
    techniques: list[str] = []
    for name, sub in LISTS.items():
        if not counters.get(name):
            continue
        params = {"attributes": "sha256,md5"} if name == "files" else {}
        for item in _all(vt, f"/collections/{report_id}/{sub}", params):
            if name == "files":
                a = item.get("attributes") or {}
                sha, md5 = a.get("sha256") or "", a.get("md5") or ""
                ident = item.get("id", "")
                sha = sha or (ident if len(ident) == 64 else "")
                md5 = md5 or (ident if len(ident) == 32 else "")
                iocs += [("sha256", sha)] if sha else []
                iocs += [("md5", md5)] if md5 else []
            elif name == "urls":
                url = (item.get("context_attributes") or {}).get("url")
                if url:
                    iocs.append(("url", normalize_url(url)))
            elif name == "attack_techniques":
                techniques.append(item.get("id", ""))
            else:
                iocs.append(({"domains": "domain", "ip_addresses": "ip"}[name], item.get("id", "")))
    return [(k, v) for k, v in iocs if v], [t for t in techniques if t]


def sync(vt: VTClient, store: Store, days: int = 90, progress: Callable[[str], None] | None = None,
         cancel: threading.Event | None = None) -> tuple[int, int]:
    """Download reports from the last `days` days that aren't on this PC yet. Returns (new reports,
    indicators on hand)."""
    say = progress or (lambda text: None)
    since = int(time.time()) - days * 86400
    store.gti_prune(since)
    start = datetime.fromtimestamp(since, timezone.utc).strftime("%Y-%m-%d")
    say("Listing Google Threat Intelligence reports...")
    reports = _all(vt, "/collections", {"filter": f"{REPORT_FILTER} creation_date:{start}+", "order": "creation_date-",
                                        "attributes": "name,creation_date,counters,report_type"})
    todo = [r for r in reports if not store.gti_has_report(r["id"])]
    for i, r in enumerate(todo, 1):
        if cancel and cancel.is_set():
            break
        a = r.get("attributes") or {}
        say(f"Downloading report {i} of {len(todo)}: {a.get('name', '')[:60]}")
        try:
            iocs, techniques = indicators(vt, r["id"], a.get("counters") or {})
        except VTError:
            log.exception("Couldn't read GTI report %s", r["id"])
            continue
        store.gti_save_report(r["id"], a.get("name") or r["id"], a.get("report_type"),
                              int(a.get("creation_date") or time.time()), techniques, iocs)
    if not (cancel and cancel.is_set()):
        store.cache_extra("gti", "last-sync", datetime.now(timezone.utc).isoformat())
    reports_now, iocs_now = store.gti_stats()
    log.info("GTI sync: %d new report(s); %d reports and %d indicators on hand", len(todo), reports_now, iocs_now)
    return len(todo), iocs_now


def normalize_url(url: str) -> str:
    url = url.strip().lower()
    return url[:-1] if url.endswith("/") else url


def _date(created: int) -> str:
    return datetime.fromtimestamp(created).strftime("%Y-%m-%d")


def _finding(level: str, what: str, where: str, rows, kind: str) -> Finding:
    best = rows[0]
    others = f" and {len(rows) - 1} other report(s)" if len(rows) > 1 else ""
    details = [f"{where} matches an indicator in Google Threat Intelligence's report \"{best['name']}\" "
               f"({best['report_type'] or 'report'}, {_date(best['created'])}){others}."]
    if kind == "ip":
        details.append("Addresses are often shared (hosting, cloud), so this alone doesn't mean much. Worth a look "
                       "only if the program using it is unfamiliar")
    else:
        details.append("Read the report to see what the threat does and how to get rid of it")
    return Finding("Threat intel", f"{what} is in a GTI threat report", level, details,
                   key=f"gti:{kind}:{where}", vt_link=link(best["id"]), data={"reports": [r["id"] for r in rows]})


def _host_matches(host: str, domains: set[str]) -> str | None:
    parts = host.lower().rstrip(".").split(".")
    for i in range(len(parts) - 1):
        candidate = ".".join(parts[i:])
        if candidate in domains:
            return candidate
    return None


def match(store: Store, hosts: dict[str, str] | None = None, urls: dict[str, str] | None = None,
          ips: dict[str, str] | None = None, files: dict[str, str] | None = None) -> list[Finding]:
    """Findings for anything on this PC that a stored report lists. Each argument maps the thing
    (host, URL, IP address, SHA-256) to where Atlas saw it, e.g. "Chrome history"."""
    files = store.known_hashes() if files is None else files
    found = []
    by_hash = store.gti_lookup("sha256", list(files))
    for sha, rows in by_hash.items():
        found.append(_finding(WARN, files[sha].rsplit("\\", 1)[-1], files[sha], rows, "sha256"))
    if hosts:
        # A report's domain matches the host itself and any subdomain of it, never the parent.
        candidates = {".".join(h.lower().split(".")[i:]) for h in hosts for i in range(len(h.split(".")) - 1)}
        known = store.gti_lookup("domain", list(candidates))
        for host, where in sorted(hosts.items()):
            hit = _host_matches(host, set(known))
            if hit:
                found.append(_finding(WARN, host, f"{host} ({where})", known[hit], "domain"))
    if urls:
        known = store.gti_lookup("url", [normalize_url(u) for u in urls])
        for url, where in urls.items():
            rows = known.get(normalize_url(url))
            if rows:
                found.append(_finding(WARN, url[:80], f"{url[:120]} ({where})", rows, "url"))
    if ips:
        known = store.gti_lookup("ip", list(ips))
        for ip, where in ips.items():
            if ip.lower() in known:
                found.append(_finding(NOTE, ip, f"{ip} ({where})", known[ip.lower()], "ip"))
    return found


def technique_context(store: Store, technique: str) -> str | None:
    """e.g. "Seen in 3 recent GTI reports, such as ..." for an ATT&CK technique."""
    rows = store.gti_reports_using(technique)
    if not rows:
        return None
    names = "; ".join(f"\"{r['name'][:70]}\" ({_date(r['created'])})" for r in rows[:2])
    return f"This technique ({technique}) appears in recent GTI threat reports about Windows, such as {names}"


def reports_for_file(vt: VTClient, store: Store, sha256: str) -> list[dict]:
    """GTI reports and threat actors that mention a file: [{"id", "name", "kind"}]. Cached a week."""
    cached = store.cached_extra("gti-file", sha256, 24 * 7)
    if cached is not None:
        return cached
    found = []
    for rel, kind in (("related_reports", "report"), ("related_threat_actors", "actor")):
        try:
            body = vt.api_get(f"/files/{sha256}/{rel}", {"limit": 5, "attributes": "name"})
        except VTError as exc:
            if exc.status in (401, 403):
                break
            raise
        for item in (body or {}).get("data") or []:
            found.append({"id": item.get("id"), "name": (item.get("attributes") or {}).get("name") or item.get("id"),
                          "kind": kind})
    store.cache_extra("gti-file", sha256, found)
    return found
