"""Software updates: outdated programs, the holes attackers are using in them, and Windows Update.

- winget (built into Windows 10 and 11) says which installed programs have a newer version.
- CISA's Known Exploited Vulnerabilities catalog lists flaws attackers are using right now. It
  names products, not versions, so Atlas can't tell whether *your* version has a given hole; but an
  out-of-date program whose maker is on the list is the one to update first.
- Windows Update: when it last installed something, and whether a restart is waiting.

Update buttons open winget in a window you can watch; Atlas doesn't update anything by itself.
"""

from __future__ import annotations

import logging
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import date, timedelta

import requests

from atlas.findings import NOTE, OK, WARN, Finding

log = logging.getLogger(__name__)

NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_LINK = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext="
KEV_YEARS = 3  # older entries are about versions long gone
WINGET_HOURS = 12  # winget takes a few seconds: don't ask it every hour
GROUP_OVER = 3  # more ordinary updates than this become one row
UPDATE_DAYS = 35  # Windows installs updates at least monthly
REBOOT_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
# Words that don't identify a product.
# Add-ons for a product (a database driver, a runtime) aren't the product itself.
ADD_ONS = {"driver", "odbc", "oledb", "connector", "redistributable", "runtime", "sdk", "plugin", "extension",
           "library", "libraries", "tools", "bindings"}
CHROMIUM_BROWSERS = {"chrome", "chromium", "edge", "brave", "opera", "vivaldi"}
STOPWORDS = {"the", "and", "for", "of", "x64", "x86", "64-bit", "32-bit", "bit", "edition", "version", "update",
             "microsoft", "windows", "app", "desktop", "client", "software", "system", "server", "workplace"}


@dataclass
class Upgrade:
    name: str
    id: str
    version: str
    available: str


# --- winget -------------------------------------------------------------------------------------

def parse_winget(text: str) -> list[Upgrade]:
    """Rows of `winget upgrade`'s table. The columns are padded to the width of the header."""
    lines = [line.rstrip() for line in text.splitlines()]
    for i, line in enumerate(lines):
        m = re.search(r"\bName\s+Id\s+Version\s+Available", line)
        if m and i + 1 < len(lines) and set(lines[i + 1].strip()) == {"-"}:
            header = line[m.start():]
            offset = m.start()
            cols = [header.index(c) + offset for c in ("Name", "Id", "Version", "Available")]
            end = header.find("Source")
            cols.append(end + offset if end > 0 else None)
            rows = []
            for row in lines[i + 2:]:
                if not row.strip() or re.match(r"^\d+ (upgrades?|packages?)", row.strip()):
                    break
                parts = [row[cols[k]:cols[k + 1]].strip() if cols[k + 1] else row[cols[k]:].strip()
                         for k in range(4)]
                if parts[1] and parts[3]:
                    rows.append(Upgrade(*parts))
            return rows
    return []


_ask_again = False


def ask_again() -> None:
    """Skip the saved answer next time (after an Update button, so the list catches up)."""
    global _ask_again
    _ask_again = True


def winget_upgrades(store=None) -> list[Upgrade] | None:
    """Programs with a newer version, or None when winget isn't there."""
    global _ask_again
    if store is not None and _ask_again:
        _ask_again = False
    elif store is not None:
        cached = store.cached_extra("winget", "upgrades", WINGET_HOURS)
        if cached is not None:
            return [Upgrade(**u) for u in cached]
    try:
        out = subprocess.run(["winget", "upgrade", "--source", "winget", "--disable-interactivity",
                              "--include-unknown"], capture_output=True, timeout=120, creationflags=NO_WINDOW)
    except (OSError, subprocess.TimeoutExpired):
        log.info("winget isn't available")
        return None
    upgrades = parse_winget(out.stdout.decode("utf-8", errors="replace"))
    if store is not None:
        store.cache_extra("winget", "upgrades", [u.__dict__ for u in upgrades])
    return upgrades


def upgrade_command(package_id: str) -> list[str]:
    """What the Update button runs, in a console window the user can watch (and answer, if winget asks)."""
    return ["cmd", "/k", "winget", "upgrade", "--id", package_id, "--exact", "--source", "winget"]


SAFE_ID = re.compile(r"^[\w.+-]+$")


def upgrade_all_command(package_ids: list[str]) -> str:
    """Update all, one after another, in one window. winget ids are letters, digits and dots; anything else is
    left out rather than passed to cmd."""
    steps = [f"winget upgrade --id {i} --exact --source winget" for i in package_ids if SAFE_ID.match(i)]
    return "cmd /k " + " & ".join(steps)


# --- CISA KEV ----------------------------------------------------------------------------------------

END_OF_LIFE = re.compile(r"end[- ]of[- ](?:life|service|support)|\bEoL\b|\bEoS\b", re.I)


def kev_catalog(store=None, years: int | None = KEV_YEARS) -> list[dict]:
    """The catalog's entries added in the last `years` (None: all of them, for routers, which stay in homes
    for a decade), downloaded at most once a day. "eol" marks entries CISA says are past end of life."""
    rows = store.cached_extra("kev", "all", 24) if store is not None else None
    if rows is None:
        try:
            resp = requests.get(KEV_URL, timeout=30)
            resp.raise_for_status()
            rows = [{**{k: r.get(k) for k in ("cveID", "vendorProject", "product", "vulnerabilityName",
                                              "dateAdded", "knownRansomwareCampaignUse")},
                     "shortDescription": (r.get("shortDescription") or "")[:300],
                     "eol": bool(END_OF_LIFE.search(f"{r.get('requiredAction')} {r.get('shortDescription')} "
                                                    f"{r.get('notes')}"))}
                    for r in resp.json().get("vulnerabilities", [])]
        except (requests.RequestException, ValueError):
            log.warning("Couldn't download the CISA KEV catalog")
            rows = (store.cached_extra("kev", "all", 24 * 30) or []) if store is not None else []
        else:
            if store is not None:
                store.cache_extra("kev", "all", rows)
    if years is None:
        return rows
    since = (date.today() - timedelta(days=365 * years)).isoformat()
    return [r for r in rows if (r.get("dateAdded") or "") >= since]


def _words(text: str) -> set[str]:
    return {w for w in re.findall(r"[a-z0-9+]+(?:-[a-z0-9]+)?", text.lower()) if w not in STOPWORDS and len(w) > 1}


def kev_matches(name: str, catalog: list[dict]) -> list[dict]:
    """Catalog entries for this program. Every word of the product's name must appear in the program's name,
    and the maker's too when the product is a single generic word. Chromium flaws count for every browser
    built on it (Chrome, Edge, Brave, Opera, Vivaldi)."""
    have = _words(name)
    found = []
    for entry in catalog:
        product, vendor = _words(entry.get("product") or ""), _words(entry.get("vendorProject") or "")
        if (have & ADD_ONS) - product:
            continue
        if "chromium" in product:
            hit = bool(have & CHROMIUM_BROWSERS)
        else:
            hit = bool(product) and product <= have and (len(product) > 1 or not vendor or bool(vendor & have)
                                                         or vendor <= product)
        if hit:
            found.append(entry)
    return sorted(found, key=lambda e: e.get("dateAdded") or "", reverse=True)


# --- Findings ------------------------------------------------------------------------------------------

def update_findings(upgrades: list[Upgrade] | None, catalog: list[dict]) -> list[Finding]:
    if upgrades is None:
        return [Finding("Updates", "Couldn't check programs for updates", NOTE,
                        ["Atlas uses winget, which comes with the App Installer from the Microsoft Store."],
                        key="updates:no-winget", fix="open", fix_label="Get App Installer",
                        data={"url": "ms-windows-store://pdp/?ProductId=9NBLGGH4NNS1"})]
    found = []
    ordinary = [u for u in upgrades if not kev_matches(u.name, catalog)]
    if len(ordinary) > GROUP_OVER:
        found.append(Finding("Updates", f"{len(ordinary)} programs have updates", NOTE,
                             ["Updates fix security holes as well as bugs. None of these are on CISA's list of "
                              "flaws attackers are using, so there's no rush.",
                              "Update all opens winget in a window and updates them one after another. Close the "
                              "programs first."] + [f"{u.name}: {u.version or 'unknown'} -> {u.available}"
                                                   for u in ordinary],
                             key="updates:ordinary", fix="winget-upgrade-all", fix_label="Update all",
                             data={"ids": [u.id for u in ordinary], "names": [u.name for u in ordinary]}))
        upgrades = [u for u in upgrades if u not in ordinary]
    for u in upgrades:
        holes = kev_matches(u.name, catalog)
        details = [f"Installed: {u.version or 'unknown'}. Newest: {u.available}."]
        if holes:
            ransomware = any((h.get("knownRansomwareCampaignUse") or "").lower() == "known" for h in holes)
            details.append(f"CISA lists {len(holes)} flaw(s) in {holes[0]['product']} that attackers are using "
                           f"right now" + (", some by ransomware gangs" if ransomware else "") +
                           ". Updates fix them, so update this first.")
            details += [f"{h['cveID']} (added {h['dateAdded']}): {h.get('vulnerabilityName') or ''}".strip()
                        for h in holes[:3]]
        else:
            details.append("Updates fix security holes as well as bugs.")
        details.append("Update opens winget in a window so you can watch it. Close the program first.")
        found.append(Finding("Updates", f"{'Update soon' if holes else 'Update available'}: {u.name}",
                             WARN if holes else NOTE, details,
                             key=f"updates:{u.id.lower()}:{u.available}", fix="winget-upgrade",
                             fix_label="Update", data={"id": u.id, "name": u.name},
                             vt_link=KEV_LINK + holes[0]["cveID"] if holes else None))
    if not found:
        found.append(Finding("Updates", "Your programs are up to date", OK, key="updates:ok",
                             details=["Checked with winget. Programs it doesn't know about update themselves or "
                                      "through their own menus."]))
    return found


def windows_update_findings(last_installed: date | None, reboot_waiting: bool, today: date | None = None) -> list[Finding]:
    today = today or date.today()
    page = {"fix": "open", "fix_label": "Open Windows Update", "data": {"url": "ms-settings:windowsupdate"}}
    found = []
    if reboot_waiting:
        found.append(Finding("Updates", "Restart to finish installing Windows updates", NOTE,
                             ["Security fixes aren't active until Windows restarts."], key="updates:windows:reboot",
                             **page))
    if last_installed is None:
        found.append(Finding("Updates", "Couldn't tell when Windows last updated", NOTE, key="updates:windows:unknown",
                             **page))
    elif (today - last_installed).days > UPDATE_DAYS:
        found.append(Finding("Updates", f"Windows hasn't installed an update since {last_installed:%Y-%m-%d}", WARN,
                             ["Windows gets security fixes every month. Updates may be paused or failing."],
                             key=f"updates:windows:old:{last_installed}", **page))
    else:
        found.append(Finding("Updates", f"Windows is updating (last update {last_installed:%Y-%m-%d})", OK,
                             key="updates:windows:ok"))
    return found


def windows_update_status(store=None) -> tuple[date | None, bool]:
    """When the newest Windows update was installed, and whether a restart is waiting."""
    if sys.platform != "win32":
        return None, False
    import winreg

    from atlas.local_checks import run_powershell_json

    reboot = True
    try:
        winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, REBOOT_KEY).Close()
    except OSError:
        reboot = False
    newest = store.cached_extra("windows-update", "newest", WINGET_HOURS) if store is not None else None
    if newest is None:
        try:
            rows = run_powershell_json("ConvertTo-Json -Compress -InputObject @(Get-HotFix | Where-Object InstalledOn"
                                       " | Sort-Object InstalledOn -Descending | Select-Object -First 1 |"
                                       " ForEach-Object { @{when=$_.InstalledOn.ToString('yyyy-MM-dd')} })", timeout=60)
        except Exception:
            log.exception("Couldn't read Windows Update history")
            rows = []
        newest = rows[0]["when"] if rows else ""
        if store is not None and newest:
            store.cache_extra("windows-update", "newest", newest)
    return (date.fromisoformat(newest) if newest else None), reboot


def check_updates(store=None) -> list[Finding]:
    found = update_findings(winget_upgrades(store), kev_catalog(store))
    return found + windows_update_findings(*windows_update_status(store))
