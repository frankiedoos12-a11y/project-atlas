"""Ad-spam finder: websites allowed to send you notifications, and browser extensions
that got in the way adware does.

"Click Allow to prove you're not a robot" pages turn notifications into a stream of fake
virus warnings and ads. Adware extensions are usually slipped in by another program's
installer, from outside the browser's store, and take over the search engine or new tab page.

Reading is safe at any time. Blocking a site edits the browser's settings file, so the
browser must be closed, and a backup of that file is saved first.
"""

from __future__ import annotations

import json
import logging
import shutil
import sqlite3
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from atlas.cleanup import BROWSERS, _roaming
from atlas.links import LinkCheck, local_warnings
from atlas.scanner import Verdict

log = logging.getLogger(__name__)

NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

# Chromium's extension "location" codes.
LOC_STORE, LOC_EXT_PREF, LOC_EXT_REGISTRY, LOC_UNPACKED, LOC_COMPONENT = 1, 2, 3, 4, 5
LOC_EXT_PREF_DOWNLOAD, LOC_POLICY, LOC_EXT_COMPONENT = 6, 7, 10
EXTERNAL = {LOC_EXT_PREF, LOC_EXT_REGISTRY, LOC_EXT_PREF_DOWNLOAD}

ATLAS_EXTENSION_ID = "gjcdnlienjkddhppmiicpjekhlkliaam"  # our own, loaded unpacked; see atlas.browserext

SETTINGS_PAGES = {"Chrome": "chrome", "Edge": "edge", "Brave": "brave", "Opera": "opera"}


@dataclass
class Profile:
    browser: str  # "Chrome", "Edge", "Firefox", ...
    exe: str  # process name, e.g. "chrome.exe"
    path: Path
    name: str  # e.g. "Default", "Profile 2"

    @property
    def label(self) -> str:
        return self.browser if self.name in ("Default", "") else f"{self.browser} ({self.name})"


@dataclass
class NotificationSite:
    profile: Profile
    site: str  # e.g. "https://news-alerts.example:443"
    pattern: str  # the browser's own key for it, used when blocking
    verdict: str = "not checked"  # "clean", "suspicious", "malicious", "unknown"
    reasons: list[str] = field(default_factory=list)
    vt_link: str | None = None

    @property
    def host(self) -> str:
        return urlparse(self.site if "://" in self.site else f"https://{self.site}").hostname or self.site


@dataclass
class Extension:
    profile: Profile
    id: str
    name: str
    version: str = ""
    enabled: bool = True
    concerns: list[str] = field(default_factory=list)  # adware signs: these make it "needs a look"
    notes: list[str] = field(default_factory=list)  # worth knowing, but normal
    permissions: list[str] = field(default_factory=list)

    @property
    def needs_look(self) -> bool:
        return bool(self.concerns)


# --- Finding profiles -------------------------------------------------------------

def chromium_profiles() -> list[Profile]:
    found = []
    for browser, exe, base in BROWSERS:
        root = base()
        if not root.is_dir():
            continue
        if (root / "Preferences").exists():  # Opera keeps a single profile in its root
            found.append(Profile(browser, exe, root, ""))
            continue
        for p in sorted(root.iterdir()):
            if p.is_dir() and (p.name == "Default" or p.name.startswith("Profile ")) and (p / "Preferences").exists():
                found.append(Profile(browser, exe, p, p.name))
    return found


def firefox_profiles() -> list[Profile]:
    root = _roaming() / "Mozilla/Firefox/Profiles"
    if not root.is_dir():
        return []
    return [Profile("Firefox", "firefox.exe", p, p.name.split(".", 1)[-1]) for p in sorted(root.iterdir())
            if p.is_dir() and ((p / "permissions.sqlite").exists() or (p / "extensions.json").exists())]


def _read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


# --- Notification permissions -----------------------------------------------------

def _chromium_notification_sites(profile: Profile) -> list[NotificationSite]:
    prefs = _read_json(profile.path / "Preferences")
    exceptions = prefs.get("profile", {}).get("content_settings", {}).get("exceptions", {})
    sites = []
    for pattern, value in (exceptions.get("notifications") or {}).items():
        if isinstance(value, dict) and value.get("setting") == 1:  # 1 = allow, 2 = block
            sites.append(NotificationSite(profile, pattern.split(",")[0], pattern))
    return sites


def _copy_sqlite(path: Path) -> Path:
    """Firefox locks its databases while running; read a copy instead."""
    tmp = Path(tempfile.mkdtemp(prefix="atlas-")) / path.name
    shutil.copy2(path, tmp)
    for extra in ("-wal", "-shm"):
        if path.with_name(path.name + extra).exists():
            shutil.copy2(path.with_name(path.name + extra), tmp.with_name(tmp.name + extra))
    return tmp


def _firefox_notification_sites(profile: Profile) -> list[NotificationSite]:
    db = profile.path / "permissions.sqlite"
    if not db.exists():
        return []
    copy = _copy_sqlite(db)
    try:
        with sqlite3.connect(copy) as conn:
            rows = conn.execute("SELECT origin FROM moz_perms WHERE type = 'desktop-notification' "
                                "AND permission = 1").fetchall()
    except sqlite3.Error:
        rows = []
    finally:
        shutil.rmtree(copy.parent, ignore_errors=True)
    return [NotificationSite(profile, origin, origin) for (origin,) in rows]


def notification_sites() -> list[NotificationSite]:
    sites = []
    for profile in chromium_profiles():
        sites += _chromium_notification_sites(profile)
    for profile in firefox_profiles():
        sites += _firefox_notification_sites(profile)
    return sites


def judge_site(host: str, scanner) -> LinkCheck:
    check = LinkCheck(f"https://{host}")
    for verdict, reason in local_warnings(check.url):
        if verdict is not Verdict.CLEAN:
            check.raise_to(verdict, reason)
    if scanner is None or scanner.vt is None:
        check.raise_to(Verdict.ERROR, "VirusTotal isn't connected. Use View on VirusTotal to look the site up")
        return check
    try:
        check.domain_report = scanner.lookup("domain", host)
        scanner.judge_report(check, check.domain_report, f"The site {host}", site=True)
    except Exception as exc:  # network trouble, quota
        check.raise_to(Verdict.ERROR, f"Lookup failed: {exc}")
        return check
    if check.verdict is Verdict.CLEAN:
        if check.domain_report.analyzed:
            check.reasons.insert(0, f"VirusTotal has no warnings about this site "
                                    f"({check.domain_report.total} engines)")
        else:
            check.raise_to(Verdict.UNKNOWN, "VirusTotal has never seen this site")
    return check


def judge_sites(sites: list[NotificationSite], scanner) -> None:
    """Look each site's domain up on VirusTotal (one lookup per domain, cached)."""
    checks: dict[str, LinkCheck] = {}
    for s in sites:
        if s.host not in checks:
            checks[s.host] = judge_site(s.host, scanner)
        check = checks[s.host]
        s.verdict = check.verdict.value
        s.reasons = list(check.reasons)
        s.vt_link = check.vt_link


def block_notifications(site: NotificationSite, backup_dir: Path, running: set[str]) -> Path:
    """Switch a site's notifications from Allow to Block. Returns the backup file's path."""
    if site.profile.exe in running:
        raise PermissionError(f"Close {site.profile.browser} first: it rewrites its settings when it closes")
    backup_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    if site.profile.browser == "Firefox":
        db = site.profile.path / "permissions.sqlite"
        backup = backup_dir / f"Firefox-{site.profile.name}-permissions-{stamp}.sqlite"
        shutil.copy2(db, backup)
        with sqlite3.connect(db) as conn:
            conn.execute("UPDATE moz_perms SET permission = 2 WHERE type = 'desktop-notification' AND origin = ?",
                         (site.pattern,))
        return backup
    prefs_path = site.profile.path / "Preferences"
    backup = backup_dir / f"{site.profile.browser}-{site.profile.name or 'profile'}-Preferences-{stamp}.json"
    shutil.copy2(prefs_path, backup)
    prefs = json.loads(prefs_path.read_text(encoding="utf-8"))
    entry = prefs["profile"]["content_settings"]["exceptions"]["notifications"][site.pattern]
    entry["setting"] = 2
    entry["last_modified"] = str(int((time.time() + 11644473600) * 1_000_000))  # Windows epoch, microseconds
    tmp = prefs_path.with_suffix(".atlas-tmp")
    tmp.write_text(json.dumps(prefs, separators=(",", ":")), encoding="utf-8")
    tmp.replace(prefs_path)
    log.info("Blocked notifications from %s in %s (backup %s)", site.site, site.profile.label, backup)
    return backup


# --- Extensions -------------------------------------------------------------------

def _resolve_name(name: str, folder: Path | None, default_locale: str | None) -> str:
    """Turn "__MSG_appName__" into the real name using the extension's _locales files."""
    if not (name.startswith("__MSG_") and folder):
        return name
    key = name[6:-2].lower()
    for locale in ("en", "en_US", default_locale or "en"):
        messages = _read_json(folder / "_locales" / locale / "messages.json")
        for k, v in messages.items():
            if k.lower() == key and isinstance(v, dict) and v.get("message"):
                return v["message"]
    return name


def _hosts(manifest: dict) -> list[str]:
    hosts = list(manifest.get("host_permissions") or [])
    hosts += [p for p in manifest.get("permissions") or [] if isinstance(p, str) and ("://" in p or p == "<all_urls>")]
    for script in manifest.get("content_scripts") or []:
        hosts += script.get("matches") or []
    return hosts


def _reads_every_site(manifest: dict) -> bool:
    return any(h in ("<all_urls>", "*://*/*", "http://*/*", "https://*/*") for h in _hosts(manifest))


def _takeovers(manifest: dict) -> list[str]:
    found = []
    overrides = manifest.get("chrome_settings_overrides") or {}
    if overrides.get("search_provider"):
        found.append("Changes your search engine")
    if overrides.get("homepage") or overrides.get("startup_pages"):
        found.append("Changes your home page or startup pages")
    if (manifest.get("chrome_url_overrides") or {}).get("newtab"):
        found.append("Replaces your new tab page")
    return found


def _chromium_extensions(profile: Profile) -> list[Extension]:
    settings: dict = {}
    for file in ("Preferences", "Secure Preferences"):
        settings.update(_read_json(profile.path / file).get("extensions", {}).get("settings", {}))
    found = []
    for ext_id, s in settings.items():
        location = s.get("location")
        if location in (None, LOC_COMPONENT, LOC_EXT_COMPONENT):
            continue  # built into the browser, or a leftover stub
        rel = s.get("path") or ""
        folder = Path(rel) if Path(rel).is_absolute() else profile.path / "Extensions" / rel if rel else None
        manifest = s.get("manifest") or (_read_json(folder / "manifest.json") if folder else {})
        if not manifest:
            continue
        name = _resolve_name(manifest.get("name", ext_id), folder, manifest.get("default_locale"))
        disabled = s.get("state") == 0 or bool(s.get("disable_reasons"))
        ext = Extension(profile, ext_id, name, manifest.get("version", ""), not disabled,
                        permissions=[p for p in manifest.get("permissions") or [] if isinstance(p, str)])
        from_store = bool(s.get("from_webstore")) or location == LOC_STORE
        if ext_id == ATLAS_EXTENSION_ID:
            ext.notes.append("Project Atlas's own link checker")
        elif location == LOC_UNPACKED:
            ext.concerns.append("Loaded unpacked (developer mode), not installed from a store")
        elif location == LOC_POLICY:
            ext.concerns.append("Forced on by a policy: it can't be removed from the browser. Adware does this; "
                                "so do workplaces")
        elif location in EXTERNAL and not from_store:
            ext.concerns.append("Added by another program, from outside the store")
        elif location in EXTERNAL:
            ext.notes.append("Added by another program's installer (it is a store extension)")
        ext.concerns += _takeovers(manifest)
        if _reads_every_site(manifest):
            ext.notes.append("Can read and change every website you visit")
        found.append(ext)
    return found


def _firefox_extensions(profile: Profile) -> list[Extension]:
    data = _read_json(profile.path / "extensions.json")
    found = []
    for a in data.get("addons") or []:
        if a.get("type") != "extension" or a.get("location") in ("app-builtin", "app-system-defaults",
                                                                  "app-system-addons"):
            continue
        name = (a.get("defaultLocale") or {}).get("name") or a.get("id", "?")
        ext = Extension(profile, a.get("id", "?"), name, a.get("version", ""), bool(a.get("active")),
                        permissions=list((a.get("userPermissions") or {}).get("permissions") or []))
        if a.get("location", "").startswith("winreg") or a.get("location") == "app-global":
            ext.concerns.append("Added by another program, from outside the store")
        if a.get("temporarilyInstalled"):
            ext.concerns.append("Loaded temporarily (developer mode)")
        origins = (a.get("userPermissions") or {}).get("origins") or []
        if any(o in ("<all_urls>", "*://*/*") for o in origins):
            ext.notes.append("Can read and change every website you visit")
        found.append(ext)
    return found


def extensions() -> list[Extension]:
    found = []
    for profile in chromium_profiles():
        found += _chromium_extensions(profile)
    for profile in firefox_profiles():
        found += _firefox_extensions(profile)
    found.sort(key=lambda e: (not e.needs_look, e.profile.label, e.name.lower()))
    return found


def open_extensions_page(ext: Extension) -> None:
    """Open the browser's own extensions page on this extension, where it can be removed."""
    if ext.profile.browser == "Firefox":
        url, exe = "about:addons", "firefox"
    else:
        scheme = SETTINGS_PAGES.get(ext.profile.browser, "chrome")
        url, exe = f"{scheme}://extensions/?id={ext.id}", ext.profile.exe.removesuffix(".exe")
    args = ["cmd", "/c", "start", "", exe]
    if ext.profile.name and ext.profile.browser != "Firefox":
        args.append(f"--profile-directory={ext.profile.name}")
    subprocess.Popen(args + [url], creationflags=NO_WINDOW)
