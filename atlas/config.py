"""Settings, file locations, and API key storage.

Settings live in %APPDATA%\\ProjectAtlas\\config.json.
Data (history database, quarantine, logs) lives in %LOCALAPPDATA%\\ProjectAtlas.
The VirusTotal API key lives in Windows Credential Manager via `keyring`, never on disk.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

import keyring

from atlas import APP_NAME

KEYRING_SERVICE = APP_NAME
KEYRING_USER = "virustotal_api_key"


def _env_dir(var: str, fallback: Path) -> Path:
    value = os.environ.get(var)
    return Path(value) if value else fallback


def package_family() -> str | None:
    """The Store package this Python runs from (e.g. Microsoft Store Python), or None."""
    if sys.platform != "win32":
        return None
    import ctypes

    length = ctypes.c_uint32(0)
    kernel32 = ctypes.windll.kernel32
    if kernel32.GetCurrentPackageFamilyName(ctypes.byref(length), None) != 122:  # ERROR_INSUFFICIENT_BUFFER
        return None  # APPMODEL_ERROR_NO_PACKAGE: an ordinary install
    buf = ctypes.create_unicode_buffer(length.value)
    if kernel32.GetCurrentPackageFamilyName(ctypes.byref(length), buf) != 0:
        return None
    return buf.value


def _app_data(var: str, kind: str) -> Path:
    """%APPDATA% / %LOCALAPPDATA%, as other programs see it.

    Microsoft Store Python's writes there are quietly redirected into a private folder that
    Explorer and other programs can't see, so Atlas uses that folder's real address directly.
    Same files either way; this way "Open quarantine folder" and the right-click icon work.
    """
    family = package_family()
    local = _env_dir("LOCALAPPDATA", Path.home())
    if family:
        return local / "Packages" / family / "LocalCache" / kind
    return _env_dir(var, Path.home())


def config_dir() -> Path:
    return _env_dir("ATLAS_CONFIG_DIR", _app_data("APPDATA", "Roaming") / APP_NAME)


def data_dir() -> Path:
    return _env_dir("ATLAS_DATA_DIR", _app_data("LOCALAPPDATA", "Local") / APP_NAME)


# Windows "known folder" ids. These find the real location even when OneDrive has moved it.
FOLDER_DOWNLOADS = "374DE290-123F-4565-9164-39C4925E467B"
FOLDER_DESKTOP = "B4BFCC3A-DB2C-424C-B029-7FE99A87C641"
FOLDER_STARTUP = "B97D20BB-F46A-4C97-BA10-5E3608430854"
FOLDER_COMMON_STARTUP = "82A5EA35-D9CD-47C5-9629-E15D2F714E6E"


def known_folder(folder_id: str) -> Path | None:
    if sys.platform != "win32":
        return None
    import ctypes
    import uuid
    from ctypes import wintypes

    class GUID(ctypes.Structure):
        _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                    ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8)]

    u = uuid.UUID(folder_id)
    guid = GUID(u.fields[0], u.fields[1], u.fields[2], (ctypes.c_ubyte * 8)(*u.bytes[8:]))
    out = ctypes.c_wchar_p()
    if ctypes.windll.shell32.SHGetKnownFolderPath(ctypes.byref(guid), 0, None, ctypes.byref(out)) != 0:
        return None
    try:
        return Path(out.value)
    finally:
        ctypes.windll.ole32.CoTaskMemFree(out)


def default_watch_folders() -> list[str]:
    downloads = known_folder(FOLDER_DOWNLOADS) or Path.home() / "Downloads"
    desktop = known_folder(FOLDER_DESKTOP) or Path.home() / "Desktop"
    return [str(downloads), str(desktop)]


CONFIG_VERSION = 2


@dataclass
class Settings:
    config_version: int = CONFIG_VERSION
    watch_folders: list[str] = field(default_factory=default_watch_folders)
    # A file is "malicious" once this many engines flag it as malicious.
    # Fewer detections than this make it "suspicious" instead.
    malicious_threshold: int = 3
    quarantine_malicious: bool = True
    # Uploading shares the file with every VirusTotal Intelligence subscriber.
    # Keep this off unless you understand that; files are then only looked up by hash.
    upload_unknown_files: bool = False
    check_source_url: bool = True
    # Cached VirusTotal verdicts are reused for this long before asking again.
    cache_hours: int = 24
    notifications: bool = True
    # Re-check startup items (registry Run keys, startup folders, tasks, services) this often
    # and alert when something new has set itself to start automatically.
    monitor_autoruns: bool = True
    autorun_check_minutes: int = 10
    # Check running programs and network connections this often (0 = only when asked), and
    # alert when something flagged is running or being talked to.
    running_check_minutes: int = 60
    # Look up each program the moment it starts, and alert if it's flagged.
    watch_new_programs: bool = True
    # Check Defender, browser start pages and search, proxy, hosts file and DNS this often (0 = only when
    # asked), and alert when something new needs a look.
    system_check_minutes: int = 60
    # Look for a newer Project Atlas on GitHub once a day.
    check_for_updates: bool = True
    # With a Google Threat Intelligence key: download indicators from Google's Windows threat reports of
    # the last gti_days days once a day, match them against this PC, and show which reports mention a
    # flagged file. Does nothing on a key without GTI access.
    gti_enabled: bool = True
    gti_days: int = 90
    # Disk space tab: where to look, and what counts as big or worth de-duplicating.
    space_scan_folders: list[str] = field(default_factory=lambda: [str(Path.home())])
    big_file_min_mb: int = 500
    duplicate_min_mb: int = 10
    # Remote-access programs you use on purpose (e.g. ["TeamViewer"]): Atlas doesn't warn about these.
    trusted_remote_tools: list[str] = field(default_factory=list)
    # Sites you trust (e.g. ["live.com"]): the link checks skip Atlas's own guesses about them, but still ask
    # VirusTotal. "Always trust this site" adds to it.
    trusted_sites: list[str] = field(default_factory=list)
    # Also trust the sites on Project Atlas's shared allow-list (allowlist.json on GitHub, checked daily).
    shared_allowlist: bool = True
    # A weekly report (health score, what changed, what Atlas did), written by the tray once a week.
    weekly_report: bool = True
    # Full scan: at most this many new VirusTotal lookups per run (a free key allows 500 a day, 4 a minute).
    full_scan_lookups: int = 200

    @classmethod
    def load(cls) -> Settings:
        path = config_dir() / "config.json"
        if not path.exists():
            settings = cls()
            settings.save()
            return settings
        raw = json.loads(path.read_text(encoding="utf-8"))
        known = {k: v for k, v in raw.items() if k in cls.__dataclass_fields__}
        settings = cls(**known)
        if raw.get("config_version", 1) < CONFIG_VERSION:
            settings._upgrade(raw.get("config_version", 1))
            settings.save()
        return settings

    def _upgrade(self, from_version: int) -> None:
        if from_version < 2:
            # v0.2 also watches the Desktop.
            for folder in default_watch_folders():
                if folder not in self.watch_folders:
                    self.watch_folders.append(folder)
        self.config_version = CONFIG_VERSION

    def save(self) -> Path:
        path = config_dir() / "config.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")
        return path


def get_api_key() -> str | None:
    return os.environ.get("ATLAS_VT_API_KEY") or keyring.get_password(KEYRING_SERVICE, KEYRING_USER)


def set_api_key(key: str) -> None:
    keyring.set_password(KEYRING_SERVICE, KEYRING_USER, key)


def delete_api_key() -> None:
    try:
        keyring.delete_password(KEYRING_SERVICE, KEYRING_USER)
    except keyring.errors.PasswordDeleteError:
        pass
