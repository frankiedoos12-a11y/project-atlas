"""System checks in one place: Defender (atlas.defender) and hijacks (atlas.hijack), plus the
Fix buttons.

Atlas only changes two things itself, after you confirm and with a backup first: your own
proxy setting, and browser policies set in your own account. Everything else either opens the
right page in Windows Security, Settings or the browser, or (for the hosts file) opens it in
Notepad as administrator so you can edit it yourself.
"""

from __future__ import annotations

import ctypes
import json
import logging
import os
import subprocess
import sys
import time
from pathlib import Path

from atlas import config
from atlas.browsers import SETTINGS_PAGES
from atlas.defender import check_defender
from atlas.findings import NOTE, OK, WARN, Finding
from atlas.hijack import HOSTS, INTERNET_SETTINGS, check_hijacks

log = logging.getLogger(__name__)

NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
ORDER = {WARN: 0, NOTE: 1, OK: 2}


def check_system(scanner=None) -> list[Finding]:
    """Every system check, worst first. `scanner` (optional) lets sites and addresses be looked up."""
    lookup = scanner.lookup if scanner is not None and scanner.vt is not None else None
    threshold = scanner.settings.malicious_threshold if scanner is not None else 3
    found = check_defender() + check_hijacks(lookup, threshold)
    return sorted(found, key=lambda f: ORDER.get(f.level, 3))


def _backup(name: str, data: dict) -> Path:
    folder = config.data_dir() / "backups"
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{name}-{time.strftime('%Y%m%d-%H%M%S')}.json"
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    return path


def describe_fix(f: Finding) -> str:
    """What pressing Fix will do, for the confirmation question."""
    return {
        "proxy-off": "Turn off the proxy setting in your account? Your current settings are saved to a backup file "
                     "first. If a VPN or antivirus you use needs it, it will turn it back on.",
        "remove-policy": f"Remove the \"{f.data.get('name')}\" policy from your account, so you can change "
                         "the setting yourself again? A backup is saved first. Restart the browser afterwards.",
        "edit-hosts": "Open the hosts file in Notepad as administrator? Windows will ask for permission. Delete the "
                      "lines Atlas pointed out, then save.",
    }.get(f.fix or "", "")


def apply_fix(f: Finding) -> str:
    """Do what the finding's Fix button says. Returns a message for the user."""
    if f.fix == "open":
        os.startfile(f.data["url"])
        return ""
    if f.fix == "browser-settings":
        scheme = SETTINGS_PAGES.get(f.data["browser"], "chrome")
        args = ["cmd", "/c", "start", "", f.data["exe"].removesuffix(".exe")]
        if f.data.get("profile"):
            args.append(f"--profile-directory={f.data['profile']}")
        subprocess.Popen(args + [f"{scheme}://settings/{f.data.get('page', 'onStartup')}"], creationflags=NO_WINDOW)
        return ""
    if f.fix == "proxy-off":
        return _proxy_off(f)
    if f.fix == "remove-policy":
        return _remove_policy(f)
    if f.fix == "edit-hosts":
        result = ctypes.windll.shell32.ShellExecuteW(None, "runas", "notepad.exe", str(HOSTS), None, 1)
        if result <= 32:
            raise OSError("Notepad wasn't started (permission was refused?)")
        return ""
    raise ValueError(f"Nothing to fix for {f.title}")


def _proxy_off(f: Finding) -> str:
    import winreg

    backup = _backup("proxy", f.data)
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS, 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
        try:
            winreg.DeleteValue(key, "AutoConfigURL")
        except FileNotFoundError:
            pass
    _tell_windows_internet_settings_changed()
    log.info("Proxy turned off (backup %s)", backup)
    return f"The proxy is off. Backup of the old settings: {backup}"


def _tell_windows_internet_settings_changed() -> None:
    if sys.platform != "win32":
        return
    wininet = ctypes.windll.wininet
    wininet.InternetSetOptionW(None, 39, None, 0)  # INTERNET_OPTION_SETTINGS_CHANGED
    wininet.InternetSetOptionW(None, 37, None, 0)  # INTERNET_OPTION_REFRESH


def _remove_policy(f: Finding) -> str:
    import winreg

    backup = _backup("browser-policy", f.data)
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, f.data["key"], 0, winreg.KEY_SET_VALUE) as key:
        winreg.DeleteValue(key, f.data["name"])
    log.info("Removed browser policy %s\\%s (backup %s)", f.data["key"], f.data["name"], backup)
    return f"Policy removed. Restart the browser, then set it the way you want. Backup: {backup}"
