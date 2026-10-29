"""Connect the Project Atlas browser extension to Atlas on this PC.

The extension (the `extension` folder next to the `atlas` package) can't hold the
VirusTotal key, so it asks a small helper program (atlas.nativehost) instead. Browsers
only start helpers they've been told about, via a registry entry per browser pointing
at a manifest that names the one extension allowed to use it.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from atlas import config, frozen
from atlas.nativehost import HOST_NAME

if sys.platform == "win32":
    import winreg

# Fixed by the "key" in extension/manifest.json, so it's the same on every PC.
from atlas.browsers import ATLAS_EXTENSION_ID as EXTENSION_ID  # noqa: E402

BROWSER_KEYS = {
    "Chrome": r"Software\Google\Chrome\NativeMessagingHosts",
    "Edge": r"Software\Microsoft\Edge\NativeMessagingHosts",
    "Brave": r"Software\BraveSoftware\Brave-Browser\NativeMessagingHosts",
}
EXTENSION_PAGES = {"Chrome": ("chrome", "chrome://extensions"), "Edge": ("msedge", "edge://extensions"),
                   "Brave": ("brave", "brave://extensions")}


def extension_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "extension"


def host_dir() -> Path:
    return config.data_dir() / "browser"


def write_host_files() -> Path:
    """The helper's launcher and manifest. Returns the manifest's path."""
    folder = host_dir()
    folder.mkdir(parents=True, exist_ok=True)
    python = Path(sys.executable)  # console python: the browser talks to it over stdin/stdout
    if frozen.is_frozen():
        python = frozen.cli_exe()
    if python.name.lower() == "pythonw.exe":
        python = python.with_name("python.exe")
    launcher = folder / "atlas-link-helper.bat"
    launcher.write_text(f'@echo off\r\n"{python}" -m atlas.nativehost %*\r\n', encoding="utf-8")
    manifest = folder / f"{HOST_NAME}.json"
    manifest.write_text(json.dumps({
        "name": HOST_NAME,
        "description": "Project Atlas link checker",
        "path": str(launcher),
        "type": "stdio",
        "allowed_origins": [f"chrome-extension://{EXTENSION_ID}/"],
    }, indent=2), encoding="utf-8")
    return manifest


def is_enabled() -> bool:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, rf"{BROWSER_KEYS['Chrome']}\{HOST_NAME}") as key:
            return Path(winreg.QueryValueEx(key, "")[0]).exists()
    except OSError:
        return False


def enable() -> Path:
    manifest = write_host_files()
    for base in BROWSER_KEYS.values():
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, rf"{base}\{HOST_NAME}") as key:
            winreg.SetValueEx(key, "", 0, winreg.REG_SZ, str(manifest))
    return manifest


def is_mine() -> bool:
    """Is the browser helper registered to this copy of Atlas?"""
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, rf"{BROWSER_KEYS['Chrome']}\{HOST_NAME}") as key:
            return Path(winreg.QueryValueEx(key, "")[0]) == host_dir() / f"{HOST_NAME}.json"
    except OSError:
        return False


def disable() -> None:
    for base in BROWSER_KEYS.values():
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, rf"{base}\{HOST_NAME}")
        except FileNotFoundError:
            pass


def open_extensions_page(browser: str) -> None:
    exe, url = EXTENSION_PAGES[browser]
    subprocess.Popen(["cmd", "/c", "start", "", exe, url], creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
