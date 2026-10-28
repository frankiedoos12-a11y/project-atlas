"""Add "Scan with Project Atlas" to Explorer's right-click menu for files and folders.

The entry is registered for your user only (HKEY_CURRENT_USER), so no administrator
rights are needed, and removing it leaves nothing behind. On Windows 11 it appears under
"Show more options" (or Shift+right-click): the compact top menu only accepts entries
from packaged Store apps.
"""

from __future__ import annotations

import sys
from pathlib import Path

from atlas import config

if sys.platform == "win32":
    import winreg

VERB = "ProjectAtlas.Scan"
LABEL = "Scan with Project Atlas"
TARGETS = (r"Software\Classes\*\shell", r"Software\Classes\Directory\shell")


def command_line() -> str:
    """What Explorer runs, with "%1" replaced by the clicked file or folder."""
    scripts = Path(sys.executable).parent
    exe = scripts / "atlas-gui.exe"
    if exe.exists():
        return f'"{exe}" --scan "%1"'
    pythonw = scripts / "pythonw.exe"
    python = pythonw if pythonw.exists() else Path(sys.executable)
    return f'"{python}" -m atlas.gui --scan "%1"'


def icon_path() -> Path:
    """Atlas's globe as an .ico for the menu, drawn once into the data folder."""
    path = config.data_dir() / "atlas.ico"
    if not path.exists():
        from atlas.tray import make_icon

        path.parent.mkdir(parents=True, exist_ok=True)
        make_icon("ok").save(path, sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64)])
    return path


def is_enabled() -> bool:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, rf"{TARGETS[0]}\{VERB}\command") as key:
            return bool(winreg.QueryValueEx(key, "")[0])
    except OSError:
        return False


def enable() -> None:
    icon = str(icon_path())
    for base in TARGETS:
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, rf"{base}\{VERB}") as key:
            winreg.SetValueEx(key, "", 0, winreg.REG_SZ, LABEL)
            winreg.SetValueEx(key, "Icon", 0, winreg.REG_SZ, icon)
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, rf"{base}\{VERB}\command") as key:
            winreg.SetValueEx(key, "", 0, winreg.REG_SZ, command_line())


def disable() -> None:
    for base in TARGETS:
        for sub in (rf"{base}\{VERB}\command", rf"{base}\{VERB}"):
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, sub)
            except FileNotFoundError:
                pass
