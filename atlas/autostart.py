"""Start Project Atlas (the tray app) when you sign in to Windows, via a Startup-folder shortcut."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from atlas import frozen


def shortcut_path() -> Path:
    return Path(os.environ["APPDATA"]) / "Microsoft/Windows/Start Menu/Programs/Startup/Project Atlas.lnk"


def is_enabled() -> bool:
    return shortcut_path().exists()


def _tray_command() -> tuple[Path, str]:
    if frozen.is_frozen():
        return frozen.gui_exe(), "-m atlas.tray"
    scripts = Path(sys.executable).parent
    tray_exe = scripts / "atlas-tray.exe"
    if tray_exe.exists():
        return tray_exe, ""
    pythonw = scripts / "pythonw.exe"
    return (pythonw if pythonw.exists() else Path(sys.executable)), "-m atlas tray"


def enable() -> Path:
    target, args = _tray_command()
    script = (
        "$s = (New-Object -ComObject WScript.Shell).CreateShortcut($env:ATLAS_LNK);"
        "$s.TargetPath = $env:ATLAS_EXE; $s.Arguments = $env:ATLAS_ARGS;"
        "$s.WorkingDirectory = $env:USERPROFILE; $s.Description = 'Project Atlas'; $s.Save()"
    )
    subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script], check=True,
        env={**os.environ, "ATLAS_LNK": str(shortcut_path()), "ATLAS_EXE": str(target), "ATLAS_ARGS": args},
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    return shortcut_path()


def is_mine() -> bool:
    """Does the sign-in shortcut start this copy of Atlas (and not another one on the PC)?"""
    if not is_enabled():
        return False
    # Windows stores the target in pieces inside the .lnk, so ask Windows for it.
    script = "(New-Object -ComObject WScript.Shell).CreateShortcut($env:ATLAS_LNK).TargetPath"
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script], capture_output=True, text=True,
        env={**os.environ, "ATLAS_LNK": str(shortcut_path())},
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    return result.stdout.strip().lower() == str(_tray_command()[0]).lower()


def disable() -> None:
    shortcut_path().unlink(missing_ok=True)
