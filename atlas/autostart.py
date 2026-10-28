"""Start Project Atlas (the tray app) when you sign in to Windows, via a Startup-folder shortcut."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def shortcut_path() -> Path:
    return Path(os.environ["APPDATA"]) / "Microsoft/Windows/Start Menu/Programs/Startup/Project Atlas.lnk"


def is_enabled() -> bool:
    return shortcut_path().exists()


def _tray_command() -> tuple[Path, str]:
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


def disable() -> None:
    shortcut_path().unlink(missing_ok=True)
