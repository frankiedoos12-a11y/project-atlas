"""Is there a newer Project Atlas on GitHub? And one-click updating for installed copies.

Atlas reads the version number from the repository's atlas/__init__.py (a few bytes, no
account or token). Copies set up by install.ps1 update by re-running the installer in a
visible PowerShell window, so you can watch it; a git clone is left to `git pull`.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
import sys
from pathlib import Path

import requests

from atlas import __version__

log = logging.getLogger(__name__)

REPO = os.environ.get("ATLAS_REPO", "frankiedoos12-a11y/project-atlas")
BRANCH = os.environ.get("ATLAS_BRANCH", "main")
VERSION_URL = "https://raw.githubusercontent.com/{repo}/{branch}/atlas/__init__.py"
INSTALL_URL = "https://raw.githubusercontent.com/{repo}/{branch}/install.ps1"


def parse_version(text: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", text)[:3])


def is_newer(latest: str, current: str = __version__) -> bool:
    return parse_version(latest) > parse_version(current)


def latest_version(session: requests.Session | None = None) -> str | None:
    """The version on GitHub, or None if it couldn't be read (offline, GitHub down...)."""
    try:
        resp = (session or requests).get(VERSION_URL.format(repo=REPO, branch=BRANCH), timeout=15)
        resp.raise_for_status()
    except requests.RequestException as exc:
        log.info("Couldn't check for updates: %s", exc)
        return None
    m = re.search(r'__version__\s*=\s*"([^"]+)"', resp.text)
    return m.group(1) if m else None


def program_folder() -> Path:
    """The folder holding atlas/, extension/ and .venv/."""
    return Path(__file__).resolve().parent.parent


def install_kind(folder: Path | None = None) -> str:
    """ "installer" (set up by install.ps1), "git" (a clone), or "other"."""
    folder = folder or program_folder()
    if (folder / ".git").exists():
        return "git"
    if (folder / "install.ps1").exists() and (folder / ".venv").exists():
        return "installer"
    return "other"


def start_update(folder: Path | None = None) -> None:
    """Re-run the installer for this copy in a new PowerShell window. It stops Atlas, updates it and starts the
    tray again; settings, history and the key are kept."""
    folder = folder or program_folder()
    if install_kind(folder) != "installer":
        raise RuntimeError("This copy wasn't set up by the installer. Update it with git pull instead.")
    url = INSTALL_URL.format(repo=REPO, branch=BRANCH)
    env = dict(os.environ, ATLAS_INSTALL_DIR=str(folder), ATLAS_REPO=REPO, ATLAS_BRANCH=BRANCH)
    env.pop("ATLAS_NO_SETUP", None)
    command = f"irm {url} | iex; Write-Host ''; Read-Host 'Done. Press Enter to close'"
    log.info("Starting update of %s from %s", folder, url)
    subprocess.Popen(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
                     env=env, cwd=os.environ.get("USERPROFILE", str(folder)),
                     creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0))


def update_hint(latest: str) -> str:
    kind = install_kind()
    if kind == "installer":
        return f"Project Atlas {latest} is available (you have {__version__})."
    if kind == "git":
        return f"Project Atlas {latest} is on GitHub (you have {__version__}). Update this copy with git pull."
    return f"Project Atlas {latest} is available (you have {__version__}). Run the install line again to update."


if __name__ == "__main__":  # quick manual check
    latest = latest_version()
    print(latest, is_newer(latest) if latest else "?", install_kind(), file=sys.stderr)
