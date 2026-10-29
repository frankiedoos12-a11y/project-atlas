"""The packaged app (ProjectAtlas-Setup.exe): no Python on the PC, just two programs in one folder.

    ProjectAtlas.exe  the window and the tray, with no console (desktop and Start menu shortcuts)
    atlas.exe         the commands, the browser extension helper and the deep check (console)

Both accept `-m <module> args...` like python.exe does, so code that starts Atlas as
`python -m atlas ...` only has to swap in the right program.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

GUI_EXE = "ProjectAtlas.exe"
CLI_EXE = "atlas.exe"
# What `-m` can start: each module's main() reads sys.argv.
MODULES = {"atlas": "atlas.cli", "atlas.cli": "atlas.cli", "atlas.gui": "atlas.gui", "atlas.tray": "atlas.tray",
           "atlas.nativehost": "atlas.nativehost"}


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def program_dir() -> Path:
    return Path(sys.executable).resolve().parent


def gui_exe() -> Path:
    return program_dir() / GUI_EXE


def cli_exe() -> Path:
    return program_dir() / CLI_EXE


def run(argv: list[str], default: str) -> int:
    """Entry point of both programs: `-m module args...`, or the default module."""
    if len(argv) > 2 and argv[1] == "-m":
        module, rest = argv[2], argv[3:]
    else:
        module, rest = default, argv[1:]
    if module not in MODULES:
        print(f"Unknown module: {module}", file=sys.stderr)
        return 2
    sys.argv = [argv[0], *rest]
    return importlib.import_module(MODULES[module]).main() or 0
