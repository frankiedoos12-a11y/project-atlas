"""Shared start-up plumbing for the command line and the tray app."""

from __future__ import annotations

import logging
import subprocess
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

from atlas import config, frozen
from atlas.db import Store
from atlas.scanner import Scanner
from atlas.vt_client import VTClient

_instance_mutex = None


def log_file() -> Path:
    return config.data_dir() / "atlas.log"


def setup_logging(verbose: bool = False) -> None:
    path = log_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    handlers: list[logging.Handler] = [RotatingFileHandler(path, maxBytes=2_000_000, backupCount=3, encoding="utf-8")]
    if sys.stderr is not None:  # pythonw.exe (the tray app) has no console
        handlers.append(logging.StreamHandler())
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s", handlers=handlers)


def build_scanner(settings: config.Settings) -> tuple[Scanner, Store]:
    data = config.data_dir()
    store = Store(data / "atlas.db")
    key = config.get_api_key()
    vt = VTClient(key) if key else None
    if vt:
        vt.on_request = store.count_vt_request
    return Scanner(settings, store, vt, data), store


USAGE_KINDS = {"files": "files", "urls": "links", "domains": "sites", "ip_addresses": "addresses",
               "uploads": "uploads"}


def vt_usage(store: Store) -> dict:
    """Atlas's own VirusTotal requests today and this month (all of Atlas on this PC: tray, window, helpers).

    VirusTotal doesn't let this key read the account's quota, so this counts what Atlas sends.
    Cached answers aren't counted: they never reach VirusTotal.
    """
    from datetime import date

    today = date.today()
    day = store.vt_usage(today.isoformat())
    month = store.vt_usage(today.replace(day=1).isoformat())
    return {"today": sum(r for r, _ in day.values()), "month": sum(r for r, _ in month.values()),
            "throttled_today": sum(t for _, t in day.values()),
            "today_by_kind": {USAGE_KINDS.get(k, k): r for k, (r, _) in sorted(day.items(), key=lambda x: -x[1][0])}}


def vt_usage_text(store: Store) -> str:
    u = vt_usage(store)
    text = f"{u['today']:,} VirusTotal lookups today, {u['month']:,} this month"
    if u["throttled_today"]:
        text += f" ({u['throttled_today']} slowed down by VirusTotal's rate limit)"
    return text


def watch_folders(settings: config.Settings) -> list[Path]:
    return [Path(f).expanduser() for f in settings.watch_folders]


MUTEX_NAME = "Local\\ProjectAtlasGuard"


def guard_running() -> bool:
    """True if the tray app or `atlas guard` is protecting this PC right now."""
    if sys.platform != "win32":
        return False
    import ctypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenMutexW.restype = ctypes.c_void_p
    handle = kernel32.OpenMutexW(0x00100000, False, MUTEX_NAME)  # SYNCHRONIZE
    if handle:
        kernel32.CloseHandle(ctypes.c_void_p(handle))
        return True
    return False


def _launch(gui_script: str, module_command: str) -> None:
    """Start an Atlas GUI process (tray or window) with no console window."""
    if frozen.is_frozen():
        subprocess.Popen([str(frozen.gui_exe()), "-m", f"atlas.{module_command}"], close_fds=True,
                         creationflags=getattr(subprocess, "DETACHED_PROCESS", 0))
        return
    scripts = Path(sys.executable).parent
    exe = scripts / f"{gui_script}.exe"
    if exe.exists():
        cmd = [str(exe)]
    else:
        pythonw = scripts / "pythonw.exe"
        cmd = [str(pythonw if pythonw.exists() else sys.executable), "-m", "atlas", module_command]
    subprocess.Popen(cmd, close_fds=True, creationflags=getattr(subprocess, "DETACHED_PROCESS", 0))


def launch_tray() -> None:
    _launch("atlas-tray", "tray")


def launch_gui() -> None:
    _launch("atlas-gui", "gui")


def claim_single_instance() -> bool:
    """True if no other Atlas guard (console or tray) is running. Held until this process exits."""
    global _instance_mutex
    if sys.platform != "win32":
        return True
    import ctypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateMutexW.restype = ctypes.c_void_p
    _instance_mutex = kernel32.CreateMutexW(None, False, MUTEX_NAME)
    return ctypes.get_last_error() != 183  # ERROR_ALREADY_EXISTS
