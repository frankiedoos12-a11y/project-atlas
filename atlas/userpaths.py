"""Programs running from folders any user can write to, and programs hidden inside other files.

Proper installers put programs in Program Files, which needs an administrator. Malware usually
can't, so it runs from AppData, Temp, Downloads or ProgramData instead. Plenty of honest programs
do too (Discord, Spotify, Teams, Zoom), but those are signed by their makers. Atlas lists the
ones that aren't validly signed, louder when they run from Temp or Downloads or appeared in the
last week, even if VirusTotal has never seen them.

It also looks for programs hidden in "alternate data streams": a second, invisible part of a
file (like holiday.jpg:payload.exe) that Explorer never shows.
"""

from __future__ import annotations

import ctypes
import logging
import os
import re
import sys
import time
from ctypes import wintypes
from dataclasses import dataclass, field
from pathlib import Path

from atlas.findings import NOTE, OK, WARN, Finding

log = logging.getLogger(__name__)

NEW_DAYS = 7
RISKY = re.compile(r"\\(temp|tmp|downloads|users\\public|windows\\temp|content\.outlook|inetcache)\\", re.I)
# Streams Windows and well-known programs add on their own.
NORMAL_STREAMS = {"::$data", ":zone.identifier:$data", ":smartscreen:$data", ":com.dropbox.attrs:$data",
                  ":ms-properties:$data", ":oecustomproperty:$data", ":encryptable:$data", ":afp_afpinfo:$data",
                  ":com.apple.quarantine:$data", ":favicon:$data", ":sec.endpointdlp:$data", ":{4c8cc155-6c1e-11d1-8e41-00c04fb9386d}:$data"}
MAX_STREAM_FILES = 5000


def user_roots() -> list[str]:
    """Folders any program running as you (or as anyone, for Public and ProgramData) can write to."""
    env = os.environ
    home = Path.home()
    roots = [env.get("LOCALAPPDATA"), env.get("APPDATA"), env.get("TEMP"), str(home / "Downloads"),
             str(home / "Desktop"), env.get("PUBLIC"), env.get("ProgramData"),
             os.path.join(env.get("WINDIR", r"C:\Windows"), "Temp")]
    return [os.path.normcase(r.rstrip("\\/")) + os.sep for r in roots if r]


@dataclass
class UserProgram:
    path: Path
    names: set[str] = field(default_factory=set)
    pids: set[int] = field(default_factory=set)
    created: float | None = None
    hidden_stream: bool = False  # running from an alternate data stream


def _atlas_folder() -> str:
    return os.path.normcase(str(Path(sys.prefix).parent)) + os.sep


def running_from_user_folders(procs: list[tuple[int, str, str]] | None = None) -> list[UserProgram]:
    """(pid, name, exe) of running processes -> programs whose file is in a user-writable folder."""
    if procs is None:
        import psutil

        procs = [(p.info["pid"], p.info["name"] or "", p.info["exe"] or "")
                 for p in psutil.process_iter(["pid", "name", "exe"])]
    roots, own = user_roots(), _atlas_folder()
    found: dict[str, UserProgram] = {}
    for pid, name, exe in procs:
        if not exe or not os.path.isabs(exe):
            continue
        key = os.path.normcase(exe)
        stream = ":" in exe[2:]  # C:\x\file.txt:hidden.exe
        if key.startswith(own) or not (stream or any(key.startswith(r) for r in roots)):
            continue
        item = found.setdefault(key, UserProgram(Path(exe), hidden_stream=stream))
        item.names.add(name)
        item.pids.add(pid)
        if item.created is None:
            try:
                item.created = os.stat(exe).st_ctime  # creation time on Windows
            except OSError:
                pass
    return list(found.values())


def judge(programs: list[UserProgram], signatures: dict, verdicts: dict | None = None,
          now: float | None = None) -> list[Finding]:
    """`signatures` maps str(path) to a Signature; `verdicts` (optional) to a VirusTotal Verdict value."""
    now = now or time.time()
    verdicts = verdicts or {}
    found, signed = [], 0
    for p in sorted(programs, key=lambda p: str(p.path).lower()):
        sig = signatures.get(str(p.path))
        where = f"{p.path} (running as {', '.join(sorted(p.names))})"
        common = dict(key=f"userpath:{str(p.path).lower()}", data={"path": str(p.path), "pids": sorted(p.pids)})
        if p.hidden_stream:
            found.append(Finding("User folders", f"Program running from a hidden part of a file: {p.path.name}",
                                 WARN, ["It runs from an alternate data stream, a hidden compartment Explorer never "
                                        "shows. Legitimate programs don't do this.", where], **common))
            continue
        if sig and sig.valid:
            signed += 1
            continue
        new = p.created is not None and now - p.created < NEW_DAYS * 86400
        risky = bool(RISKY.search(str(p.path)))
        verdict = verdicts.get(str(p.path))
        reasons = ["It isn't validly signed by its maker" + (f" ({sig.status})" if sig and sig.status not in
                                                              ("NotSigned", "Unavailable") else "")]
        if risky:
            reasons.append("It runs from a temporary or download folder, where programs are rarely meant to stay")
        if new:
            reasons.append(f"It appeared in the last {NEW_DAYS} days ({time.strftime('%Y-%m-%d', time.localtime(p.created))})")
        if verdict in ("unknown",):
            reasons.append("VirusTotal has never seen it")
        level = WARN if (risky or new or verdict in ("malicious", "suspicious")) else NOTE
        found.append(Finding("User folders", f"Unsigned program running from a user folder: {p.path.name}", level,
                             reasons + [where], **common))
    found.append(Finding("User folders", f"{signed} signed program(s) run from user folders", OK,
                         ["Discord, Teams, Zoom and similar install for just you, in AppData. Signed by their makers."],
                         key="userpath:signed"))
    return found


# --- Alternate data streams --------------------------------------------------------------------

class _StreamData(ctypes.Structure):
    _fields_ = [("StreamSize", ctypes.c_longlong), ("cStreamName", ctypes.c_wchar * 296)]


def streams(path: Path) -> list[tuple[str, int]]:
    """(":name:$DATA", size) for each data stream of a file (the main one is "::$DATA")."""
    if sys.platform != "win32":
        return []
    k32 = ctypes.windll.kernel32
    k32.FindFirstStreamW.restype = wintypes.HANDLE
    k32.FindFirstStreamW.argtypes = [wintypes.LPCWSTR, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    k32.FindNextStreamW.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    k32.FindClose.argtypes = [wintypes.HANDLE]
    data = _StreamData()
    handle = k32.FindFirstStreamW(str(path), 0, ctypes.byref(data), 0)
    if handle in (None, wintypes.HANDLE(-1).value):
        return []
    found = []
    try:
        while True:
            found.append((data.cStreamName, data.StreamSize))
            if not k32.FindNextStreamW(handle, ctypes.byref(data)):
                break
    finally:
        k32.FindClose(handle)
    return found


def hidden_programs(folders: list[Path] | None = None) -> list[Finding]:
    """Executables hidden in alternate data streams of files in Downloads, Desktop, Documents and Temp."""
    if folders is None:
        home = Path.home()
        folders = [home / "Downloads", home / "Desktop", home / "Documents", Path(os.environ.get("TEMP", home))]
    found, checked = [], 0
    for folder in folders:
        try:
            entries = list(folder.iterdir())
        except OSError:
            continue
        for entry in entries:
            if checked >= MAX_STREAM_FILES:
                break
            try:
                if not entry.is_file():
                    continue
            except OSError:
                continue
            checked += 1
            for name, size in streams(entry):
                if name.lower() in NORMAL_STREAMS or size < 64:
                    continue
                try:
                    with open(f"{entry}{name.removesuffix(':$DATA')}", "rb") as fh:
                        head = fh.read(2)
                except OSError:
                    continue
                if head == b"MZ":  # a Windows program
                    stream = name.removesuffix(":$DATA")
                    found.append(Finding("User folders", f"Program hidden inside {entry.name}", WARN,
                                         [f"{entry}{stream} is a Windows program ({size:,} bytes) tucked into a hidden "
                                          "stream of another file. Malware hides there because Explorer and most "
                                          "tools never show it."],
                                         key=f"ads:{str(entry).lower()}{stream.lower()}",
                                         data={"path": f"{entry}{stream}"}))
    return found
