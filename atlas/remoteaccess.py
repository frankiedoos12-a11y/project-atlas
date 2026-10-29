"""Remote-access programs: the tools tech-support scammers talk people into installing.

AnyDesk, TeamViewer, ScreenConnect, Quick Assist and the rest are legitimate, but a caller who
asks you to install one can see and control the PC, empty bank accounts and plant malware.
Atlas lists the ones that are installed, running or sitting in Downloads, and the tray speaks
up the moment one starts. Programs you use on purpose can be marked as yours
(`trusted_remote_tools` in the settings); Atlas then stays quiet about them.
"""

from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass
from pathlib import Path

from atlas.findings import NOTE, OK, WARN, Finding

SCAM_ADVICE = ("If someone you don't know (a phone call, a pop-up, an email about a refund or a virus) asked you to "
               "install or open it, it's a scam: hang up, end it with the button below, and call your bank if you "
               "logged in to it.")


@dataclass(frozen=True)
class Tool:
    name: str
    files: re.Pattern  # program file names (running processes, downloaded copies)
    installed: re.Pattern | None = None  # names in Settings > Apps


def _files(*names: str) -> re.Pattern:
    return re.compile(r"^(?:" + "|".join(names) + r")\.exe$", re.I)


def _names(pattern: str) -> re.Pattern:
    return re.compile(pattern, re.I)


TOOLS = [
    Tool("AnyDesk", _files(r"anydesk[\w ().-]*"), _names(r"^anydesk")),
    Tool("TeamViewer", _files(r"teamviewer[\w ().-]*", r"tv_w32", r"tv_x64"), _names(r"^teamviewer")),
    Tool("ScreenConnect (ConnectWise Control)", _files(r"screenconnect[\w .-]*", r"connectwisecontrol[\w .-]*"),
         _names(r"screenconnect|connectwise control")),
    Tool("Quick Assist", _files(r"quickassist"), None),
    Tool("RustDesk", _files(r"rustdesk[\w ().-]*"), _names(r"^rustdesk")),
    Tool("UltraViewer", _files(r"ultraviewer[\w .-]*"), _names(r"^ultraviewer")),
    Tool("Splashtop", _files(r"strwinclt", r"srserver", r"srmanager", r"splashtop[\w .-]*"), _names(r"^splashtop")),
    Tool("LogMeIn / GoTo", _files(r"logmein[\w .-]*", r"lmiguardiansvc", r"gotoassist[\w .-]*",
                                  r"goto ?resolve[\w .-]*", r"g2ax_[\w]+"), _names(r"^logmein|^goto (assist|resolve)")),
    Tool("Supremo", _files(r"supremo[\w .-]*"), _names(r"^supremo")),
    Tool("AeroAdmin", _files(r"aeroadmin[\w .-]*"), _names(r"^aeroadmin")),
    Tool("Ammyy Admin", _files(r"aa_v\d+", r"ammyy[\w .-]*"), _names(r"^ammyy")),
    Tool("Zoho Assist", _files(r"zohoassist[\w .-]*", r"zaservice", r"zohotray"), _names(r"^zoho assist")),
    Tool("RemotePC", _files(r"remotepc[\w .-]*", r"rpcsuite"), _names(r"^remotepc")),
    Tool("NetSupport", _files(r"client32", r"pcicfgui"), _names(r"^netsupport")),
    Tool("Remote Utilities", _files(r"rutserv", r"rfusclient", r"rutview"), _names(r"^remote utilities")),
    Tool("Chrome Remote Desktop", _files(r"remoting_host", r"remoting_desktop"),
         _names(r"^chrome remote desktop")),
    Tool("VNC", _files(r"tvnserver", r"winvnc\d*", r"vncserver", r"vncviewer", r"uvnc_service"),
         _names(r"tightvnc|ultravnc|realvnc|tigervnc|vnc server")),
    Tool("HopToDesk", _files(r"hoptodesk[\w .-]*"), _names(r"^hoptodesk")),
    Tool("Getscreen.me", _files(r"getscreen[\w .-]*"), _names(r"^getscreen")),
    Tool("DWService", _files(r"dwagent[\w .-]*", r"dwagsvc"), _names(r"^dwagent|^dwservice")),
    Tool("SimpleHelp", _files(r"remote access", r"simplehelp[\w .-]*", r"simpleservice"), _names(r"^simplehelp")),
    Tool("MeshCentral", _files(r"meshagent[\w .-]*"), _names(r"^mesh ?agent")),
    Tool("Atera", _files(r"ateraagent"), _names(r"^atera ?agent")),
    Tool("Action1", _files(r"action1_agent[\w .-]*"), _names(r"^action1")),
    Tool("Level", _files(r"level-windows-amd64"), _names(r"^level agent")),
    Tool("FleetDeck", _files(r"fleetdeck[\w .-]*"), _names(r"^fleetdeck")),
    Tool("Parsec", _files(r"parsecd"), _names(r"^parsec")),
]
DOWNLOAD_DAYS = 30  # downloaded copies older than this aren't worth a warning on their own


def match_file(name: str) -> Tool | None:
    return next((t for t in TOOLS if t.files.match(name)), None)


def match_program(name: str) -> Tool | None:
    return next((t for t in TOOLS if t.installed and t.installed.search(name.strip())), None)


def is_trusted(tool: Tool, trusted: list[str]) -> bool:
    return tool.name.lower() in {t.lower() for t in trusted}


def running_tools() -> dict[str, tuple[Tool, set[int], set[str]]]:
    """Remote-access tools running now: name -> (tool, pids, program paths)."""
    import psutil

    found: dict[str, tuple[Tool, set[int], set[str]]] = {}
    for p in psutil.process_iter(["pid", "name", "exe"]):
        tool = match_file(p.info["name"] or "")
        if tool:
            entry = found.setdefault(tool.name, (tool, set(), set()))
            entry[1].add(p.info["pid"])
            if p.info["exe"]:
                entry[2].add(p.info["exe"])
    return found


def installed_tools(names: list[str]) -> dict[str, tuple[Tool, str]]:
    found: dict[str, tuple[Tool, str]] = {}
    for name in names:
        tool = match_program(name)
        if tool:
            found.setdefault(tool.name, (tool, name))
    return found


def downloaded_copies(folders: list[Path], now: float | None = None) -> dict[str, tuple[Tool, list[Path]]]:
    """Remote-access programs saved in Downloads or on the Desktop in the last month: scammers have people
    download the portable version, which never shows up in Settings > Apps."""
    now = now or time.time()
    found: dict[str, tuple[Tool, list[Path]]] = {}
    for folder in folders:
        try:
            entries = list(os.scandir(folder))
        except OSError:
            continue
        for entry in entries:
            tool = match_file(entry.name)
            try:
                recent = entry.is_file() and now - entry.stat().st_mtime < DOWNLOAD_DAYS * 86400
            except OSError:
                continue
            if tool and recent:
                found.setdefault(tool.name, (tool, []))[1].append(Path(entry.path))
    return found


def remote_findings(running: dict, installed: dict, downloaded: dict, trusted: list[str]) -> list[Finding]:
    found: list[Finding] = []
    names = sorted(set(running) | set(installed) | set(downloaded))
    for name in names:
        tool = (running.get(name) or installed.get(name) or downloaded.get(name))[0]
        key = re.sub(r"\W+", "-", name.lower())
        if is_trusted(tool, trusted):
            found.append(Finding("Remote access", f"{name} (marked as yours)", OK,
                                 ["You said you use this on purpose, so Atlas doesn't warn about it."],
                                 key=f"remote:{key}:trusted", fix="untrust-remote", fix_label="Not mine after all",
                                 data={"tool": name}))
            continue
        where = []
        if name in installed:
            where.append(f"Installed as \"{installed[name][1]}\".")
        if name in downloaded:
            where += [f"Downloaded: {p}" for p in downloaded[name][1][:3]]
        if name in running:
            pids, exes = running[name][1], running[name][2]
            details = [f"{name} is running right now, so someone may be able to see and control this PC.",
                       SCAM_ADVICE] + where + [f"Program: {e}" for e in sorted(exes)[:3]]
            found.append(Finding("Remote access", f"{name} is running", WARN, details, key=f"remote:{key}:running",
                                 fix="end-remote", fix_label=f"End {name}...",
                                 data={"tool": name, "pids": sorted(pids)}))
        elif name in downloaded:
            found.append(Finding("Remote access", f"{name} was downloaded recently", WARN,
                                 ["Scammers often ask people to download this so they can take over the PC.",
                                  SCAM_ADVICE] + where, key=f"remote:{key}:downloaded", fix="trust-remote",
                                 fix_label="It's mine", data={"tool": name}))
        else:
            found.append(Finding("Remote access", f"{name} is installed", NOTE,
                                 ["It lets someone see and control this PC when it runs. Fine if you or your IT "
                                  "person use it; if you don't know why it's here, uninstall it (Installed tab).",
                                  ] + where, key=f"remote:{key}:installed", fix="trust-remote",
                                 fix_label="It's mine", data={"tool": name}))
    if not found:
        found.append(Finding("Remote access", "No remote-access programs found", OK,
                             ["None of the tools scammers use to take over a PC (AnyDesk, TeamViewer, ScreenConnect, "
                              f"Quick Assist and {len(TOOLS) - 4} others) are installed, running or downloaded."],
                             key="remote:none"))
    return found


def check_remote_access(trusted: list[str], download_folders: list[Path]) -> list[Finding]:
    from atlas.installed import list_installed

    installed = installed_tools([p.name for p in list_installed()])
    return remote_findings(running_tools(), installed, downloaded_copies(download_folders), trusted)


def started_alert(name: str) -> tuple[str, str]:
    """The tray pop-up when a remote-access tool starts."""
    return (f"Atlas: {name} just started",
            f"Someone may be able to see and control this PC. If a caller or pop-up asked you to run it, it's a "
            f"scam: hang up and end it (Protection page).")
