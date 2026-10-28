"""Open doors: programs accepting connections from the network, and the firewall rules letting them in.

A backdoor or a forgotten remote-access tool waits for connections. Atlas lists every program
listening on a network address (not just on this PC), says which are Windows' own, and points out
remote-access tools. It also checks that Windows Firewall is on, and reads its inbound rules from
the registry (much faster than PowerShell) to find ones that let in programs from user folders,
or programs that are gone. The programs themselves are looked up on VirusTotal by the caller.

Read-only: nothing is closed or blocked.
"""

from __future__ import annotations

import logging
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

from atlas.findings import NOTE, OK, WARN, Finding

log = logging.getLogger(__name__)

FIREWALL = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"
PROFILES = {"DomainProfile": "Domain", "StandardProfile": "Private", "PublicProfile": "Public"}
REMOTE_ACCESS = re.compile(r"anydesk|teamviewer|screenconnect|connectwise|splashtop|rustdesk|ultravnc|tightvnc|"
                           r"realvnc|winvnc|tvnserver|vncserver|atera|ammyy|aa_v3|supremo|logmein|radmin|"
                           r"client32\.exe|netsupport|rutserv|rfusclient|remote utilities|dameware|bomgar|"
                           r"beyondtrust|goto ?(assist|resolve)|zohoassist|getscreen|meshagent|level\.exe|"
                           r"simplehelp|remotepc|chrome ?remote ?desktop|remoting_host", re.I)
USER_FOLDERS = re.compile(r"\\(appdata|temp|downloads|users\\public|desktop)\\", re.I)


@dataclass
class Listener:
    pid: int
    program: str
    path: str | None
    ports: set[str] = field(default_factory=set)  # e.g. "TCP 3389", "UDP 5353"
    addresses: set[str] = field(default_factory=set)


def _loopback(ip: str) -> bool:
    return ip.startswith("127.") or ip in ("::1", "localhost")


def listeners() -> list[Listener]:
    """Programs listening on a network-facing address (every address, or a specific one)."""
    import socket

    import psutil

    procs: dict[int, tuple[str, str | None]] = {}
    found: dict[str, Listener] = {}  # one per program file
    for c in psutil.net_connections("inet"):
        tcp = c.type == socket.SOCK_STREAM
        if (tcp and c.status != psutil.CONN_LISTEN) or (not tcp and c.raddr) or not c.laddr:
            continue
        if _loopback(c.laddr.ip):
            continue
        pid = c.pid or 0
        if pid not in procs:
            try:
                p = psutil.Process(pid)
                procs[pid] = (p.name(), p.exe() or None)
            except (psutil.Error, OSError):
                procs[pid] = ("System" if pid in (0, 4) else f"process {pid}", None)
        name, path = procs[pid]
        # UDP "listeners" are mostly network discovery and the random ports QUIC/WebRTC clients bind:
        # only remote-access tools are worth listing for UDP.
        if not tcp and not REMOTE_ACCESS.search(f"{name} {path or ''}"):
            continue
        item = found.setdefault(os.path.normcase(path or name), Listener(pid, name, path))
        item.ports.add(f"{'TCP' if tcp else 'UDP'} {c.laddr.port}")
        item.addresses.add(c.laddr.ip)
    return list(found.values())


def is_windows_program(path: str | None, name: str = "") -> bool:
    if not path:
        return name in ("System", "svchost.exe", "lsass.exe", "wininit.exe", "services.exe", "spoolsv.exe")
    windows = os.path.normcase(os.environ.get("WINDIR", r"C:\Windows")) + os.sep
    return os.path.normcase(path).startswith(windows)


def _ports(ports: set[str]) -> str:
    items = sorted(ports, key=lambda p: (p.split()[0], int(p.split()[1])))
    return ", ".join(items[:8]) + (f" and {len(items) - 8} more" if len(items) > 8 else "")


def listener_findings(items: list[Listener]) -> list[Finding]:
    """Remote-access tools and other programs that accept connections. Verdicts come separately."""
    found, windows = [], []
    for item in sorted(items, key=lambda i: i.program.lower()):
        if is_windows_program(item.path, item.program):
            windows.append(item)
            continue
        where = f"{item.program} ({item.path or 'program file not visible'}) listens on {_ports(item.ports)}"
        common = dict(key=f"listen:{(item.path or item.program).lower()}", data={"path": item.path, "pid": item.pid})
        if REMOTE_ACCESS.search(f"{item.program} {item.path or ''}"):
            found.append(Finding("Listening", f"Remote-access tool waiting for connections: {item.program}", WARN,
                                 ["Anyone with its ID and password can see and control this PC. Fine if you use it; "
                                  "scammers install these tools too, and they're often forgotten afterwards. "
                                  "Uninstall it if nobody here uses it.", where], **common))
        else:
            found.append(Finding("Listening", f"{item.program} accepts network connections", NOTE,
                                 ["Usually a program that shares, streams or syncs over your home network (a game, "
                                  "media server, printer or phone app). Worth knowing which programs do.", where],
                                 **common))
    if windows:
        names = sorted({w.program for w in windows})
        found.append(Finding("Listening", f"Windows' own services listen on {sum(len(w.ports) for w in windows)} "
                             "port(s)", OK, [", ".join(names)], key="listen:windows"))
    return found


# --- Firewall -------------------------------------------------------------------------------

def _firewall_values() -> tuple[dict[str, int | None], list[str]]:
    """(profile -> EnableFirewall, inbound rule strings) from the registry; policy settings win."""
    if sys.platform != "win32":
        return {}, []
    import winreg

    def read(path: str, name: str):
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
                return winreg.QueryValueEx(key, name)[0]
        except OSError:
            return None

    profiles = {}
    for key, label in PROFILES.items():
        policy = read(rf"SOFTWARE\Policies\Microsoft\WindowsFirewall\{key}", "EnableFirewall")
        profiles[label] = policy if policy is not None else read(rf"{FIREWALL}\{key}", "EnableFirewall")
    rules = []
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, rf"{FIREWALL}\FirewallRules") as key:
            for i in range(winreg.QueryInfoKey(key)[1]):
                value = winreg.EnumValue(key, i)[1]
                if isinstance(value, str):
                    rules.append(value)
    except OSError:
        pass
    return profiles, rules


def parse_rule(text: str) -> dict[str, str]:
    """"v2.33|Action=Allow|Active=TRUE|Dir=In|App=C:\\x.exe|Name=X|" -> {"Action": "Allow", ...}"""
    fields = {}
    for part in text.split("|"):
        if "=" in part:
            k, v = part.split("=", 1)
            fields.setdefault(k, v)
    return fields


def firewall_findings(profiles: dict[str, int | None] | None = None, rules: list[str] | None = None) -> list[Finding]:
    if profiles is None or rules is None:
        profiles, rules = _firewall_values()
    found = []
    off = [name for name, on in profiles.items() if on == 0]
    if off:
        found.append(Finding("Firewall", f"Windows Firewall is off for {', '.join(off)} networks", WARN,
                             ["Without it, any program listening for connections can be reached from the network. "
                              "Turn it back on unless another security suite's firewall has taken over."],
                             key="firewall:off:" + ",".join(off), fix="open", fix_label="Open Firewall settings",
                             data={"url": "windowsdefender://network"}))
    elif profiles:
        found.append(Finding("Firewall", "Windows Firewall is on for every network type", OK, key="firewall:on"))
    apps: dict[str, dict] = {}  # one entry per program, however many rules (TCP, UDP, per profile) it has
    for text in rules:
        r = parse_rule(text)
        if r.get("Action") != "Allow" or r.get("Dir") != "In" or r.get("Active", "").upper() != "TRUE":
            continue
        app = os.path.expandvars(r.get("App", ""))
        if not app or not USER_FOLDERS.search(app):
            continue
        entry = apps.setdefault(app.lower(), {"app": app, "names": set(), "public": False})
        name = r.get("Name", "?")
        entry["names"].add(name if not name.startswith("@") else Path(app).name)
        entry["public"] |= "Public" in r.get("Profile", "Public") or "Profile" not in r
    for entry in apps.values():
        app, exists = entry["app"], Path(entry["app"]).exists()
        names = ", ".join(f"\"{n}\"" for n in sorted(entry["names"]))
        found.append(Finding(
            "Firewall", f"Firewall lets in a program from a user folder: {Path(app).name}", NOTE,
            ([f"Rule {names} allows incoming connections to {app}" +
              (" on any network, public Wi-Fi included." if entry["public"] else " on home and work networks.")] +
             (["Games and chat apps often add these (Windows asks the first time they run). Atlas looks the program "
               "up; worth a look if you don't recognise it."] if exists else
              ["The program is gone, so the rule is a leftover. Harmless, but it would let in anything placed there "
               "again; remove it in Windows Defender Firewall > Advanced settings > Inbound Rules."])),
            key=f"firewall:rule:{app.lower()}", fix="open", fix_label="Open Firewall settings",
            data={"url": "wf.msc", "path": app if exists else None}))
    return found
