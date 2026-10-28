"""Installed programs audit: what's installed, and is any of it adware or worse?

Atlas reads the same list as Settings > Apps, finds each program's main file, and looks it
up on VirusTotal. Engines label adware and "potentially unwanted programs" (PUPs: toolbars,
fake optimisers, browsers that install themselves) separately from malware, so those get
called out by name. Known PUP families are recognised even without VirusTotal.

Uninstalling runs the program's own uninstaller, and only when you press the button.
"""

from __future__ import annotations

import ctypes
import logging
import re
import shlex
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from atlas.processes import RunningFile, judge_files
from atlas.scanner import Scanner, Verdict

log = logging.getLogger(__name__)

UNINSTALL_KEYS = [("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "all users"),
                  ("HKLM", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall", "all users"),
                  ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Uninstall", "this user")]
PUP_KINDS = re.compile(r"adware|\bpua\b|\bpup\b|riskware|grayware|greyware|unwanted|bundler|toolbar|hacktool", re.I)
# Long-known adware and potentially unwanted programs, often spread through download scams and ads.
KNOWN_PUPS = re.compile(r"onelaunch|wave browser|shift browser|web ?companion|segurazo|santivirus|bytefence|"
                        r"restoro|reimage|pc app store|search ?protect|conduit|babylon|mywebsearch|mindspark|"
                        r"genieo|ask toolbar|sweetim|iminent|delta toolbar|pc accelerate|pc speed ?up|"
                        r"advanced system ?care|driver ?support|smart pc fixer|pcfixer|systweak|mypc backup|"
                        r"pdf ?(converter|maker|pro) ?(lab|hub|suite)|searchmanager|chromium ?\(|cloud ?vpn ?free",
                        re.I)
# Kinds of software that are often bundled junk: worth a second look, not a warning.
SHADY_KINDS = re.compile(r"toolbar|driver ?(updater|booster|easy)|registry ?(cleaner|fixer|mechanic)|"
                         r"(pc|system) ?(optimi[sz]er|cleaner|booster|mechanic|tune ?up)|speed ?up|"
                         r"coupon|shopping ?assistant", re.I)


@dataclass
class InstalledProgram:
    name: str
    publisher: str = ""
    version: str = ""
    installed_on: str = ""  # YYYY-MM-DD, when Windows recorded it
    location: str = ""
    uninstall: str = ""
    size_mb: float | None = None
    scope: str = "all users"  # or "this user"
    key: str = ""  # registry key, for reference
    file: RunningFile | None = None  # its main program file, once found
    concerns: list[str] = field(default_factory=list)  # make it "needs a look"
    notes: list[str] = field(default_factory=list)
    unwanted: bool = False  # engines call it potentially unwanted rather than malware

    @property
    def verdict(self) -> Verdict:
        v = self.file.verdict if self.file and self.file.result else Verdict.CLEAN
        if self.unwanted and v is Verdict.MALICIOUS:
            return Verdict.SUSPICIOUS  # adware and bundlers are a nuisance, not malware: no quarantine-level alarm
        if self.concerns and v.rank < Verdict.SUSPICIOUS.rank:
            return Verdict.SUSPICIOUS
        return v

    @property
    def status(self) -> str:
        """What the window shows: "UNWANTED" for adware and PUPs, otherwise the verdict."""
        return "UNWANTED" if self.unwanted or (self.concerns and self.verdict is Verdict.SUSPICIOUS) \
            else self.verdict.value.upper()

    @property
    def reasons(self) -> list[str]:
        own = self.file.result.reasons if self.file and self.file.result else []
        return self.concerns + own + self.notes


def _registry_rows() -> list[tuple[str, str, str, dict]]:
    if sys.platform != "win32":
        return []
    import winreg

    hives = {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER}
    rows = []
    for hive, path, scope in UNINSTALL_KEYS:
        try:
            root = winreg.OpenKey(hives[hive], path)
        except OSError:
            continue
        with root:
            for i in range(winreg.QueryInfoKey(root)[0]):
                name = winreg.EnumKey(root, i)
                try:
                    with winreg.OpenKey(root, name) as sub:
                        values = {}
                        for j in range(winreg.QueryInfoKey(sub)[1]):
                            n, v, _ = winreg.EnumValue(sub, j)
                            values[n] = v
                except OSError:
                    continue
                rows.append((scope, f"{hive}\\{path}\\{name}", name, values))
    return rows


def _main_file(values: dict) -> Path | None:
    """The program's own .exe: its icon file if that's a program, else the biggest .exe where it's installed."""
    icon = str(values.get("DisplayIcon") or "").strip().strip('"').split(",")[0].strip().strip('"')
    if icon.lower().endswith(".exe") and Path(icon).is_file():
        return Path(icon)
    location = str(values.get("InstallLocation") or "").strip().strip('"')
    if location and Path(location).is_dir():
        try:
            exes = [p for p in Path(location).glob("*.exe") if not re.match(r"unins|uninst|setup|update", p.name, re.I)]
            if exes:
                return max(exes, key=lambda p: p.stat().st_size)
        except OSError:
            pass
    return None


def list_installed(rows=None) -> list[InstalledProgram]:
    """Programs as Settings > Apps shows them (hidden system parts and updates left out)."""
    rows = _registry_rows() if rows is None else rows
    found: dict[tuple[str, str], InstalledProgram] = {}
    for scope, key, _, v in rows:
        name = str(v.get("DisplayName") or "").strip()
        if not name or v.get("SystemComponent") == 1 or v.get("ParentKeyName") or v.get("ReleaseType") in (
                "Update", "Hotfix", "Security Update"):
            continue
        date = str(v.get("InstallDate") or "")
        p = InstalledProgram(
            name=name, publisher=str(v.get("Publisher") or "").strip(), version=str(v.get("DisplayVersion") or ""),
            installed_on=f"{date[:4]}-{date[4:6]}-{date[6:8]}" if re.fullmatch(r"\d{8}", date) else "",
            location=str(v.get("InstallLocation") or ""), uninstall=str(v.get("UninstallString") or ""),
            size_mb=round(v["EstimatedSize"] / 1024, 1) if isinstance(v.get("EstimatedSize"), int) else None,
            scope=scope, key=key)
        exe = _main_file(v)
        if exe:
            p.file = RunningFile(exe, "installed")
        found.setdefault((name.lower(), p.version), p)
    return sorted(found.values(), key=lambda p: p.name.lower())


def judge_program(p: InstalledProgram) -> None:
    """Concerns that don't need VirusTotal, plus PUP labels from it once looked up."""
    p.concerns.clear()
    p.notes.clear()
    p.unwanted = False
    text = f"{p.name} {p.publisher}"
    m = KNOWN_PUPS.search(text)
    if m:
        p.concerns.append(f"\"{m.group(0).strip()}\" is a well-known potentially unwanted program: it usually arrives "
                          "bundled with something else and shows ads, changes your browser or nags you to pay")
    elif SHADY_KINDS.search(text):
        p.notes.append("Programs of this kind are often bundled adware. Fine if you installed it on purpose")
    report = p.file.result.file_report if p.file and p.file.result else None
    if report and report.found:
        labels = report.threat_kinds + ([report.label] if report.label else [])
        kinds = [k for k in labels if PUP_KINDS.search(k)]
        if kinds and (report.malicious or report.suspicious) and p.file.verdict is not Verdict.CLEAN:
            # VirusTotal's consensus label decides: a few engines saying "trojan" don't outvote "pua.utorrent".
            consensus = (report.label or "").split(".")[0]
            p.unwanted = bool(PUP_KINDS.search(consensus)) if consensus else len(kinds) == len(labels)
            p.concerns.append(f"Engines label it potentially unwanted ({', '.join(dict.fromkeys(kinds))}): adware, "
                              "bundled offers or similar. Uninstall it unless you rely on it")
    if not p.publisher:
        p.notes.append("It doesn't say who made it")
    if not p.file:
        p.notes.append("Atlas couldn't find its program file, so only its name was checked")


def check_installed(scanner: Scanner, progress: Callable[[str], None] | None = None,
                    programs: list[InstalledProgram] | None = None) -> list[InstalledProgram]:
    say = progress or (lambda text: None)
    say("Reading the list of installed programs...")
    programs = list_installed() if programs is None else programs
    files = [p.file for p in programs if p.file]
    if scanner.vt is not None and files:
        judge_files(scanner, files, say)
    for p in programs:
        judge_program(p)
    programs.sort(key=lambda p: (-p.verdict.rank, p.name.lower()))
    return programs


# --- Uninstalling ------------------------------------------------------------------

def uninstall_command(command: str) -> tuple[str, str]:
    """(program, arguments) for an uninstall string. MsiExec "/I" (repair) becomes "/X" (remove)."""
    command = command.strip()
    m = re.match(r'(?i)\s*msiexec(\.exe)?\s+/[ix]\s*(\{[0-9a-f-]+\})', command)
    if m:
        return "msiexec.exe", f"/x {m.group(2)}"
    if command.startswith('"'):
        exe, _, rest = command[1:].partition('"')
        return exe, rest.strip()
    m = re.match(r"(?i)(.+?\.exe)(\s.*)?$", command)
    if m:
        return m.group(1), (m.group(2) or "").strip()
    parts = shlex.split(command, posix=False)
    return parts[0], " ".join(parts[1:])


def run_uninstaller(p: InstalledProgram) -> None:
    """Start the program's own uninstaller. Windows asks for permission if it needs an administrator."""
    if not p.uninstall:
        raise OSError("This program doesn't have an uninstaller registered. Try Settings > Apps.")
    exe, args = uninstall_command(p.uninstall)
    log.info("Starting uninstaller for %s: %s %s", p.name, exe, args)
    result = ctypes.windll.shell32.ShellExecuteW(None, "open", exe, args or None, None, 1)
    if result <= 32:
        raise OSError(f"Windows couldn't start the uninstaller (error {result}). Try Settings > Apps.")
