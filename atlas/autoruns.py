"""Programs set to start automatically ("autoruns").

Malware and adware almost always add themselves to one of these places so they
come back after every reboot:

- Registry Run / RunOnce keys, per-user and machine-wide
- Startup folders
- Scheduled tasks
- Services and drivers
- Winlogon shell/userinit replacements, and Image File Execution Options
  "debugger" hijacks (launching one program secretly starts another)

Everything here only reads, except `set_enabled`, which switches an item off or on the same
way Task Manager's Startup apps page does. Nothing is ever removed.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import sys
import struct
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from atlas.config import FOLDER_COMMON_STARTUP, FOLDER_STARTUP, known_folder
from atlas.db import Store
from atlas.local_checks import Signature, check_signatures, run_powershell_json, sha256_file
from atlas.scanner import Scanner, ScanResult, Verdict

if sys.platform == "win32":
    import winreg

log = logging.getLogger(__name__)

# Microsoft's own code. "Microsoft Windows Hardware Compatibility Publisher" is deliberately
# absent: Microsoft uses it to sign *third-party* drivers.
MICROSOFT_SIGNERS = {"Microsoft Windows", "Microsoft Corporation", "Microsoft Windows Publisher"}

# Programs that run other files. For these, the interesting file is the one they're told to run.
SCRIPT_HOSTS = {"rundll32.exe", "regsvr32.exe", "wscript.exe", "cscript.exe", "mshta.exe",
                "powershell.exe", "pwsh.exe", "cmd.exe"}

TEMP_HINTS = ("\\appdata\\local\\temp\\", "\\windows\\temp\\")

SYSTEM_ROOT = os.environ.get("SystemRoot", r"C:\Windows")


@dataclass
class Autorun:
    category: str  # "Registry Run", "Startup folder", "Scheduled task", "Service", "Driver", "Winlogon", "IFEO hijack"
    location: str  # registry key, folder, or task folder
    name: str
    command: str
    enabled: bool = True  # False when switched off, e.g. in Task Manager's Startup apps
    path: Path | None = None  # the file that actually runs, resolved from `command`
    host: str | None = None  # e.g. "powershell.exe" when a script host runs `path`

    @property
    def key(self) -> str:
        return f"{self.category}|{self.location}|{self.name}"


# --- Working out which file a command line runs ----------------------------------

def _normalize(raw: str) -> str:
    s = os.path.expandvars(raw.strip())
    low = s.lower()
    if low.startswith("\\??\\"):
        s = s[4:]
    elif low.startswith("\\systemroot\\"):
        s = SYSTEM_ROOT + s[11:]
    elif low.startswith(("system32\\", "syswow64\\")):
        s = f"{SYSTEM_ROOT}\\{s}"
    return s


def _is_file(p: Path) -> bool:
    try:
        return p.is_file()
    except (OSError, ValueError):
        return False


def _find_file(candidate: str) -> Path | None:
    candidate = candidate.strip().strip('"')
    if not candidate:
        return None
    p = Path(candidate)
    if p.is_absolute():
        for c in (p, Path(candidate + ".exe")):
            if _is_file(c):
                return c
        return None
    if "\\" in candidate or "/" in candidate:
        return None
    found = shutil.which(candidate)
    if found:
        return Path(found)
    sys32 = Path(SYSTEM_ROOT, "System32", candidate)
    for c in (sys32, Path(f"{sys32}.exe")):
        if _is_file(c):
            return c
    return None


def split_command(command: str) -> tuple[str, str]:
    """Split a command line into (program, arguments), coping with unquoted paths that contain spaces."""
    s = _normalize(command)
    if s.startswith('"'):
        end = s.find('"', 1)
        if end > 0:
            return s[1:end], s[end + 1:].strip()
    tokens = s.split(" ")
    for i in range(len(tokens), 0, -1):  # longest prefix that is a real file wins
        program = " ".join(tokens[:i])
        if _find_file(program):
            return program, " ".join(tokens[i:])
    return tokens[0], " ".join(tokens[1:])


_ARG_TOKEN = re.compile(r'"([^"]+)"|(\S+)')


def _script_target(args: str) -> Path | None:
    """The file a script host was told to run, e.g. the .vbs given to wscript.exe."""
    for m in _ARG_TOKEN.finditer(args):
        token = m.group(1) or m.group(2)
        if token.startswith(("-", "/")):
            continue
        token = _normalize(token.split(",")[0])  # rundll32 takes "file.dll,EntryPoint"
        if "\\" in token or "/" in token:
            found = _find_file(token)
            if found:
                return found
    return None


def resolve(entry: Autorun) -> Autorun:
    command = entry.command
    if entry.category == "Winlogon":
        # Userinit is a comma-separated list, normally "C:\Windows\system32\userinit.exe,".
        command = next((part for part in command.split(",") if part.strip()), command)
    program, args = split_command(command)
    exe = _find_file(program)
    if exe and exe.name.lower() in SCRIPT_HOSTS:
        entry.host = exe.name.lower()
        entry.path = _script_target(args) or exe
    elif exe:
        entry.path = exe
    elif Path(program.strip('"')).is_absolute():
        entry.path = Path(program.strip('"'))  # a full path to a file that's gone: reported as a leftover
    return entry


# --- Finding autoruns -------------------------------------------------------------

def _reg_values(hive, path: str):
    try:
        key = winreg.OpenKey(hive, path)
    except OSError:
        return
    with key:
        i = 0
        while True:
            try:
                name, value, _ = winreg.EnumValue(key, i)
            except OSError:
                return
            i += 1
            yield name, value


def _reg_subkeys(hive, path: str):
    try:
        key = winreg.OpenKey(hive, path)
    except OSError:
        return
    with key:
        i = 0
        while True:
            try:
                yield winreg.EnumKey(key, i)
            except OSError:
                return
            i += 1


def _reg_value(hive, path: str, name: str):
    try:
        with winreg.OpenKey(hive, path) as key:
            return winreg.QueryValueEx(key, name)[0]
    except OSError:
        return None


def _approved(hive, sub: str) -> dict[str, bool]:
    """Which Run/StartupFolder items are switched on in Task Manager's Startup apps."""
    path = rf"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\{sub}"
    return {name.lower(): not (isinstance(v, bytes) and v and v[0] & 1) for name, v in _reg_values(hive, path)}


def registry_run_entries() -> list[Autorun]:
    hkcu, hklm = winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE
    cv = r"Software\Microsoft\Windows\CurrentVersion"
    wow = r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion"
    keys = [
        ("HKCU", hkcu, rf"{cv}\Run", "Run"),
        ("HKCU", hkcu, rf"{cv}\RunOnce", None),
        ("HKCU", hkcu, rf"{cv}\Policies\Explorer\Run", None),
        ("HKLM", hklm, rf"{cv}\Run", "Run"),
        ("HKLM", hklm, rf"{cv}\RunOnce", None),
        ("HKLM", hklm, rf"{cv}\Policies\Explorer\Run", None),
        ("HKLM", hklm, rf"{wow}\Run", "Run32"),
        ("HKLM", hklm, rf"{wow}\RunOnce", None),
    ]
    entries = []
    for label, hive, path, approved_sub in keys:
        approved = _approved(hive, approved_sub) if approved_sub else {}
        for name, value in _reg_values(hive, path):
            if isinstance(value, str) and value.strip():
                entries.append(Autorun("Registry Run", rf"{label}\{path}", name or "(Default)", value,
                                       enabled=approved.get(name.lower(), True)))
    return entries


_SHORTCUT_SCRIPT = (
    "$sh = New-Object -ComObject WScript.Shell;"
    " $r = Get-Content -LiteralPath $env:ATLAS_LIST -Encoding UTF8 | Where-Object { $_ } | ForEach-Object {"
    " $l = $sh.CreateShortcut($_); [pscustomobject]@{lnk=[string]$_; target=$l.TargetPath; args=$l.Arguments} };"
    " ConvertTo-Json -InputObject @($r) -Compress"
)


def startup_folder_entries() -> list[Autorun]:
    entries = []
    folders = [(FOLDER_STARTUP, winreg.HKEY_CURRENT_USER), (FOLDER_COMMON_STARTUP, winreg.HKEY_LOCAL_MACHINE)]
    for folder_id, hive in folders:
        folder = known_folder(folder_id)
        if not folder or not folder.is_dir():
            continue
        approved = _approved(hive, "StartupFolder")
        for f in folder.iterdir():
            if f.is_file() and f.name.lower() != "desktop.ini":
                entries.append(Autorun("Startup folder", str(folder), f.name, f'"{f}"',
                                       enabled=approved.get(f.name.lower(), True)))
    shortcuts = [e for e in entries if e.name.lower().endswith(".lnk")]
    if shortcuts:
        rows = run_powershell_json(_SHORTCUT_SCRIPT, [str(Path(e.location, e.name)) for e in shortcuts])
        targets = {r["lnk"]: r for r in rows}
        for e in shortcuts:
            row = targets.get(str(Path(e.location, e.name)))
            if row and row.get("target"):
                e.command = f'"{row["target"]}" {row.get("args") or ""}'.strip()
    return entries


_TASK_SCRIPT = (
    "$r = Get-ScheduledTask | ForEach-Object { $t = $_; foreach ($a in $t.Actions) {"
    " if ($a.PSObject.Properties['Execute'] -and $a.Execute) {"
    " [pscustomobject]@{folder=$t.TaskPath; name=$t.TaskName; state=[string]$t.State;"
    " exe=$a.Execute; args=$a.Arguments} } } };"
    " ConvertTo-Json -InputObject @($r) -Compress"
)


def scheduled_task_entries() -> list[Autorun]:
    entries = []
    seen: dict[str, int] = {}
    for row in run_powershell_json(_TASK_SCRIPT):
        exe = (row.get("exe") or "").strip().strip('"')
        command = f'"{exe}" {row.get("args") or ""}'.strip()
        name = row["name"]
        n = seen.get(row["folder"] + name, 0)
        seen[row["folder"] + name] = n + 1
        if n:  # a task with several actions
            name = f"{name} (action {n + 1})"
        entries.append(Autorun("Scheduled task", row["folder"], name, command,
                               enabled=row.get("state") != "Disabled"))
    return entries


def service_entries() -> list[Autorun]:
    hklm = winreg.HKEY_LOCAL_MACHINE
    base = r"SYSTEM\CurrentControlSet\Services"
    entries = []
    for name in _reg_subkeys(hklm, base):
        path = rf"{base}\{name}"
        start, svc_type, image = (_reg_value(hklm, path, v) for v in ("Start", "Type", "ImagePath"))
        if start not in (0, 1, 2) or not isinstance(image, str) or not isinstance(svc_type, int):
            continue  # only things that start automatically
        if svc_type & 0x30:
            category = "Service"
        elif svc_type & 0x03:
            category = "Driver"
        else:
            continue
        command = image
        if "svchost.exe" in image.lower():
            # Shared-host services: the real code is the ServiceDll.
            dll = _reg_value(hklm, rf"{path}\Parameters", "ServiceDll") or _reg_value(hklm, path, "ServiceDll")
            if isinstance(dll, str) and dll:
                command = f'"{dll}"'
        entries.append(Autorun(category, rf"HKLM\{base}", name, command))
    return entries


WINLOGON = r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
IFEO = r"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"


def hijack_entries() -> list[Autorun]:
    entries = []
    for label, hive in (("HKLM", winreg.HKEY_LOCAL_MACHINE), ("HKCU", winreg.HKEY_CURRENT_USER)):
        values = dict(_reg_values(hive, WINLOGON))
        for value_name in ("Shell", "Userinit"):
            value = values.get(value_name)
            if isinstance(value, str) and value.strip():
                entries.append(Autorun("Winlogon", rf"{label}\{WINLOGON}", value_name, value))
    for program in _reg_subkeys(winreg.HKEY_LOCAL_MACHINE, IFEO):
        debugger = _reg_value(winreg.HKEY_LOCAL_MACHINE, rf"{IFEO}\{program}", "Debugger")
        if isinstance(debugger, str) and debugger.strip():
            entries.append(Autorun("IFEO hijack", rf"HKLM\{IFEO}", program, debugger))
    return entries


SOURCES: list[Callable[[], list[Autorun]]] = [
    registry_run_entries, startup_folder_entries, scheduled_task_entries, service_entries, hijack_entries,
]


def enumerate_all() -> list[Autorun]:
    entries: list[Autorun] = []
    for source in SOURCES:
        try:
            entries.extend(source())
        except Exception:
            log.exception("Could not read startup items from %s", source.__name__)
    return [resolve(e) for e in entries]



# --- Switching items off and on ----------------------------------------------------

APPROVED_KEY = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved"
ADMIN_NEEDED = "Needs administrator rights. Run Project Atlas as administrator to change this one."


def can_switch(category: str, location: str) -> str | None:
    """None if Atlas can switch this item off and on, otherwise why not."""
    if category == "Registry Run" and _approved_target(location) is None:
        return "Windows has no off switch for this kind of entry (RunOnce or policy). It can only be removed."
    if category in ("Service", "Driver"):
        return "Services and drivers are left to Windows' Services tool: switching the wrong one off can stop Windows starting."
    if category in ("Winlogon", "IFEO hijack"):
        return "This can only be repaired, not switched off."
    return None


def _approved_target(location: str):
    """(hive, StartupApproved subkey) for a Run key location, or None."""
    low = location.lower()
    if not low.endswith("\\run") or "\\policies\\" in low:
        return None
    hive = winreg.HKEY_CURRENT_USER if low.startswith("hkcu") else winreg.HKEY_LOCAL_MACHINE
    return hive, "Run32" if "wow6432node" in low else "Run"


def approved_value(on: bool, now: float | None = None) -> bytes:
    """What Task Manager writes: 02 = on; 03 + the time it was switched off (a FILETIME) = off."""
    if on:
        return bytes([2]) + bytes(11)
    filetime = int(((now if now is not None else time.time()) + 11644473600) * 10_000_000)
    return bytes([3, 0, 0, 0]) + struct.pack("<Q", filetime)


def _write_approved(hive, sub: str, name: str, on: bool) -> None:
    try:
        with winreg.CreateKeyEx(hive, rf"{APPROVED_KEY}\{sub}", 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, name, 0, winreg.REG_BINARY, approved_value(on))
    except PermissionError:
        raise PermissionError(ADMIN_NEEDED) from None


_TASK_SWITCH_SCRIPT = (
    "$a = Get-Content -LiteralPath $env:ATLAS_LIST -Encoding UTF8;"
    " try { if ($a[2] -eq 'on') { Enable-ScheduledTask -TaskPath $a[0] -TaskName $a[1] -ErrorAction Stop | Out-Null }"
    " else { Disable-ScheduledTask -TaskPath $a[0] -TaskName $a[1] -ErrorAction Stop | Out-Null };"
    " ConvertTo-Json -InputObject @(@{ok=$true}) -Compress }"
    " catch { ConvertTo-Json -InputObject @(@{ok=$false; error=[string]$_}) -Compress }"
)


def set_enabled(category: str, location: str, name: str, on: bool) -> None:
    """Switch a startup item on or off. Raises PermissionError or ValueError with a readable reason."""
    reason = can_switch(category, location)
    if reason:
        raise ValueError(reason)
    if category == "Registry Run":
        hive, sub = _approved_target(location)
        _write_approved(hive, sub, "" if name == "(Default)" else name, on)
    elif category == "Startup folder":
        common = known_folder(FOLDER_COMMON_STARTUP)
        hive = winreg.HKEY_LOCAL_MACHINE if common and Path(location) == common else winreg.HKEY_CURRENT_USER
        _write_approved(hive, "StartupFolder", name, on)
    elif category == "Scheduled task":
        task = re.sub(r" \(action \d+\)$", "", name)
        (row,) = run_powershell_json(_TASK_SWITCH_SCRIPT, [location, task, "on" if on else "off"], timeout=60) or [{}]
        if not row.get("ok"):
            error = row.get("error", "unknown error")
            if "denied" in error.lower():
                raise PermissionError(ADMIN_NEEDED)
            raise OSError(error)
    else:
        raise ValueError(f"Can't switch {category} items")

# --- Judging autoruns -------------------------------------------------------------

def _hijack_problems(entry: Autorun) -> list[str]:
    problems = []
    if entry.category == "Winlogon":
        value = entry.command.strip().lower().rstrip(",").strip()
        if entry.location.startswith("HKCU"):
            problems.append(f"Winlogon {entry.name} is set for your account only, which Windows never does itself")
        elif entry.name == "Shell" and value != "explorer.exe":
            problems.append("The Windows shell has been replaced (it should be explorer.exe)")
        elif entry.name == "Userinit" and value not in (f"{SYSTEM_ROOT}\\system32\\userinit.exe".lower(),
                                                       "userinit.exe"):
            problems.append("Userinit has been changed to also start another program at sign-in")
    elif entry.category == "IFEO hijack":
        problems.append(f"Opening {entry.name} secretly starts a different program instead")
    return problems


def is_microsoft(sig: Signature | None) -> bool:
    return sig is not None and sig.valid and sig.signer in MICROSOFT_SIGNERS


def is_atlas_itself(path: Path) -> bool:
    """Atlas's own launchers (atlas-tray.exe etc., or the app's ProjectAtlas.exe), which are unsigned."""
    try:
        return (path.resolve().parent == Path(sys.executable).resolve().parent
                and path.name.lower().startswith(("atlas", "projectatlas")))
    except OSError:
        return False


def assess(entry: Autorun, sig: Signature | None, scanner: Scanner | None) -> ScanResult:
    """Judge one startup item. With scanner=None, VirusTotal is skipped."""
    result = ScanResult(path=entry.path or Path(entry.command[:200]))
    result.signature = sig
    if entry.path is None:
        result.raise_to(Verdict.UNKNOWN, "Could not work out which file this starts")
        return result
    if not entry.path.exists():
        result.reasons.append("Points to a file that no longer exists (often left over from an uninstall)")
        return result
    if is_atlas_itself(entry.path):
        result.reasons.append("This is Project Atlas itself")
        return result

    for problem in _hijack_problems(entry):
        result.raise_to(Verdict.SUSPICIOUS, problem)
    if entry.host in ("powershell.exe", "pwsh.exe") and re.search(r"\s-(e|en|enc|encodedcommand)\s", entry.command + " ", re.I):
        result.raise_to(Verdict.SUSPICIOUS, "Runs a hidden, encoded PowerShell command, a common malware trick")
    if entry.host == "mshta.exe":
        result.raise_to(Verdict.SUSPICIOUS, "Starts an HTML application (mshta), which legitimate software rarely does")
    signed = sig is not None and sig.valid
    if not signed and any(h in str(entry.path).lower() for h in TEMP_HINTS):
        result.raise_to(Verdict.SUSPICIOUS, "Unsigned program that starts from a Temp folder")

    if is_microsoft(sig) and not result.reasons:
        result.reasons.append(f"Signed by {sig.signer}")
        return result  # Windows' own files: no need to spend VirusTotal lookups
    if scanner is None or scanner.vt is None:
        if not result.reasons:
            result.reasons.append("VirusTotal check skipped")
        return result

    try:
        result.sha256 = sha256_file(entry.path)
        result.file_report = scanner.lookup("file", result.sha256)
        scanner.judge_report(result, result.file_report, "File")
        if not result.file_report.analyzed and not signed:
            result.raise_to(Verdict.UNKNOWN, "VirusTotal has no results for this file and it is not validly signed")
    except Exception as exc:
        result.raise_to(Verdict.ERROR, f"Could not check file: {exc}")
    if not result.reasons:
        if result.file_report and result.file_report.analyzed:
            result.reasons.append(f"No engines flagged this file ({result.file_report.total} checked)")
        else:
            result.reasons.append(f"Not on VirusTotal yet, but validly signed by {sig.signer}")
    return result


def assess_all(entries: list[Autorun], scanner: Scanner | None) -> list[tuple[Autorun, ScanResult]]:
    files = sorted({str(e.path) for e in entries if e.path and _is_file(e.path)})
    signatures = check_signatures([Path(f) for f in files])
    return [(e, assess(e, signatures.get(str(e.path)) if e.path else None, scanner)) for e in entries]


# --- Watching for new autoruns ----------------------------------------------------

class AutorunMonitor:
    """Re-checks startup items periodically and reports ones that are new or changed."""

    def __init__(self, scanner: Scanner, store: Store, interval_minutes: int,
                 on_finding: Callable[[Autorun, ScanResult, bool], None]):
        self.scanner = scanner
        self.store = store
        self.interval = max(1, interval_minutes) * 60
        self.on_finding = on_finding  # (entry, result, is_new)
        self.paused = False
        self.last_check: str | None = None
        self._wake = threading.Event()
        self._stop = threading.Event()

    def check(self) -> list[tuple[Autorun, ScanResult]]:
        """Compare startup items against what was seen before. Returns the new or changed ones."""
        entries = enumerate_all()
        seen = self.store.autoruns_seen()
        first_run = not seen
        changed = [e for e in entries if seen.get(e.key) != e.command]
        results = assess_all(changed, self.scanner)
        self.store.sync_autoruns(entries, {e.key: r for e, r in results})
        for entry, result in results:
            if not entry.enabled:
                continue
            is_new = entry.key not in seen
            bad = result.verdict in (Verdict.SUSPICIOUS, Verdict.MALICIOUS)
            # The first run records what's already there and only speaks up about problems.
            # After that, anything new that isn't part of Windows is worth knowing about,
            # but routine changes (an app updating its own startup entry) only matter if bad.
            if bad or (not first_run and is_new and not is_microsoft(result.signature)):
                self.store.record_scan(str(result.path), result.sha256, result.verdict.value, result.reasons,
                                       None, f"startup item: {entry.category}")
                self.on_finding(entry, result, is_new)
        self.last_check = datetime.now().strftime("%H:%M")
        return results

    def check_now(self) -> None:
        self._wake.set()

    def run(self) -> None:
        while not self._stop.is_set():
            if not self.paused:
                try:
                    self.check()
                except Exception:
                    log.exception("Startup item check failed")
            self._wake.wait(self.interval)
            self._wake.clear()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()
