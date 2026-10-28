"""Microsoft Defender: is it switched on and up to date, has anything tampered with it, and
a second opinion on a single file.

Malware's first move is often to blind the antivirus: switch real-time protection off, or add
its own folder to Defender's exclusions. Windows only shows the exclusion list itself to
administrators, but Defender writes every settings change to its event log, which anyone can
read, so a new exclusion still shows up there.

Atlas only reads. Fixes open Windows Security at the right page; turning things back on
needs you (and often an administrator) anyway, which is the point of tamper protection.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from atlas.findings import NOTE, OK, WARN, Finding
from atlas.local_checks import run_powershell_json

log = logging.getLogger(__name__)

NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
EVENT_DAYS = 30
OLD_SIGNATURES_DAYS = 3

_STATUS_SCRIPT = (
    "$s = Get-MpComputerStatus -ErrorAction Stop; $p = Get-MpPreference -ErrorAction SilentlyContinue;"
    " ConvertTo-Json -Compress -InputObject ([pscustomobject]@{"
    " service=$s.AMServiceEnabled; antivirus=$s.AntivirusEnabled; realtime=$s.RealTimeProtectionEnabled;"
    " behavior=$s.BehaviorMonitorEnabled; downloads=$s.IoavProtectionEnabled; tamper=$s.IsTamperProtected;"
    " age=$s.AntivirusSignatureAge; mode=[string]$s.AMRunningMode; pua=if ($p) { [int]$p.PUAProtection } else { $null }})"
)

# 1116 detected, 5001 real-time protection off, 5007 settings changed, 5010/5012 scanning off, 5013 tamper blocked.
_EVENTS_SCRIPT = (
    "$since = (Get-Date).AddDays(-%d);"
    " $e = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational';"
    " Id=1116,5001,5007,5010,5012,5013; StartTime=$since} -ErrorAction SilentlyContinue;"
    " ConvertTo-Json -Compress -InputObject @($e | ForEach-Object { [pscustomobject]@{id=$_.Id;"
    " when=$_.TimeCreated.ToString('yyyy-MM-dd HH:mm'); text=$_.Message} })"
) % EVENT_DAYS

_POLICY_EXCLUSIONS = r"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions"
# The key path has spaces in it ("...\Windows Defender\Exclusions\Paths\C:\x = 0x0"), so match up to the line's end.
EXCLUSION_RE = re.compile(r"New value:[^\r\n]*?\\Exclusions\\(Paths|Processes|Extensions|IpAddresses|TemporaryPaths)"
                          r"\\(.+?)\s*=", re.I)
SWITCHED_OFF_RE = re.compile(r"New value:[^\r\n]*?\\(DisableRealtimeMonitoring|DisableAntiSpyware|DisableAntiVirus|"
                             r"DisableBehaviorMonitoring|DisableIOAVProtection|DisableScriptScanning|"
                             r"DisableOnAccessProtection)\s*=\s*0x1", re.I)
THREAT_RE = re.compile(r"Name:\s*(.+)")
WINDOWS_SECURITY = {"protection": "windowsdefender://threatsettings", "apps": "windowsdefender://appbrowser",
                    "updates": "windowsdefender://threat", "home": "windowsdefender:"}


def _status() -> dict | None:
    try:
        rows = run_powershell_json(_STATUS_SCRIPT, timeout=60)
    except Exception:
        log.exception("Couldn't read Defender's status")
        return None
    return rows[0] if rows else None


def status_findings(status: dict | None) -> list[Finding]:
    if status is None:
        return [Finding("Defender", "Couldn't read Defender's status", NOTE,
                        ["Another antivirus may be in charge, or Defender's service isn't running."],
                        key="defender:unreadable", fix="open", fix_label="Open Windows Security",
                        data={"url": WINDOWS_SECURITY["home"]})]
    mode = status.get("mode") or ""
    if mode and mode.lower() not in ("normal", ""):
        return [Finding("Defender", f"Defender is in \"{mode}\": another antivirus is in charge", NOTE,
                        ["That's fine if you installed one on purpose. Atlas can't check its settings."],
                        key=f"defender:mode:{mode}")]
    found = []

    def check(ok: bool, good: str, bad: str, why: str, key: str, page: str) -> None:
        if ok:
            found.append(Finding("Defender", good, OK, key=f"defender:{key}:ok"))
        else:
            found.append(Finding("Defender", bad, WARN, [why], key=f"defender:{key}:off", fix="open",
                                 fix_label="Open Windows Security", data={"url": WINDOWS_SECURITY[page]}))

    check(bool(status.get("service")) and bool(status.get("antivirus")), "Defender antivirus is on",
          "Defender antivirus is off", "Nothing is scanning files as they arrive.", "antivirus", "protection")
    check(bool(status.get("realtime")), "Real-time protection is on", "Real-time protection is off",
          "Windows turns it back on by itself after a while, but malware switches it off to get in.",
          "realtime", "protection")
    check(bool(status.get("tamper")), "Tamper protection is on", "Tamper protection is off",
          "Tamper protection stops programs from quietly switching Defender off. Turn it on under "
          "Virus & threat protection settings.", "tamper", "protection")
    check(bool(status.get("behavior")) and bool(status.get("downloads")),
          "Behaviour monitoring and download scanning are on",
          "Behaviour monitoring or download scanning is off",
          "These catch malware by what it does and as it's downloaded.", "behaviour", "protection")
    age = status.get("age")
    if isinstance(age, int) and age > OLD_SIGNATURES_DAYS:
        found.append(Finding("Defender", f"Virus definitions are {age} days old", WARN,
                             ["Defender usually updates several times a day. Check for updates in Windows Security."],
                             key="defender:signatures:old", fix="open", fix_label="Open Windows Security",
                             data={"url": WINDOWS_SECURITY["updates"]}))
    elif isinstance(age, int):
        found.append(Finding("Defender", "Virus definitions are up to date", OK, key="defender:signatures:ok"))
    if status.get("pua") == 0:
        found.append(Finding(
            "Defender", "Potentially unwanted app blocking is off", WARN,
            ["This is the Defender setting that blocks adware, bundled toolbars, browser hijackers and fake "
             "\"PC optimizers\". Turn it on under App & browser control > Reputation-based protection > "
             "Potentially unwanted app blocking (tick both Block apps and Block downloads)."],
            key="defender:pua:off", fix="open", fix_label="Open App & browser control",
            data={"url": WINDOWS_SECURITY["apps"]}))
    elif status.get("pua") in (1, 2):
        found.append(Finding("Defender", "Potentially unwanted app blocking is on" +
                             (" (audit only)" if status["pua"] == 2 else ""), OK, key="defender:pua:ok"))
    return found


def _events() -> list[dict]:
    try:
        return run_powershell_json(_EVENTS_SCRIPT, timeout=90)
    except Exception:
        log.exception("Couldn't read Defender's event log")
        return []


def event_findings(events: list[dict]) -> list[Finding]:
    """Tampering and detections from Defender's own log (last 30 days)."""
    found = []
    for e in events:
        text, when, eid = str(e.get("text") or ""), e.get("when", ""), e.get("id")
        if eid == 5007:
            m = EXCLUSION_RE.search(text)
            if m:
                kind = {"paths": "folder or file", "processes": "program", "extensions": "file type",
                        "ipaddresses": "network address", "temporarypaths": "temporary folder"}[m.group(1).lower()]
                found.append(Finding("Defender", f"An exclusion was added: {m.group(2)}", WARN,
                                     [f"On {when} Defender was told to stop scanning this {kind}. Malware does this "
                                      "to hide. If you didn't add it yourself, remove it in Windows Security > "
                                      "Virus & threat protection settings > Exclusions (needs an administrator)."],
                                     key=f"defender:exclusion:{m.group(2).lower()}", fix="open",
                                     fix_label="Open Windows Security", data={"url": WINDOWS_SECURITY["protection"]}))
                continue
            m = SWITCHED_OFF_RE.search(text)
            if m:
                found.append(Finding("Defender", f"A Defender setting was switched off: {m.group(1)}", WARN,
                                     [f"Changed on {when}. If you didn't do this, something may be trying to "
                                      "blind Defender."], key=f"defender:setting:{m.group(1).lower()}:{when}",
                                     fix="open", fix_label="Open Windows Security",
                                     data={"url": WINDOWS_SECURITY["protection"]}))
        elif eid in (5001, 5010, 5012):
            found.append(Finding("Defender", "Real-time protection was switched off" if eid == 5001 else
                                 "Defender scanning was switched off", WARN, [f"On {when}."],
                                 key=f"defender:event:{eid}:{when}", fix="open", fix_label="Open Windows Security",
                                 data={"url": WINDOWS_SECURITY["protection"]}))
        elif eid == 5013:
            found.append(Finding("Defender", "Tamper protection blocked a change to Defender", WARN,
                                 [f"On {when} something tried to change Defender's settings and was stopped. "
                                  "Worth finding out what."], key=f"defender:tamper-blocked:{when}"))
        elif eid == 1116:
            m = THREAT_RE.search(text)
            name = m.group(1).strip() if m else "a threat"
            found.append(Finding("Defender", f"Defender found {name}", NOTE,
                                 [f"On {when}. Defender handles these itself; see Protection history in "
                                  "Windows Security."], key=f"defender:detected:{name}:{when}", fix="open",
                                 fix_label="Open Windows Security", data={"url": WINDOWS_SECURITY["updates"]}))
    return found


def policy_exclusion_findings() -> list[Finding]:
    """Exclusions set by group policy, which (unlike Defender's own list) anyone can read."""
    if sys.platform != "win32":
        return []
    import winreg

    found = []
    for kind in ("Paths", "Processes", "Extensions"):
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, rf"{_POLICY_EXCLUSIONS}\{kind}") as key:
                for i in range(winreg.QueryInfoKey(key)[1]):
                    name = winreg.EnumValue(key, i)[0]
                    found.append(Finding("Defender", f"A policy excludes this from scanning: {name}", WARN,
                                         ["Set through Windows policy, which home PCs rarely use. Malware sets "
                                          "these to hide from Defender."], key=f"defender:policy-exclusion:{name}"))
        except OSError:
            continue
    return found


def check_defender() -> list[Finding]:
    return status_findings(_status()) + policy_exclusion_findings() + event_findings(_events())


# --- Second opinion ---------------------------------------------------------------

@dataclass
class DefenderScan:
    path: Path
    clean: bool | None  # None: couldn't scan
    threats: list[str] = field(default_factory=list)
    message: str = ""


def mpcmdrun() -> Path | None:
    platform = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "Microsoft/Windows Defender/Platform"
    versions = sorted((p for p in platform.glob("*") if (p / "MpCmdRun.exe").exists()),
                      key=lambda p: [int(x) if x.isdigit() else 0 for x in p.name.replace("-", ".").split(".")])
    if versions:
        return versions[-1] / "MpCmdRun.exe"
    fallback = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Windows Defender/MpCmdRun.exe"
    return fallback if fallback.exists() else None


def scan_file(path: Path, timeout: int = 600) -> DefenderScan:
    """Ask Defender to scan one file now. Report only: Defender is told not to act on what it finds."""
    exe = mpcmdrun()
    if exe is None:
        return DefenderScan(path, None, message="Defender's scanner (MpCmdRun.exe) wasn't found")
    try:
        out = subprocess.run([str(exe), "-Scan", "-ScanType", "3", "-File", str(path), "-DisableRemediation"],
                             capture_output=True, timeout=timeout, creationflags=NO_WINDOW)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return DefenderScan(path, None, message=f"Defender couldn't scan it: {exc}")
    text = out.stdout.decode("utf-8", errors="replace") + out.stderr.decode("utf-8", errors="replace")
    threats = [m.group(1).strip() for m in re.finditer(r"Threat\s*:\s*(.+)", text)]
    if out.returncode == 2 or threats:
        names = ", ".join(threats) or "a threat"
        return DefenderScan(path, False, threats, f"Defender found {names}")
    if out.returncode == 0 and "found no threats" in text:
        return DefenderScan(path, True, message=f"Defender found no threats ({datetime.now():%H:%M})")
    return DefenderScan(path, None, message=f"Defender couldn't scan it (code {out.returncode}): "
                                            f"{text.strip().splitlines()[-1] if text.strip() else 'no output'}")
