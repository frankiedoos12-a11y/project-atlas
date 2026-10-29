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
    " age=$s.AntivirusSignatureAge; mode=[string]$s.AMRunningMode; pua=if ($p) { [int]$p.PUAProtection } else { $null };"
    " cfa=if ($p) { [int]$p.EnableControlledFolderAccess } else { $null };"
    " network=if ($p) { [int]$p.EnableNetworkProtection } else { $null };"
    " cloud=if ($p) { [int]$p.MAPSReporting } else { $null };"
    " firstsight=if ($p) { -not $p.DisableBlockAtFirstSeen } else { $null };"
    " asr_ids=@(if ($p) { $p.AttackSurfaceReductionRules_Ids }); asr_actions=@(if ($p) { $p.AttackSurfaceReductionRules_Actions })})"
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
    status = _status()
    return (status_findings(status) + protection_findings(status) + smartscreen_findings(_smartscreen_values())
            + policy_exclusion_findings() + event_findings(_events()))


# --- Extra protection Windows has but leaves off -------------------------------------------------

# Attack surface reduction rules that suit a home PC: they stop the usual tricks of malicious email
# attachments, Office macros, scripts and USB sticks, and rarely get in the way of normal use.
# Microsoft's "standard protection" trio comes first. (Rules that break normal software, such as
# "block executables unless they're common", are left out.)
ASR_RULES = {
    "56a863a9-875e-4185-98a7-b882c64b5ce5": "Block abuse of exploited vulnerable signed drivers",
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2": "Block credential stealing from LSASS",
    "e6db77e5-3df2-4cf1-b95a-636979351e5b": "Block persistence through WMI event subscription",
    "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550": "Block executable content from email client and webmail",
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a": "Block all Office applications from creating child processes",
    "3b576869-a4ec-4529-8536-b80a7769e899": "Block Office applications from creating executable content",
    "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84": "Block Office applications from injecting code into other processes",
    "26190899-1602-49e8-8b27-eb1d0a1ce869": "Block Office communication application from creating child processes",
    "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b": "Block Win32 API calls from Office macros",
    "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c": "Block Adobe Reader from creating child processes",
    "d3e037e1-3eb8-44c8-a917-57927947596d": "Block JavaScript or VBScript from launching downloaded executable content",
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc": "Block execution of potentially obfuscated scripts",
    "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4": "Block untrusted and unsigned processes that run from USB",
    "c1db55ab-c21a-4637-bb3f-a12568109d35": "Use advanced protection against ransomware",
}
ASR_ON = (1, 6)  # 1 = block, 6 = warn (the user can let it through); 2 = audit only, 0 = off
_IDS = ",".join(f"'{i}'" for i in ASR_RULES)
# Run as administrator, only after the user agrees. Rules already on stay as they are.
HARDEN_SCRIPT = (f"$ids = @({_IDS}); Add-MpPreference -AttackSurfaceReductionRules_Ids $ids"
                 " -AttackSurfaceReductionRules_Actions (@('Enabled') * $ids.Count);"
                 " Set-MpPreference -EnableNetworkProtection Enabled")
UNDO_SCRIPT = (f"Remove-MpPreference -AttackSurfaceReductionRules_Ids @({_IDS});"
               " Set-MpPreference -EnableNetworkProtection Disabled")


def protection_findings(status: dict | None) -> list[Finding]:
    """Defender features that are off on most home PCs, and the cloud protection that should be on."""
    if not status or (status.get("mode") or "normal").lower() != "normal":
        return []
    found = []
    page = {"fix": "open", "fix_label": "Open Windows Security", "data": {"url": WINDOWS_SECURITY["protection"]}}
    if status.get("cloud") == 0:
        found.append(Finding("Defender", "Cloud-delivered protection is off", WARN,
                             ["Defender checks new files with Microsoft's cloud, which catches brand-new malware "
                              "within seconds. Turn it on under Virus & threat protection settings."],
                             key="defender:cloud:off", **page))
    elif status.get("firstsight") is False:
        found.append(Finding("Defender", "Block at first sight is off", WARN,
                             ["It holds new files until the cloud has looked at them. Malware turns it off."],
                             key="defender:first-sight:off", **page))
    actions = dict(zip([str(i).lower() for i in status.get("asr_ids") or []], status.get("asr_actions") or []))
    on = [i for i in ASR_RULES if actions.get(i) in ASR_ON]
    network = status.get("network") == 1
    if len(on) == len(ASR_RULES) and network:
        found.append(Finding("Defender", "Extra attack protection is on", OK,
                             [f"All {len(ASR_RULES)} recommended attack surface reduction rules, and network "
                              "protection."], key="defender:harden:ok",
                             fix="defender-undo", fix_label="Turn off again (asks for administrator)..."))
    else:
        missing = [name for i, name in ASR_RULES.items() if i not in on]
        found.append(Finding(
            "Defender", f"Extra attack protection is off ({len(on)} of {len(ASR_RULES)} rules on, network "
                        f"protection {'on' if network else 'off'})", NOTE,
            ["Windows has these built in but leaves them off. They block what most malware does first: Office "
             "macros and email attachments starting programs, scripts downloading programs, passwords being read "
             "out of memory, and dangerous websites in every browser (network protection). Windows Home has no "
             "switch for them, so Atlas can turn them on for you.",
             "Rarely, one gets in the way of a program you use. Windows then says it blocked something, and Atlas "
             "can turn them off again just as easily."]
            + [f"Off: {name}" for name in missing[:6]] + ([f"...and {len(missing) - 6} more"] if len(missing) > 6 else []),
            key=f"defender:harden:{len(on)}:{int(network)}",
            fix="defender-harden", fix_label="Turn on (asks for administrator)..."))
    if status.get("cfa") == 1:
        found.append(Finding("Defender", "Ransomware protection (controlled folder access) is on", OK,
                             key="defender:cfa:ok"))
    return found


def _smartscreen_values() -> dict:
    """Windows' and Edge's SmartScreen settings and Smart App Control, straight from the registry."""
    if sys.platform != "win32":
        return {}
    import winreg

    def read(hive, path, name):
        try:
            with winreg.OpenKey(hive, path) as key:
                return winreg.QueryValueEx(key, name)[0]
        except OSError:
            return None

    hklm, hkcu = winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER
    return {
        "windows": read(hklm, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer", "SmartScreenEnabled"),
        "windows_policy": read(hklm, r"SOFTWARE\Policies\Microsoft\Windows\System", "EnableSmartScreen"),
        "edge": read(hkcu, r"Software\Microsoft\Edge\SmartScreenEnabled", ""),
        "edge_policy": read(hklm, r"SOFTWARE\Policies\Microsoft\Edge", "SmartScreenEnabled"),
        "sac": read(hklm, r"SYSTEM\CurrentControlSet\Control\CI\Policy", "VerifiedAndReputablePolicyState"),
    }


def smartscreen_findings(values: dict) -> list[Finding]:
    if not values:
        return []
    found = []
    apps = {"fix": "open", "fix_label": "Open App & browser control", "data": {"url": WINDOWS_SECURITY["apps"]}}
    if values.get("windows_policy") == 0 or str(values.get("windows") or "").lower() == "off":
        found.append(Finding("SmartScreen", "SmartScreen for apps and files is off", WARN,
                             ["SmartScreen warns before you run a program from the internet that few people have "
                              "run. Turn on \"Check apps and files\" under Reputation-based protection."
                              + (" A policy switched it off." if values.get("windows_policy") == 0 else "")],
                             key="smartscreen:windows:off", **apps))
    if values.get("edge_policy") == 0 or values.get("edge") == 0:
        found.append(Finding("SmartScreen", "SmartScreen is off in Microsoft Edge", WARN,
                             ["It blocks known phishing and malware sites in Edge. Turn it on under Edge > Settings "
                              "> Privacy, search and services > Security."], key="smartscreen:edge:off", **apps))
    if not found:
        found.append(Finding("SmartScreen", "SmartScreen is on", OK, key="smartscreen:ok"))
    sac = values.get("sac")
    if sac == 1:
        found.append(Finding("SmartScreen", "Smart App Control is on", OK, key="sac:on"))
    elif sac == 2:
        found.append(Finding("SmartScreen", "Smart App Control is learning (evaluation mode)", OK,
                             ["Windows is checking whether it would get in your way before switching it on."],
                             key="sac:evaluation"))
    elif sac == 0:
        found.append(Finding("SmartScreen", "Smart App Control is off", NOTE,
                             ["It blocks programs that are neither signed nor known to be safe. On many PCs it can "
                              "only be switched back on by resetting Windows, so it isn't worth changing for that. "
                              "Atlas's other checks cover much of the same ground."], key="sac:off", **apps))
    return found


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
