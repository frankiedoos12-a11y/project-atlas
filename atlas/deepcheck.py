"""Deep check: the parts of Windows only an administrator may read.

Pressing "Deep check (administrator)" starts a small collector with Windows' permission prompt.
The collector only *reads* and writes what it saw to a JSON file; it needs no VirusTotal key (the
prompt may sign in as a different administrator account, which wouldn't have one) and changes
nothing. Atlas, running as you again, then judges what was collected:

- Defender's exclusion list (malware's favourite hiding place)
- the DNS cache: sites this PC looked up recently, matched against threat intel and VirusTotal
- the Security log: failed sign-ins, new user accounts, new administrators, the log being cleared
- command lines of every process, including the system ones hidden from a normal user
- WMI event subscriptions, a stealthy way for malware to start itself
"""

from __future__ import annotations

import ctypes
import json
import logging
import os
import sys
import time
from collections import Counter
from ctypes import wintypes
from pathlib import Path

from atlas import health
from atlas.findings import NOTE, OK, WARN, Finding
from atlas.local_checks import run_powershell_json

log = logging.getLogger(__name__)

FAILED_LOGON_WARN = 10
_DEFENDER_SCRIPT = ("$p = Get-MpPreference -ErrorAction Stop; ConvertTo-Json -Compress -InputObject @([pscustomobject]@{"
                    " paths=@($p.ExclusionPath); processes=@($p.ExclusionProcess); extensions=@($p.ExclusionExtension);"
                    " ips=@($p.ExclusionIpAddress) })")
_DNS_SCRIPT = ("ConvertTo-Json -Compress -InputObject @(Get-DnsClientCache -ErrorAction SilentlyContinue |"
               " Where-Object { $_.Type -in 1, 28, 5 } | ForEach-Object { [pscustomobject]@{ name=$_.Entry;"
               " data=$_.Data } })")
# 4625 failed sign-in, 4720 account created, 4732 added to a local group, 1102 Security log cleared.
_SECURITY_SCRIPT = (
    "$since = (Get-Date).AddDays(-7); ConvertTo-Json -Compress -Depth 3 -InputObject @("
    "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625,4720,4732,1102; StartTime=$since}"
    " -MaxEvents 2000 -ErrorAction SilentlyContinue | ForEach-Object { $x = [xml]$_.ToXml(); $d = @{};"
    " foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = [string]$n.'#text' };"
    " [pscustomobject]@{ id=$_.Id; when=$_.TimeCreated.ToString('yyyy-MM-dd HH:mm'); data=$d } })"
)
_WMI_SCRIPT = (
    "ConvertTo-Json -Compress -InputObject @(Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer"
    " -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ kind=$_.CimClass.CimClassName;"
    " name=[string]$_.Name; command=[string]$_.CommandLineTemplate; script=[string]$_.ScriptText;"
    " file=[string]$_.ScriptFileName } })"
)
# Windows' own subscription, present on every PC.
NORMAL_CONSUMERS = {("NTEventLogEventConsumer", "SCM Event Log Consumer")}


# --- The collector (runs elevated) -------------------------------------------------------------

def _try(name: str, fn):
    try:
        return fn()
    except Exception as exc:  # one part failing mustn't lose the others
        log.exception("Deep check: %s failed", name)
        return {"error": str(exc)}


def collect() -> dict:
    from atlas import cmdlines

    def processes():
        procs, hidden = cmdlines.processes()
        return {"hidden": hidden, "items": [p.__dict__ for p in procs]}

    return {
        "collected": time.strftime("%Y-%m-%d %H:%M"),
        "admin": is_admin(),
        "defender": _try("defender", lambda: (run_powershell_json(_DEFENDER_SCRIPT, timeout=60) or [{}])[0]),
        "dns": _try("dns", lambda: run_powershell_json(_DNS_SCRIPT, timeout=60)),
        "security": _try("security", lambda: run_powershell_json(_SECURITY_SCRIPT, timeout=120)),
        "wmi": _try("wmi", lambda: run_powershell_json(_WMI_SCRIPT, timeout=60)),
        "processes": _try("processes", processes),
        "disks": _try("disks", lambda: run_powershell_json(health.RELIABILITY_SCRIPT, timeout=60)),
    }


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


# --- Starting it ------------------------------------------------------------------------------

class _ShellExecuteInfo(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.DWORD), ("fMask", ctypes.c_ulong), ("hwnd", wintypes.HWND),
                ("lpVerb", wintypes.LPCWSTR), ("lpFile", wintypes.LPCWSTR), ("lpParameters", wintypes.LPCWSTR),
                ("lpDirectory", wintypes.LPCWSTR), ("nShow", ctypes.c_int), ("hInstApp", wintypes.HINSTANCE),
                ("lpIDList", ctypes.c_void_p), ("lpClass", wintypes.LPCWSTR), ("hkeyClass", wintypes.HKEY),
                ("dwHotKey", wintypes.DWORD), ("hIconOrMonitor", wintypes.HANDLE), ("hProcess", wintypes.HANDLE)]


def _python() -> str:
    exe = Path(sys.executable)
    console = exe.with_name("python.exe")
    return str(console if exe.name.lower() == "pythonw.exe" and console.exists() else exe)


def output_file() -> Path:
    from atlas import config

    return config.data_dir() / "deep-check.json"


def run_elevated(timeout: int = 600) -> dict:
    """Show Windows' permission prompt, run the collector, wait for it and return what it saw."""
    out = output_file()
    out.parent.mkdir(parents=True, exist_ok=True)
    try:
        out.unlink()
    except OSError:
        pass
    info = _ShellExecuteInfo()
    info.cbSize = ctypes.sizeof(info)
    info.fMask = 0x40  # SEE_MASK_NOCLOSEPROCESS
    info.lpVerb = "runas"
    info.lpFile = _python()
    info.lpParameters = f'-m atlas deep-check --collect --out "{out}"'
    info.lpDirectory = str(Path(__file__).resolve().parent.parent)
    info.nShow = 0  # hidden
    shell32 = ctypes.windll.shell32
    shell32.ShellExecuteExW.argtypes = [ctypes.POINTER(_ShellExecuteInfo)]
    if not shell32.ShellExecuteExW(ctypes.byref(info)):
        err = ctypes.GetLastError()
        raise OSError("The administrator permission was refused." if err == 1223 else
                      f"Windows couldn't start the deep check (error {err}).")
    try:
        ctypes.windll.kernel32.WaitForSingleObject(info.hProcess, timeout * 1000)
    finally:
        ctypes.windll.kernel32.CloseHandle(info.hProcess)
    try:
        return json.loads(out.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise OSError(f"The deep check didn't finish ({exc}).") from exc


def load_last() -> dict | None:
    try:
        return json.loads(output_file().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


# --- Judging what was collected (runs as you) ----------------------------------------------------

def defender_findings(d: dict) -> list[Finding]:
    if not isinstance(d, dict) or "error" in d:
        return [Finding("Deep check", "Couldn't read Defender's exclusions", NOTE,
                        [str((d or {}).get("error", "no answer"))[:300]], key="deep:defender:error")]
    kinds = {"paths": "folder or file", "processes": "program", "extensions": "file type", "ips": "network address"}
    values = [str(v) for k in kinds for v in d.get(k) or [] if v]
    if any(v.startswith("N/A") for v in values):  # "N/A: Must be an administrator to view exclusions"
        return [Finding("Deep check", "Defender's exclusions need administrator rights", NOTE,
                        ["Windows only shows them to an administrator."], key="deep:defender:notadmin")]
    found = []
    for field_name, what in kinds.items():
        for value in d.get(field_name) or []:
            if not value:
                continue
            found.append(Finding("Defender", f"Defender doesn't scan this {what}: {value}", WARN,
                                 ["Exclusions are malware's favourite hiding place. If you or a program you trust (a game "
                                  "launcher, development tool, backup software) didn't add it, remove it in Windows "
                                  "Security > Virus & threat protection settings > Exclusions."],
                                 key=f"deep:exclusion:{field_name}:{str(value).lower()}", fix="open",
                                 fix_label="Open Windows Security", data={"url": "windowsdefender://threatsettings"}))
    if not found:
        found.append(Finding("Defender", "Defender has no exclusions", OK, key="deep:exclusions:none"))
    return found


def security_findings(events) -> list[Finding]:
    if not isinstance(events, list):
        return [Finding("Deep check", "Couldn't read the Security log", NOTE,
                        [str((events or {}).get("error", "no answer"))[:300]], key="deep:security:error")]
    found = []
    failed = Counter()
    for e in events:
        data = e.get("data") or {}
        eid, when = e.get("id"), e.get("when", "")
        if eid == 4625:
            failed[(data.get("TargetUserName") or "?", data.get("IpAddress") or "-")] += 1
        elif eid == 4720:
            found.append(Finding("Accounts", f"New user account: {data.get('TargetUserName')}", WARN,
                                 [f"Created {when} by {data.get('SubjectUserName') or '?'}. If nobody here made it, "
                                  "attackers add accounts to get back in later."],
                                 key=f"deep:newuser:{data.get('TargetUserName')}:{when}"))
        elif eid == 4732 and "admin" in (data.get("TargetUserName") or "").lower():
            member = data.get("MemberName") or data.get("MemberSid") or "?"
            found.append(Finding("Accounts", f"Someone was made an administrator", WARN,
                                 [f"{member} was added to {data.get('TargetUserName')} on {when} by "
                                  f"{data.get('SubjectUserName') or '?'}."], key=f"deep:admin:{member}:{when}"))
        elif eid == 1102:
            found.append(Finding("Accounts", "The Security log was cleared", WARN,
                                 [f"On {when} by {data.get('SubjectUserName') or '?'}. Attackers clear it to hide "
                                  "what they did; people rarely do this themselves."], key=f"deep:logcleared:{when}"))
    total = sum(failed.values())
    if total:
        top = ", ".join(f"{user} from {ip} ({n}x)" for (user, ip), n in failed.most_common(4))
        found.append(Finding("Accounts", f"{total} failed sign-in(s) in the last 7 days",
                             WARN if total >= FAILED_LOGON_WARN else NOTE,
                             [top, "A few are typos. Many, or from network addresses, mean someone is guessing "
                                   "passwords (often through Remote Desktop)."], key=f"deep:failed:{total // 10}"))
    if not found:
        found.append(Finding("Accounts", "No failed sign-ins, new accounts or new administrators this week", OK,
                             key="deep:accounts:ok"))
    return found


def wmi_findings(rows) -> list[Finding]:
    if not isinstance(rows, list):
        return []
    found = []
    for r in rows:
        kind, name = r.get("kind") or "?", r.get("name") or "?"
        if (kind, name) in NORMAL_CONSUMERS:
            continue
        action = r.get("command") or r.get("file") or (r.get("script") or "")[:300]
        active = kind in ("CommandLineEventConsumer", "ActiveScriptEventConsumer")
        found.append(Finding("WMI", f"WMI subscription runs {'a command' if active else 'an action'}: {name}",
                             WARN if active else NOTE,
                             ["WMI subscriptions run something when an event happens (at start-up, every few minutes). "
                              "Malware uses them to start itself without any visible startup entry." if active else
                              "A WMI subscription that logs or reports events. Usually installed by management or "
                              "hardware software.", f"{kind}: {action}"], key=f"wmi:{kind}:{name}"))
    if not found:
        found.append(Finding("WMI", "No unusual WMI subscriptions", OK, key="wmi:ok"))
    return found


def analyze(data: dict, context=None) -> tuple[list[Finding], dict]:
    """Findings from a collector's output, plus extra things to match: {"hosts": {...}, "procs": [...]}."""
    from atlas import cmdlines

    found = []
    if not data.get("admin"):
        found.append(Finding("Deep check", "The deep check didn't get administrator rights", NOTE,
                             ["Parts of it were refused, so some checks are missing."], key="deep:notadmin"))
    found += defender_findings(data.get("defender"))
    if data.get("admin"):  # without it the Security log just comes back empty, which proves nothing
        found += security_findings(data.get("security"))
    found += wmi_findings(data.get("wmi"))
    if data.get("admin") and isinstance(data.get("disks"), list):
        found += [f for f in health.check_disks(data["disks"]) if f.level != OK]
    procs = data.get("processes") or {}
    items = [cmdlines.Proc(**p) for p in procs.get("items") or []] if isinstance(procs, dict) else []
    found += cmdlines.evaluate(items, context)
    hosts = {}
    dns = data.get("dns")
    if isinstance(dns, list):
        hosts = {str(r.get("name") or "").lower().rstrip("."): "DNS cache" for r in dns if r.get("name")}
    return found, {"hosts": hosts, "procs": items}
