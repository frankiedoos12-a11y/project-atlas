"""Suspicious command lines: attacks that run inside clean Windows programs.

A VirusTotal hash lookup can't see these: powershell.exe, mshta.exe or rundll32.exe are Microsoft's
own, clean files. What gives an attack away is how they're started: an encoded PowerShell command,
a script fetched from the internet, Word starting a command prompt, a "svchost.exe" outside the
Windows folder. The rules below follow the open Sigma and LOLBAS projects, trimmed to what
signals trouble on a home PC running Windows 10 or 11, and each names its MITRE ATT&CK technique.

Atlas only reads: nothing is stopped.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import sys
from collections.abc import Iterable
from dataclasses import dataclass, field

from atlas.findings import NOTE, WARN, Finding

log = logging.getLogger(__name__)

SHELLS = r"(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|msiexec|schtasks|" \
         r"cmstp|forfiles|wmic|curl|installutil|msbuild|hh)\.exe"
OFFICE = r"(winword|excel|powerpnt|outlook|olk|onenote|msaccess|mspub|visio|acrord32|acrobat|foxitpdfreader|" \
         r"foxitphantompdf|sumatrapdf|wordpad|thunderbird|hwp)\.exe"
BROWSERS = r"(chrome|msedge|firefox|brave|opera|iexplore)\.exe"
USER_FOLDERS = r"(\\appdata\\|\\temp\\|\\downloads\\|\\users\\public\\|\\programdata\\|\\desktop\\|\\windows\\temp\\)"
DOWNLOAD = r"(downloadstring|downloadfile|downloaddata|invoke-webrequest|\biwr\b|invoke-restmethod|\birm\b|" \
           r"net\.webclient|start-bitstransfer|\bwget\b|\bcurl\b|xmlhttp|msxml2)"
RUN_IT = r"(\biex\b|invoke-expression|\|\s*iex|&\s*\(|\.invoke\(|scriptblock\]::create)"
# Windows' own programs, which only ever run from the Windows folder.
SYSTEM_NAMES = {"svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe", "smss.exe", "wininit.exe",
                "explorer.exe", "rundll32.exe", "dllhost.exe", "taskhostw.exe", "spoolsv.exe", "conhost.exe",
                "runtimebroker.exe", "sihost.exe", "lsm.exe", "ctfmon.exe", "fontdrvhost.exe", "dwm.exe",
                "searchindexer.exe", "wmiprvse.exe", "audiodg.exe", "taskmgr.exe", "regsvr32.exe", "mshta.exe",
                "powershell.exe", "cmd.exe", "certutil.exe", "msiexec.exe"}
# Common misspellings of those, used to blend in.
LOOKALIKES = re.compile(r"^(scvhost|svchosts|svhost|svch0st|svchot|lsas|lsasss|isass|csrsss|crss|winlogin|"
                        r"expl0rer|explorer32|iexplorer|rundl32|rundll|taskhost32|spoolsvc|dllhst)\.exe$", re.I)


@dataclass
class Proc:
    pid: int
    name: str
    exe: str = ""
    cmdline: str = ""
    parent: str = ""  # parent's process name
    ppid: int = 0


@dataclass
class Rule:
    id: str
    title: str
    technique: str  # MITRE ATT&CK
    level: str
    why: str
    image: str = ".*"  # process name
    cmd: str | None = None  # command line
    parent: str | None = None
    unless: str | None = None  # command line that makes it harmless
    _compiled: dict = field(default_factory=dict, repr=False)

    def _re(self, name: str) -> re.Pattern | None:
        text = getattr(self, name)
        if text is None:
            return None
        if name not in self._compiled:
            self._compiled[name] = re.compile(text if name != "image" else f"^{text}$", re.I | re.S)
        return self._compiled[name]

    def matches(self, p: Proc) -> bool:
        if not self._re("image").search(p.name or ""):
            return False
        if self.cmd and not self._re("cmd").search(p.cmdline or ""):
            return False
        if self.parent and not self._re("parent").search(p.parent or ""):
            return False
        return not (self.unless and self._re("unless").search(p.cmdline or ""))


PS = r"(powershell|pwsh|powershell_ise)\.exe"
RULES = [
    Rule("ps-encoded", "PowerShell running an encoded (hidden) command", "T1059.001", WARN,
         "The command is base64-encoded so it can't be read at a glance. Malware does this all the time; "
         "admin tools rarely do", PS, r"\s[-/]e(c|n|nc|nco|ncod|ncode|ncoded|ncodedc\w*)?\s+[a-z0-9+/=]{40,}"),
    Rule("ps-download-run", "PowerShell downloading and running code", "T1059.001", WARN,
         "It fetches code from the internet and runs it straight from memory: the classic 'download cradle', "
         "also what fake CAPTCHA (\"ClickFix\") pages tell people to paste into the Run box",
         PS, rf"{DOWNLOAD}.*{RUN_IT}|{RUN_IT}.*{DOWNLOAD}"),
    Rule("ps-hidden-download", "Hidden PowerShell window downloading something", "T1059.001", WARN,
         "A hidden PowerShell window that downloads files", PS, rf"-w(i|in|ind|indo|indow|indows\w*)?\s+h(i|id|idd|idde|idden)?\b.*{DOWNLOAD}"),
    Rule("ps-user-script", "PowerShell running a script from a download or temporary folder", "T1059.001", NOTE,
         "Scripts started from Downloads or Temp with the safety policy switched off are worth a look",
         PS, rf"-ex\w*\s+(bypass|unrestricted).*{USER_FOLDERS}[^\s\"']*\.ps1"),
    Rule("ps-defender-off", "PowerShell switching off parts of Defender", "T1562.001", WARN,
         "Malware turns off Defender's protection, or excludes its own folder from scanning, before doing damage",
         PS, r"(set-mppreference\s.*-disable\w+\s+(\$true|1)|add-mppreference\s.*-exclusion\w+)"),
    Rule("mshta-remote", "mshta running a script from the internet", "T1218.005", WARN,
         "mshta runs HTML applications. Started with a web address or inline script, it's almost always "
         "malware or a fake-CAPTCHA page's pasted command", r"mshta\.exe", r"(https?://|javascript:|vbscript:)"),
    Rule("rundll32-script", "rundll32 running script code", "T1218.011", WARN,
         "rundll32 should load a DLL, not script code", r"rundll32\.exe", r"(javascript:|vbscript:|mshtml,runhtmlapplication)"),
    Rule("rundll32-userdll", "rundll32 loading a DLL from a user folder", "T1218.011", NOTE,
         "Usually a program's own helper; malware also hides DLLs in AppData or Temp and starts them this way",
         r"rundll32\.exe", USER_FOLDERS, unless=r"\\appdata\\local\\(microsoft|google|programs)\\"),
    Rule("regsvr32-remote", "regsvr32 loading a script (\"Squiblydoo\")", "T1218.010", WARN,
         "regsvr32 told to fetch and run a script, a well-known way to slip past application controls",
         r"regsvr32\.exe", r"(/i:\s*https?://|scrobj\.dll|/i:[^\s]*\.sct)"),
    Rule("certutil-download", "certutil downloading or decoding files", "T1105", WARN,
         "certutil manages certificates. Attackers use it to download or unpack malware because it's trusted",
         r"certutil\.exe", r"(-urlcache|/urlcache|-verifyctl.*https?://|-decode(hex)?\b|/decode(hex)?\b)"),
    Rule("bitsadmin-download", "bitsadmin downloading a file", "T1197", WARN,
         "Windows' background download service, abused to fetch malware quietly",
         r"bitsadmin\.exe", r"/(transfer|addfile|setnotifycmdline)"),
    Rule("script-user-folder", "Script started from Downloads, Temp or an email attachment", "T1059.005", WARN,
         "JavaScript and VBScript files run by Windows Script Host are a common email-attachment trick",
         r"(wscript|cscript)\.exe", rf"{USER_FOLDERS}.*\.(js|jse|vbs|vbe|wsf|wsh|hta)\b|content\.outlook"),
    Rule("msiexec-remote", "Installer run straight from the internet", "T1218.007", WARN,
         "msiexec installing a package from a web address, without a download you chose",
         r"msiexec\.exe", r"/(i|package)\s*\"?https?://"),
    Rule("cmstp-inf", "cmstp installing a connection profile from a user folder", "T1218.003", WARN,
         "cmstp with a profile from a user folder is a known way to run code with no prompt",
         r"cmstp\.exe", rf"{USER_FOLDERS}.*\.inf"),
    Rule("shadow-delete", "Deleting backups and restore points", "T1490", WARN,
         "Ransomware deletes Windows' restore points and backups first so files can't be recovered",
         r"(vssadmin|wmic|wbadmin|bcdedit|powershell|pwsh)\.exe",
         r"(delete\s+shadows|shadowcopy\s+delete|delete\s+catalog|recoveryenabled\s+no|"
         r"ignoreallfailures|win32_shadowcopy.*delete)"),
    Rule("firewall-off", "Switching the firewall off", "T1562.004", WARN,
         "Turning off Windows Firewall from the command line", r"(netsh|powershell|pwsh)\.exe",
         r"(advfirewall\s+set\s+\w+\s+state\s+off|firewall\s+set\s+opmode\s+disable|"
         r"set-netfirewallprofile\s.*-enabled\s+(false|0))"),
    Rule("log-clear", "Clearing Windows' event logs", "T1070.001", WARN,
         "Attackers wipe the logs to cover their tracks", r"(wevtutil|powershell|pwsh)\.exe",
         r"(\bcl\b|clear-log|clear-eventlog)"),
    Rule("add-admin", "Creating a user or making someone an administrator", "T1136.001", WARN,
         "New accounts and new administrators are how attackers keep a way back in",
         r"(net|net1|powershell|pwsh)\.exe", r"(user\s+\S+\s+\S+\s+/add|localgroup\s+administrators\s+\S+\s+/add|"
                                            r"new-localuser|add-localgroupmember\s.*administrators)"),
    Rule("schtask-user", "Scheduled task set to run something from a user folder", "T1053.005", WARN,
         "A task that starts a program from AppData, Temp or Downloads at sign-in or every few minutes is a "
         "common way for malware to come back after a restart", r"(schtasks|powershell|pwsh)\.exe",
         rf"(/create|register-scheduledtask).*{USER_FOLDERS}"),
    Rule("run-key-user", "Adding a startup entry for a program in a user folder", "T1547.001", NOTE,
         "Programs in user folders that add themselves to startup are worth knowing about",
         r"(reg|powershell|pwsh)\.exe", rf"\\currentversion\\run.*{USER_FOLDERS}"),
    Rule("office-child", "An Office document, PDF or email started a command shell or script", "T1204.002", WARN,
         "Word, Excel, Outlook or a PDF reader starting PowerShell, a command prompt or a script host is how "
         "booby-trapped attachments get in", SHELLS, parent=f"^{OFFICE}$"),
    Rule("browser-script", "The browser started a script host or PowerShell", "T1204.002", WARN,
         "Opening a downloaded script straight from the browser. Fine only if you meant to run it",
         r"(wscript|cscript|mshta|powershell|pwsh)\.exe", parent=f"^{BROWSERS}$"),
    Rule("run-box-cradle", "Command pasted into the Run box downloads and runs code", "T1204.004", WARN,
         "Fake CAPTCHA and \"fix this error\" pages (ClickFix) tell people to press Windows+R and paste a command. "
         "If you did that, disconnect from the internet and run a full scan",
         r"(powershell|pwsh|mshta|cmd)\.exe", rf"({DOWNLOAD}|https?://)", parent=r"^explorer\.exe$",
         unless=r"\\windowsapps\\|-file\s"),
]


def system_lookalike(p: Proc) -> str | None:
    """Why a process name pretends to be part of Windows, or None."""
    name = (p.name or "").lower()
    exe = os.path.normcase(p.exe or "")
    windows = os.path.normcase(os.environ.get("WINDIR", r"C:\Windows"))
    if LOOKALIKES.match(name):
        return f"\"{p.name}\" is a misspelling of a Windows program name, a trick to blend in"
    if name in SYSTEM_NAMES and exe and not exe.startswith(windows + os.sep):
        return f"{p.name} is part of Windows and only runs from the Windows folder, but this copy runs from {p.exe}"
    return None


def _own_pids() -> set[int]:
    """Atlas itself and the helpers it starts (PowerShell for signatures and settings)."""
    return {os.getpid()}


def evaluate(procs: Iterable[Proc], context=None) -> list[Finding]:
    """Findings for the processes that match a rule. `context(technique)` may add a line of
    threat-intel context, e.g. which GTI reports use the technique."""
    own = _own_pids()
    found: dict[str, Finding] = {}
    for p in procs:
        if p.pid in own or p.ppid in own:
            continue
        hits = [r for r in RULES if r.matches(p)]
        why = system_lookalike(p)
        for rule in hits:
            add(found, p, rule.id, rule.title, rule.level, [rule.why], rule.technique, context)
        if why:
            add(found, p, "masquerade", "A program pretending to be part of Windows", WARN, [why], "T1036.005", context)
    return sorted(found.values(), key=lambda f: (f.level != WARN, f.title))


def add(found: dict, p: Proc, rule_id: str, title: str, level: str, why: list[str], technique: str, context) -> None:
    digest = hashlib.sha1(f"{p.name}|{p.cmdline}".encode("utf-8", "replace")).hexdigest()[:12]
    key = f"cmdline:{rule_id}:{digest}"
    if key in found:
        found[key].data["pids"].append(p.pid)
        return
    details = list(why)
    details.append(f"Process: {p.name} (PID {p.pid})" + (f", started by {p.parent}" if p.parent else ""))
    if p.cmdline:
        details.append(f"Command line: {p.cmdline[:600]}")
    details.append(f"MITRE ATT&CK {technique}")
    extra = context(technique) if context else None
    if extra:
        details.append(extra)
    found[key] = Finding("Command lines", f"{title}: {p.name}", level, details, key=key,
                         vt_link=f"https://attack.mitre.org/techniques/{technique.replace('.', '/')}/",
                         data={"pids": [p.pid], "technique": technique, "exe": p.exe})


def processes() -> tuple[list[Proc], int]:
    """Every process with its command line and parent, plus how many Windows wouldn't show."""
    import psutil

    names = {}
    procs, hidden = [], 0
    rows = list(psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline"]))
    for p in rows:
        names[p.info["pid"]] = p.info["name"] or ""
    for p in rows:
        info = p.info
        if info["pid"] in (0, 4):
            continue
        cmd = info.get("cmdline")
        if cmd is None:
            hidden += 1
        procs.append(Proc(info["pid"], info["name"] or "", info.get("exe") or "",
                          _join(cmd), names.get(info.get("ppid") or 0, ""), info.get("ppid") or 0))
    return procs, hidden


def process(pid: int) -> Proc | None:
    import psutil

    try:
        p = psutil.Process(pid)
        with p.oneshot():
            parent = p.parent()
            return Proc(pid, p.name(), p.exe() or "", _join(p.cmdline()), parent.name() if parent else "", p.ppid())
    except (psutil.Error, OSError):
        return None


def _join(cmd) -> str:
    if not cmd:
        return ""
    if sys.platform == "win32":
        import subprocess

        return subprocess.list2cmdline(cmd)
    return " ".join(cmd)
