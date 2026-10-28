"""Turn a VirusTotal sandbox report into plain sentences: what a file actually does when run.

VirusTotal runs files in several sandboxes and merges what they saw (registry changes,
programs started, servers contacted, ...). Most of it is noise to anyone but an analyst, so
only the things that tell you what kind of trouble a file is get a sentence here.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import PureWindowsPath

MAX_LINES = 12

VERDICTS = {
    "RAT": "Lets an attacker control the PC remotely",
    "STEALER": "Steals passwords, browser cookies or other personal data",
    "RANSOM": "Encrypts your files and demands a ransom",
    "RANSOMWARE": "Encrypts your files and demands a ransom",
    "BANKER": "Goes after online banking logins",
    "MINER": "Secretly uses the PC to mine cryptocurrency",
    "CRYPTOMINER": "Secretly uses the PC to mine cryptocurrency",
    "KEYLOGGER": "Records what you type",
    "BACKDOOR": "Opens a hidden way into the PC",
    "SPYWARE": "Spies on what you do",
    "SPREADER": "Tries to spread to other computers",
    "WORM": "Tries to spread to other computers",
    "DROPPER": "Downloads or unpacks more malware",
    "LOADER": "Downloads or unpacks more malware",
    "DOWNLOADER": "Downloads or unpacks more malware",
    "ADWARE": "Shows unwanted ads",
    "PUP": "Potentially unwanted: bundled extras, adware or similar",
    "PUA": "Potentially unwanted: bundled extras, adware or similar",
    "GREYWARE": "Potentially unwanted: bundled extras, adware or similar",
    "EXPLOIT": "Exploits flaws in other software",
    "EVADER": "Works to avoid being detected",
    "HACKTOOL": "A hacking tool",
}

TAGS = {
    "PERSISTENCE": "Sets itself up to start with Windows",
    "SELF_DELETE": "Deletes itself afterwards to cover its tracks",
    "OBFUSCATED": "Disguises its own code",
    "DETECT_DEBUG_ENVIRONMENT": "Checks whether it is being watched or analysed",
    "LONG_SLEEPS": "Waits a long time before acting, to get past security checks",
    "INSTALLS_BROWSER_EXTENSION": "Installs a browser extension",
    "TUNNELING": "Hides its network traffic inside a tunnel",
}

AUTOSTART = re.compile(r"\\currentversion\\(run|runonce|policies\\explorer\\run)\b|\\winlogon\\(shell|userinit)"
                       r"|\\image file execution options\\|\\currentcontrolset\\services\\", re.I)
UAC = re.compile(r"enablelua|consentpromptbehavioradmin", re.I)
DEFENDER = re.compile(r"windows defender|disableantispyware|disablerealtimemonitoring|-exclusion(path|process)|"
                      r"set-mppreference|add-mppreference", re.I)
PROXY = re.compile(r"internet settings\\(proxyserver|autoconfigurl)", re.I)
BROWSER_START = re.compile(r"\\(start page|searchscopes|default_search_provider)", re.I)
SHADOW_COPIES = re.compile(r"vssadmin.*delete|wbadmin.*delete|shadowcopy.*delete|recoveryenabled\s+no", re.I)
SCHEDULED_TASK = re.compile(r"schtasks(\.exe)?\s.*/create", re.I)
FIREWALL = re.compile(r"netsh(\.exe)?\s+(advfirewall|firewall)", re.I)
HIDDEN_POWERSHELL = re.compile(r"powershell.*\s-(e|en|enc|encodedcommand|w\s+hidden|windowstyle\s+hidden)\b", re.I)
PROGRAM_TYPES = {".exe", ".dll", ".scr", ".sys", ".ps1", ".vbs", ".js", ".bat", ".cmd", ".hta", ".msi"}
# Lookups every Windows sandbox run makes on its own.
BACKGROUND_HOSTS = re.compile(r"(^|\.)(microsoft\.com|windowsupdate\.com|msftncsi\.com|msftconnecttest\.com|"
                              r"windows\.com|live\.com|bing\.com|bing\.net|digicert\.com|verisign\.com|"
                              r"globalsign\.com|sectigo\.com|usertrust\.com|msedge\.net|akamaiedge\.net)$", re.I)


def _public_ip(text: str) -> bool:
    try:
        return ipaddress.ip_address(text).is_global
    except ValueError:
        return False


def describe_behaviour(summary: dict | None) -> list[str]:
    if not summary:
        return []
    lines: list[str] = []

    def say(text: str) -> None:
        if text not in lines:
            lines.append(text)

    for verdict in summary.get("verdicts") or []:
        if verdict in VERDICTS:
            say(VERDICTS[verdict])

    registry = [f"{k.get('key', '')}={k.get('value', '')}" for k in summary.get("registry_keys_set") or []
                if isinstance(k, dict)]
    commands = [c for c in (summary.get("command_executions") or []) + (summary.get("processes_created") or [])
                if isinstance(c, str)]
    everything = registry + commands

    if "PERSISTENCE" in (summary.get("tags") or []) or any(AUTOSTART.search(r) for r in registry):
        say(TAGS["PERSISTENCE"])
    if any(UAC.search(r) for r in everything):
        say("Turns off User Account Control (the \"Do you want to allow...\" prompts)")
    if any(DEFENDER.search(r) for r in everything):
        say("Tampers with Windows Defender")
    if any(SHADOW_COPIES.search(c) for c in commands):
        say("Deletes Windows backup snapshots, which ransomware does before encrypting")
    if summary.get("services_created"):
        say("Installs a Windows service")
    if any(SCHEDULED_TASK.search(c) for c in commands):
        say("Creates a scheduled task")
    if any(FIREWALL.search(c) for c in commands):
        say("Changes firewall settings")
    if any(HIDDEN_POWERSHELL.search(c) for c in commands):
        say("Runs hidden or scrambled PowerShell commands")
    if any(PROXY.search(r) for r in registry):
        say("Changes your proxy settings, which can redirect your web traffic")
    if any(BROWSER_START.search(r) for r in registry):
        say("Changes the browser's home page or search engine")

    dropped = {PureWindowsPath(f.get("path", "")).name for f in summary.get("files_dropped") or []
               if isinstance(f, dict) and PureWindowsPath(f.get("path", "")).suffix.lower() in PROGRAM_TYPES}
    if dropped:
        say(f"Puts {len(dropped)} other program file(s) on the PC")

    servers = [d["hostname"] for d in summary.get("dns_lookups") or []
               if isinstance(d, dict) and d.get("hostname") and not BACKGROUND_HOSTS.search(d["hostname"])]
    servers += [t["destination_ip"] for t in summary.get("ip_traffic") or []
                if isinstance(t, dict) and _public_ip(str(t.get("destination_ip", "")))]
    servers = list(dict.fromkeys(servers))
    if servers:
        shown = ", ".join(servers[:3]) + (f" and {len(servers) - 3} more" if len(servers) > 3 else "")
        say(f"Contacts {len(servers)} server(s) on the internet: {shown}")

    for tag in summary.get("tags") or []:
        if tag in TAGS:
            say(TAGS[tag])

    high = [t.get("signature_description") for t in summary.get("mitre_attack_techniques") or []
            if isinstance(t, dict) and t.get("severity") == "IMPACT_SEVERITY_HIGH" and t.get("signature_description")]
    if high:
        say("Sandboxes also flagged: " + "; ".join(list(dict.fromkeys(high))[:3]))
    return lines[:MAX_LINES]
