"""Drivers and services: is anything running in the Windows kernel that shouldn't be?

- Loaded drivers are hashed and compared with the LOLDrivers project's list of known-vulnerable
  and malicious drivers. Attackers "bring their own" signed but vulnerable driver to switch off
  antivirus from inside the kernel. The list is downloaded once a week and kept on this PC.
- Whether Windows' own vulnerable-driver blocklist and Memory Integrity (core isolation) are on.
- Drivers and services installed in the last 30 days (Windows logs each one), flagged when they
  run something from a user folder or a script, a common way for malware to start as SYSTEM.
- With a Google Threat Intelligence / Enterprise key, every driver is also looked up on VirusTotal.

Nothing is stopped or removed.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests

from atlas.findings import NOTE, OK, WARN, Finding
from atlas.local_checks import run_powershell_json

log = logging.getLogger(__name__)

NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
LOLDRIVERS_URL = "https://www.loldrivers.io/api/drivers.json"
LOLDRIVERS_PAGE = "https://www.loldrivers.io/drivers/{id}/"
REFRESH_DAYS = 7
CORE_ISOLATION = "windowsdefender://coreisolation"
USER_FOLDERS = re.compile(r"\\(appdata|temp|downloads|users\\public|desktop)\\", re.I)
# Installers put real services here too (Defender, Malwarebytes), so a valid signature clears these.
PROGRAM_DATA = re.compile(r"\\programdata\\", re.I)
SCRIPTY = re.compile(r"(powershell|pwsh|cmd(\.exe)?\s+/c|mshta|rundll32|wscript|cscript|regsvr32)", re.I)

_EVENTS_SCRIPT = (
    "$since = (Get-Date).AddDays(-30); ConvertTo-Json -Compress -InputObject @("
    "Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045; StartTime=$since} -ErrorAction SilentlyContinue |"
    " ForEach-Object { [pscustomobject]@{ when=$_.TimeCreated.ToString('yyyy-MM-dd HH:mm');"
    " name=[string]$_.Properties[0].Value; path=[string]$_.Properties[1].Value; type=[string]$_.Properties[2].Value;"
    " start=[string]$_.Properties[3].Value; account=[string]$_.Properties[4].Value } })"
)


# --- LOLDrivers ------------------------------------------------------------------------

def _feed_file() -> Path:
    from atlas import config

    return config.data_dir() / "loldrivers.json"


def compact_feed(raw: list[dict]) -> dict[str, list[str]]:
    """sha256 -> [LOLDrivers id, driver name, category] from the project's full JSON."""
    hashes: dict[str, list[str]] = {}
    for d in raw:
        name = (d.get("Tags") or ["?"])[0]
        for s in d.get("KnownVulnerableSamples") or []:
            sha = (s.get("SHA256") or "").lower()
            if len(sha) == 64:
                hashes[sha] = [d.get("Id", ""), s.get("Filename") or name, d.get("Category", "vulnerable driver")]
    return hashes


def loldrivers(refresh: bool = True) -> dict[str, list[str]]:
    """The known-bad driver hashes, downloaded at most once a week."""
    path = _feed_file()
    data = {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        pass
    fetched = datetime.fromisoformat(data["fetched"]) if data.get("fetched") else None
    if refresh and (fetched is None or (datetime.now(timezone.utc) - fetched).days >= REFRESH_DAYS):
        try:
            resp = requests.get(LOLDRIVERS_URL, timeout=120)
            resp.raise_for_status()
            data = {"fetched": datetime.now(timezone.utc).isoformat(), "hashes": compact_feed(resp.json())}
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(data), encoding="utf-8")
            log.info("LOLDrivers list updated: %d driver hashes", len(data["hashes"]))
        except (requests.RequestException, ValueError, OSError) as exc:
            log.info("Couldn't update the LOLDrivers list: %s", exc)
    return data.get("hashes") or {}


# --- Loaded drivers -----------------------------------------------------------------------

def loaded_drivers(text: str | None = None) -> list[tuple[str, Path]]:
    """(name, file) for every running driver."""
    if text is None:
        try:
            out = subprocess.run(["driverquery", "/v", "/fo", "csv"], capture_output=True, timeout=120,
                                 creationflags=NO_WINDOW)
        except (OSError, subprocess.TimeoutExpired) as exc:
            log.info("driverquery failed: %s", exc)
            return []
        text = out.stdout.decode("mbcs" if sys.platform == "win32" else "utf-8", errors="replace")
    found = []
    for row in csv.DictReader(io.StringIO(text)):
        if row.get("State") == "Running" and row.get("Path"):
            found.append((row.get("Display Name") or row.get("Module Name") or "?", Path(image_path(row["Path"]))))
    return found


def image_path(command: str) -> str:
    """A service's or driver's file from its ImagePath: quotes, arguments, \\SystemRoot and \\??\\ removed."""
    command = command.strip()
    if command.startswith('"'):
        command = command[1:].split('"', 1)[0]
    else:
        m = re.match(r"(?i)(.+?\.(exe|sys|dll))(\s|$)", command)
        command = m.group(1) if m else command.split(" ")[0]
    windir = os.environ.get("WINDIR", r"C:\Windows")
    command = re.sub(r"(?i)^\\\?\?\\", "", command)
    command = re.sub(r"(?i)^(\\systemroot|%systemroot%)", windir.replace("\\", "\\\\"), command)
    if re.match(r"(?i)^system32\\", command):
        command = os.path.join(windir, command)
    return os.path.expandvars(command)


def protection_status() -> list[Finding]:
    """Windows' vulnerable-driver blocklist and Memory Integrity."""
    if sys.platform != "win32":
        return []
    import winreg

    def value(path: str, name: str):
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
                return winreg.QueryValueEx(key, name)[0]
        except OSError:
            return None

    found = []
    blocklist = value(r"SYSTEM\CurrentControlSet\Control\CI\Config", "VulnerableDriverBlocklistEnable")
    hvci = value(r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity", "Enabled")
    fix = dict(fix="open", fix_label="Open Core isolation", data={"url": CORE_ISOLATION})
    if blocklist == 0:
        found.append(Finding("Drivers", "Microsoft's vulnerable driver blocklist is off", WARN,
                             ["It stops drivers that attackers are known to abuse from loading. Turn on "
                              "\"Microsoft Vulnerable Driver Blocklist\" under Device security > Core isolation."],
                             key="drivers:blocklist:off", **fix))
    else:
        found.append(Finding("Drivers", "Microsoft's vulnerable driver blocklist is on", OK, key="drivers:blocklist:ok"))
    if hvci == 1:
        found.append(Finding("Drivers", "Memory integrity is on", OK, key="drivers:hvci:ok"))
    else:
        found.append(Finding("Drivers", "Memory integrity (core isolation) is off", NOTE,
                             ["It keeps malicious and vulnerable drivers from tampering with Windows' core. Most "
                              "PCs from the last few years can turn it on under Device security > Core isolation; "
                              "Windows will say if a driver is in the way."], key="drivers:hvci:off", **fix))
    return found


def driver_findings(drivers: list[tuple[str, Path]], hashes: dict[str, str], bad: dict[str, list[str]]) -> list[Finding]:
    """`hashes` maps a driver's path to its SHA-256."""
    found = []
    for name, path in drivers:
        sha = hashes.get(str(path))
        hit = bad.get(sha or "")
        if not hit:
            continue
        lol_id, lol_name, category = hit
        malicious = category == "malicious"
        found.append(Finding(
            "Drivers", f"{'Malicious' if malicious else 'Known-vulnerable'} driver loaded: {path.name}", WARN,
            [("This driver is known malware." if malicious else
              "This signed driver has a known flaw that attackers use to switch off antivirus and take over Windows "
              "from inside the kernel (\"bring your own vulnerable driver\").") +
             f" LOLDrivers lists it as {lol_name}.",
             f"Driver: {name}, file {path}",
             "Update or uninstall the program that installed it (often an old hardware, RGB-lighting, overclocking or "
             "anti-cheat tool). Turning on Memory integrity also blocks most of these."],
            key=f"drivers:lol:{sha}", vt_link=LOLDRIVERS_PAGE.format(id=lol_id),
            data={"path": str(path), "sha256": sha}))
    return found


# --- New services ---------------------------------------------------------------------------

def new_services(rows: list[dict] | None = None) -> list[dict]:
    if rows is None:
        try:
            rows = run_powershell_json(_EVENTS_SCRIPT, timeout=90)
        except Exception:
            log.exception("Couldn't read service installs")
            rows = []
    return rows


def service_findings(rows: list[dict], signatures: dict | None = None) -> list[Finding]:
    """`signatures` maps a program path to its Signature; ProgramData services are checked with it."""
    if signatures is None:
        from atlas.local_checks import check_signatures

        signatures = check_signatures(sorted({Path(image_path(r.get("path") or "")) for r in rows
                                              if PROGRAM_DATA.search(r.get("path") or "")}))
    found, seen = [], set()
    for r in rows:
        command = r.get("path") or ""
        if (r.get("name"), command) in seen:
            continue  # reinstalled by an update: once is enough
        seen.add((r.get("name"), command))
        reasons = []
        if SCRIPTY.search(command):
            reasons.append("It runs a command or script instead of a program, a common way for malware to run as "
                           "SYSTEM at every start")
        if USER_FOLDERS.search(command):
            reasons.append("Its program is in a user folder (AppData, Temp, Downloads, Desktop...), where proper "
                           "services and drivers don't live")
        elif PROGRAM_DATA.search(command) and Path(image_path(command)).exists():  # gone: a one-time updater
            sig = signatures.get(str(Path(image_path(command))))
            if not (sig and sig.valid):
                reasons.append("Its program is in ProgramData and isn't validly signed. Real services there (Defender, "
                               "antivirus updaters) are signed")
        if not reasons:
            continue
        found.append(Finding("Services", f"New {r.get('type') or 'service'}: {r.get('name')}", WARN,
                             reasons + [f"Installed {r.get('when')}, starts {r.get('start') or '?'}, runs as "
                                        f"{r.get('account') or '?'}", f"Command: {command[:400]}"],
                             key=f"services:{r.get('name')}:{command[:120]}",
                             data={"path": image_path(command) if command else ""}))
    if rows:
        found.append(Finding("Services", f"{len(rows)} driver and service install(s) in the last 30 days"
                             + ("; none look out of place" if not found else ""), OK if not found else NOTE,
                             ["Windows logs every one. Updates install many (Defender, graphics, browsers)."],
                             key="services:summary"))
    return found
