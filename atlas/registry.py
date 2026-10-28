"""Registry check: the hiding places and settings the startup check doesn't cover.

The Startup items tab already reads the Run keys, services, drivers, Winlogon and IFEO debuggers.
This covers the rest of the well-known spots, all readable without administrator rights:

- Hijacks: per-user COM objects overriding Windows' own (loads a DLL into Explorer and other
  programs), and the "open" commands abused to get administrator rights with no prompt
- Other ways to start: Command Processor AutoRun, Active Setup, AppInit/AppCert DLLs, silent
  process exit monitors, the crash debugger, netsh helpers, print monitors, time providers, the
  screensaver, logon scripts, the .NET profiler hook, Office's test DLL and startup folders
- Passwords: unknown LSA packages and password filters, WDigest keeping passwords readable in
  memory, LSA protection
- Settings attackers loosen: Office macros and Protected View, UAC, Remote Desktop

Each finding says when its key last changed. `snapshot()` and `changes()` let the tray notice when
any of these change.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from atlas.drivers import image_path
from atlas.findings import NOTE, OK, WARN, Finding

log = logging.getLogger(__name__)

USER_FOLDERS = re.compile(r"\\(appdata|temp|downloads|users\\public|desktop|documents)\\|^\\\\", re.I)
SCRIPTY = re.compile(r"(powershell|pwsh|mshta|wscript|cscript|certutil|bitsadmin|https?://|javascript:|"
                     r"\.(vbs|js|jse|hta|ps1|bat|cmd)\b)", re.I)
LOADERS = re.compile(r"\b(rundll32|regsvr32)(\.exe)?\b", re.I)  # fine when the DLL they load is Windows' own
SYSTEM_FOLDERS = re.compile(r"^[a-z]:\\windows\\(system32|syswow64)\\", re.I)

WINDOWS_NT = r"Software\Microsoft\Windows NT\CurrentVersion"
LSA = r"SYSTEM\CurrentControlSet\Control\Lsa"
KNOWN_LSA = {"msv1_0", "kerberos", "schannel", "wdigest", "tspkg", "pku2u", "cloudap", "negoexts", "scecli",
             "rassfm", "livessp", "", '""', "msoidssp", "kdcpw"}
KNOWN_NETSH = {"ifmon.dll", "rasmontr.dll", "authfwcfg.dll", "dhcpcmonitor.dll", "nshdnsclient.dll", "dot3cfg.dll",
               "fwcfg.dll", "hnetmon.dll", "netiohlp.dll", "netprofm.dll", "nettrace.dll", "nshhttp.dll",
               "nshipsec.dll", "nshwfp.dll", "rpcnsh.dll", "wcnnetsh.dll", "whhelper.dll", "wlancfg.dll",
               "wshelper.dll", "wwancfg.dll", "peerdistsh.dll", "p2pnetsh.dll", "napmontr.dll", "dhcpmonitor.dll"}
UAC_BYPASS_KEYS = {
    r"Software\Classes\ms-settings\shell\open\command": "fodhelper / computerdefaults",
    r"Software\Classes\mscfile\shell\open\command": "eventvwr",
    r"Software\Classes\exefile\shell\open\command": "every program you start",
    r"Software\Classes\Folder\shell\open\command": "sdclt",
    r"Software\Classes\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\Shell\open\command": "wsreset",
    r"Software\Classes\Launcher.SystemSettings\Shell\Open\command": "Settings",
    r"Software\Classes\ms-cxh-full\shell\open\command": "Windows setup",
}
OFFICE_APPS = ("Word", "Excel", "PowerPoint", "Outlook", "Access", "Publisher", "Visio")
RISKY_TRUSTED = re.compile(r"(downloads|desktop|documents|\\temp\\|\\temp$|onedrive)|^\\\\|^[a-z]:\\?$", re.I)


# --- Reading the registry ---------------------------------------------------------------------------

class Registry:
    """Read-only registry access. Hives are "HKCU" and "HKLM"; missing keys read as empty."""

    def _open(self, hive: str, path: str):
        import winreg

        return winreg.OpenKey({"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}[hive], path)

    def values(self, hive: str, path: str) -> dict | None:
        """name -> value ("" is the key's default value), or None when the key doesn't exist."""
        import winreg

        try:
            with self._open(hive, path) as key:
                return {winreg.EnumValue(key, i)[0]: winreg.EnumValue(key, i)[1]
                        for i in range(winreg.QueryInfoKey(key)[1])}
        except OSError:
            return None

    def subkeys(self, hive: str, path: str) -> list[str]:
        import winreg

        try:
            with self._open(hive, path) as key:
                return [winreg.EnumKey(key, i) for i in range(winreg.QueryInfoKey(key)[0])]
        except OSError:
            return []

    def changed(self, hive: str, path: str) -> datetime | None:
        """When the key was last written (local time)."""
        import winreg

        try:
            with self._open(hive, path) as key:
                stamp = winreg.QueryInfoKey(key)[2]
        except OSError:
            return None
        return (datetime(1601, 1, 1) + timedelta(microseconds=stamp // 10) + _utc_offset()) if stamp else None


def _utc_offset() -> timedelta:
    return datetime.now().astimezone().utcoffset() or timedelta(0)


@dataclass
class Spot:
    """One registry value Atlas watches: where it is, and what it's set to."""

    area: str
    hive: str
    path: str
    name: str
    value: object

    @property
    def id(self) -> str:
        return f"{self.hive}\\{self.path}|{self.name}"

    @property
    def location(self) -> str:
        return f"{self.hive}\\{self.path}" + (f" > {self.name}" if self.name else " > (default)")


class Check:
    def __init__(self, reg: Registry):
        self.reg = reg
        self.found: list[Finding] = []
        self.spots: list[Spot] = []  # everything read, for the change watch

    def watch(self, area: str, hive: str, path: str, name: str, value) -> None:
        self.spots.append(Spot(area, hive, path, name, value))

    def add(self, area: str, title: str, level: str, why: list[str], hive: str, path: str, name: str = "",
            value=None, file: str | None = None, key: str | None = None) -> None:
        when = self.reg.changed(hive, path)
        location = f"{hive}\\{path}" + (f" > {name}" if name else "")
        details = list(why) + [f"Registry: {location}" + (f" = {_text(value)[:300]}" if value is not None else "")]
        if when:
            details.append(f"Key last changed {when:%Y-%m-%d %H:%M}")
        self.found.append(Finding(area, title, level, details, key=key or f"reg:{location.lower()}:{_digest(value)}",
                                  data={"path": file, "registry": location}))


def _text(value) -> str:
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value)
    if isinstance(value, bytes):
        return value.hex()[:80]
    return str(value)


def _digest(value) -> str:
    return hashlib.sha1(_text(value).encode("utf-8", "replace")).hexdigest()[:10]


def file_of(command: str) -> str:
    """The program or DLL a registry value points to (bare DLL names live in System32)."""
    path = image_path(str(command or "")).strip()
    if path and not re.match(r"^[a-z]:\\|^\\\\", path, re.I) and re.search(r"\.(dll|exe|cpl|scr|ocx)$", path, re.I):
        path = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "System32", path)
    return path


def _odd_location(command: str) -> str | None:
    """Why a command or DLL path looks wrong for a system hook, or None."""
    if SCRIPTY.search(str(command)):
        return "It runs a script or downloads something, not a program"
    if LOADERS.search(str(command)):
        dlls = re.findall(r"[a-z]:\\[^,\"]+?\.(?:dll|ocx|cpl)\b", os.path.expandvars(str(command)), re.I)
        if not dlls or not all(SYSTEM_FOLDERS.match(d) for d in dlls):
            return "It uses rundll32/regsvr32 to load a DLL from outside Windows"
        return None
    path = file_of(command)
    if USER_FOLDERS.search(path):
        return "It points into a user folder (AppData, Temp, Downloads...), where system hooks never live"
    return None


# --- Hijacks -------------------------------------------------------------------------------------------

def com_hijacks(c: Check) -> None:
    for clsid in c.reg.subkeys("HKCU", r"Software\Classes\CLSID"):
        for server in ("InprocServer32", "LocalServer32"):
            path = rf"Software\Classes\CLSID\{clsid}\{server}"
            user = c.reg.values("HKCU", path)
            if user is None:
                continue
            target = user.get("") or ""
            c.watch("COM objects", "HKCU", path, "", target)
            machine = c.reg.values("HKLM", path)
            scriptlet = c.reg.values("HKCU", rf"Software\Classes\CLSID\{clsid}\ScriptletURL")
            if scriptlet is not None:
                c.add("COM objects", f"COM object runs a script from a web address: {clsid}", WARN,
                      ["A per-user COM object loads a scriptlet from the internet when any program uses it."],
                      "HKCU", rf"Software\Classes\CLSID\{clsid}\ScriptletURL", "", scriptlet.get(""))
            elif machine is not None and os.path.normcase(file_of(target)) != os.path.normcase(file_of(machine.get("") or "")):
                c.add("COM objects", f"Your account overrides a Windows component: {clsid}", WARN,
                      ["A per-user entry replaces the machine's own registration, so programs that use this "
                       "component (often Explorer) load this file instead. It's a favourite way for malware to "
                       "start without administrator rights.",
                       f"Machine's file: {machine.get('') or '?'}"],
                      "HKCU", path, "", target, file=file_of(target))


def uac_bypasses(c: Check) -> None:
    for path, what in UAC_BYPASS_KEYS.items():
        values = c.reg.values("HKCU", path)
        if values is None:
            continue
        command = values.get("") or values.get("DelegateExecute") or ""
        c.watch("UAC bypass", "HKCU", path, "", command)
        c.add("Hijacks", f"Administrator-prompt bypass set up ({what})", WARN,
              ["Windows trusts this command to run with administrator rights without asking. Malware writes it to "
               "get those rights silently. Nothing legitimate needs it."],
              "HKCU", path, "", command, file=file_of(command) if command else None)
    for ext in (".exe", ".scr", ".bat", ".cmd", ".com", ".lnk"):
        values = c.reg.values("HKCU", rf"Software\Classes\{ext}")
        if values and values.get(""):
            c.watch("File types", "HKCU", rf"Software\Classes\{ext}", "", values.get(""))
            c.add("Hijacks", f"How Windows opens {ext} files was changed for your account", WARN,
                  [f"{ext} files now open as \"{values.get('')}\" instead of the Windows default. Malware does this to "
                   "run itself every time you start a program."], "HKCU", rf"Software\Classes\{ext}", "", values.get(""))


# --- Other ways to start --------------------------------------------------------------------------------

def startup_spots(c: Check) -> None:
    for hive in ("HKCU", "HKLM"):
        path = r"Software\Microsoft\Command Processor"
        autorun = (c.reg.values(hive, path) or {}).get("AutoRun")
        if autorun:
            c.watch("Command Processor", hive, path, "AutoRun", autorun)
            odd = _odd_location(autorun)
            c.add("Startup hooks", "Command Processor AutoRun runs something with every command prompt",
                  WARN if odd else NOTE, [odd or "Developer tools (Anaconda, Clink) set this. Worth knowing if you "
                                                 "don't use them."], hive, path, "AutoRun", autorun)

    for base in (r"Software\Microsoft\Active Setup\Installed Components",
                 r"Software\WOW6432Node\Microsoft\Active Setup\Installed Components"):
        for comp in c.reg.subkeys("HKLM", base):
            values = c.reg.values("HKLM", rf"{base}\{comp}") or {}
            stub = values.get("StubPath")
            if not stub:
                continue
            c.watch("Active Setup", "HKLM", rf"{base}\{comp}", "StubPath", stub)
            odd = _odd_location(stub)
            if odd:
                c.add("Startup hooks", f"Active Setup runs something at sign-in: {values.get('') or comp}", WARN,
                      [odd, "Active Setup runs its command once for every account that signs in."],
                      "HKLM", rf"{base}\{comp}", "StubPath", stub, file=file_of(stub))

    for base in (rf"{WINDOWS_NT}\Windows", r"Software\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows"):
        values = c.reg.values("HKLM", base) or {}
        dlls = (values.get("AppInit_DLLs") or "").strip()
        c.watch("AppInit DLLs", "HKLM", base, "AppInit_DLLs", dlls)
        if dlls and values.get("LoadAppInit_DLLs") == 1:
            c.add("Startup hooks", "AppInit DLLs load into every program", WARN,
                  ["These DLLs are loaded into every program that shows a window. An old trick, still used by "
                   "adware and spyware."], "HKLM", base, "AppInit_DLLs", dlls, file=file_of(dlls.split(",")[0]))

    path = r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls"
    for name, value in (c.reg.values("HKLM", path) or {}).items():
        c.watch("AppCert DLLs", "HKLM", path, name, value)
        c.add("Startup hooks", f"AppCert DLL loads into programs: {name}", WARN,
              ["Loaded into every program that starts another program. Windows doesn't use this itself."],
              "HKLM", path, name, value, file=file_of(value))

    spe = rf"{WINDOWS_NT}\SilentProcessExit"
    for program in c.reg.subkeys("HKLM", spe):
        monitor = (c.reg.values("HKLM", rf"{spe}\{program}") or {}).get("MonitorProcess")
        if monitor:
            c.watch("Silent process exit", "HKLM", rf"{spe}\{program}", "MonitorProcess", monitor)
            c.add("Startup hooks", f"A program starts whenever {program} closes", WARN,
                  ["\"Silent process exit\" monitoring starts this command each time that program exits: a stealthy "
                   "way to stay running."], "HKLM", rf"{spe}\{program}", "MonitorProcess", monitor,
                  file=file_of(monitor))

    debugger = (c.reg.values("HKLM", rf"{WINDOWS_NT}\AeDebug") or {}).get("Debugger")
    if debugger:
        c.watch("Crash debugger", "HKLM", rf"{WINDOWS_NT}\AeDebug", "Debugger", debugger)
        odd = _odd_location(debugger)
        if odd:
            c.add("Startup hooks", "The crash debugger runs something unusual", WARN,
                  [odd, "Windows starts the crash debugger whenever a program crashes."],
                  "HKLM", rf"{WINDOWS_NT}\AeDebug", "Debugger", debugger, file=file_of(debugger))

    for name, dll in (c.reg.values("HKLM", r"Software\Microsoft\NetSh") or {}).items():
        c.watch("Netsh helpers", "HKLM", r"Software\Microsoft\NetSh", name, dll)
        if str(dll).lower() not in KNOWN_NETSH:
            path = file_of(dll)
            c.add("Startup hooks", f"Extra netsh helper DLL: {dll}", WARN if not SYSTEM_FOLDERS.match(path) else NOTE,
                  ["netsh loads its helper DLLs every time it runs, and Windows runs netsh often. Malware registers "
                   "its own here."], "HKLM", r"Software\Microsoft\NetSh", name, dll, file=path)

    monitors = r"SYSTEM\CurrentControlSet\Control\Print\Monitors"
    for monitor in c.reg.subkeys("HKLM", monitors):
        driver = (c.reg.values("HKLM", rf"{monitors}\{monitor}") or {}).get("Driver")
        if driver:
            c.watch("Print monitors", "HKLM", rf"{monitors}\{monitor}", "Driver", driver)
            path = file_of(driver)
            if not SYSTEM_FOLDERS.match(path) or not Path(path).exists():
                c.add("Startup hooks", f"Print monitor loads a DLL from outside Windows: {monitor}", WARN,
                      ["The print spooler loads print monitors as SYSTEM at every start. They belong in "
                       "System32."], "HKLM", rf"{monitors}\{monitor}", "Driver", driver, file=path)

    providers = r"SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders"
    for provider in c.reg.subkeys("HKLM", providers):
        dll = (c.reg.values("HKLM", rf"{providers}\{provider}") or {}).get("DllName")
        if dll:
            c.watch("Time providers", "HKLM", rf"{providers}\{provider}", "DllName", dll)
            path = file_of(dll)
            if not SYSTEM_FOLDERS.match(path):
                c.add("Startup hooks", f"Time provider loads a DLL from outside Windows: {provider}", WARN,
                      ["The Windows Time service loads it as SYSTEM. Its own providers are in System32."],
                      "HKLM", rf"{providers}\{provider}", "DllName", dll, file=path)

    saver = (c.reg.values("HKCU", r"Control Panel\Desktop") or {}).get("SCRNSAVE.EXE")
    if saver:
        c.watch("Screensaver", "HKCU", r"Control Panel\Desktop", "SCRNSAVE.EXE", saver)
        path = file_of(saver)
        if not SYSTEM_FOLDERS.match(path):
            c.add("Startup hooks", f"Screensaver is a program outside Windows: {Path(path).name}", WARN,
                  ["Screensavers are programs. One outside System32 is a known way to run something whenever the PC "
                   "is idle."], "HKCU", r"Control Panel\Desktop", "SCRNSAVE.EXE", saver, file=path)

    for hive, path in (("HKCU", "Environment"),
                       ("HKLM", r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment")):
        env = {k.upper(): v for k, v in (c.reg.values(hive, path) or {}).items()}
        script = env.get("USERINITMPRLOGONSCRIPT")
        if script:
            c.watch("Logon script", hive, path, "UserInitMprLogonScript", script)
            c.add("Startup hooks", "A logon script runs at every sign-in", WARN,
                  ["Set through an environment variable, it never shows up as a startup item. Home PCs don't use "
                   "logon scripts."], hive, path, "UserInitMprLogonScript", script, file=file_of(script))
        profiler = env.get("COR_PROFILER_PATH") or env.get("COR_PROFILER")
        if env.get("COR_ENABLE_PROFILING") in ("1", 1) and profiler:
            c.watch(".NET profiler", hive, path, "COR_PROFILER", profiler)
            odd = _odd_location(profiler)
            c.add("Startup hooks", "A .NET profiler loads into every .NET program", WARN if odd or hive == "HKCU" else NOTE,
                  [odd or "Performance and debugging tools set this. Malware uses it to load into every .NET program "
                          "(PowerShell included)."], hive, path, "COR_PROFILER", profiler, file=file_of(profiler))

    perf = c.reg.values("HKCU", r"Software\Microsoft\Office test\Special\Perf")
    if perf is not None:
        c.watch("Office test DLL", "HKCU", r"Software\Microsoft\Office test\Special\Perf", "", perf.get(""))
        c.add("Startup hooks", "Office loads a hidden test DLL", WARN,
              ["The \"Office test\" key makes Word, Excel and the rest load this DLL every time they start. Only "
               "Microsoft's own testing uses it; attackers use it to start with Office."],
              "HKCU", r"Software\Microsoft\Office test\Special\Perf", "", perf.get(""), file=file_of(perf.get("") or ""))


def office_startup_folders(folders: list[Path] | None = None) -> list[Finding]:
    """Files in Word's and Excel's startup folders: they load (macros included) whenever Office starts."""
    if folders is None:
        appdata = Path(os.environ.get("APPDATA", Path.home()))
        folders = [appdata / "Microsoft" / "Word" / "STARTUP", appdata / "Microsoft" / "Excel" / "XLSTART"]
    found = []
    for folder in folders:
        try:
            files = [f for f in folder.iterdir() if f.is_file()]
        except OSError:
            continue
        for f in files:
            macro = f.suffix.lower() in (".dotm", ".xlsm", ".xlam", ".xla", ".wll", ".xll", ".dot", ".xlsb")
            found.append(Finding("Office", f"Loads whenever Office starts: {f.name}", WARN if macro else NOTE,
                                 [f"It's in {folder}, so Office opens it automatically" +
                                  (", macros included. Attackers drop macro files here to run every time you open "
                                   "Office." if macro else "."), "Fine if you added it (a personal macro workbook, "
                                                                  "an add-in you use)."],
                                 key=f"office:startup:{str(f).lower()}", data={"path": str(f)}))
    return found


# --- Passwords --------------------------------------------------------------------------------------------

def password_settings(c: Check) -> None:
    lsa = c.reg.values("HKLM", LSA) or {}
    for name in ("Authentication Packages", "Security Packages", "Notification Packages"):
        packages = lsa.get(name) or []
        packages = packages if isinstance(packages, list) else [packages]
        c.watch("LSA", "HKLM", LSA, name, packages)
        unknown = [p for p in packages if str(p).strip().strip('"').lower() not in KNOWN_LSA]
        for p in unknown:
            c.add("Passwords", f"Unknown {name.lower().removesuffix('s')}: {p}", WARN,
                  ["Windows loads it into LSA, the part that handles every password and sign-in. "
                   + ("Password filters see every new password in plain text; " if name == "Notification Packages"
                      else "") + "malware registers itself here to steal credentials. Some company security tools "
                                 "do too."], "HKLM", LSA, name, packages, file=file_of(f"{p}.dll"),
                  key=f"reg:lsa:{name.lower()}:{str(p).lower()}")
    ppl = lsa.get("RunAsPPL")
    c.watch("LSA", "HKLM", LSA, "RunAsPPL", ppl)
    if ppl in (1, 2):
        c.found.append(Finding("Passwords", "LSA protection is on", OK, key="reg:lsa:ppl:ok"))
    else:
        c.add("Passwords", "LSA protection is off", NOTE,
              ["It stops other programs from reading passwords out of memory. Turn it on under Windows Security > "
               "Device security > Core isolation > Local Security Authority protection."], "HKLM", LSA, "RunAsPPL", ppl,
              key="reg:lsa:ppl:off")
        c.found[-1].fix, c.found[-1].fix_label = "open", "Open Core isolation"
        c.found[-1].data["url"] = "windowsdefender://coreisolation"
    wdigest = r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
    use = (c.reg.values("HKLM", wdigest) or {}).get("UseLogonCredential")
    c.watch("WDigest", "HKLM", wdigest, "UseLogonCredential", use)
    if use == 1:
        c.add("Passwords", "Windows keeps your password readable in memory (WDigest)", WARN,
              ["With this on, tools like Mimikatz can read your password in plain text. Windows has it off since "
               "8.1; attackers switch it on. Set UseLogonCredential to 0 (needs an administrator)."],
              "HKLM", wdigest, "UseLogonCredential", use)


# --- Settings attackers loosen ---------------------------------------------------------------------------------

def office_settings(c: Check) -> None:
    versions = [v for v in c.reg.subkeys("HKCU", r"Software\Microsoft\Office") if re.fullmatch(r"\d+\.0", v)]
    for version in versions:
        for app in OFFICE_APPS:
            for base, by in ((rf"Software\Microsoft\Office\{version}\{app}\Security", "you"),
                             (rf"Software\Policies\Microsoft\Office\{version}\{app}\Security", "a policy")):
                sec = c.reg.values("HKCU", base)
                if sec is None:
                    continue
                setting = "Level" if app == "Outlook" else "VBAWarnings"  # 1 = run all macros, in both
                c.watch("Office", "HKCU", base, setting, sec.get(setting))
                if sec.get(setting) == 1:
                    c.add("Office", f"{app}: all macros run without asking", WARN,
                          [f"Set by {by}. Any document or email with macros can run code the moment it's opened. "
                           f"Set it back in {app} > File > Options > Trust Center > Macro Settings."],
                          "HKCU", base, setting, 1)
                if sec.get("blockcontentexecutionfrominternet") == 0 and by == "a policy":
                    c.add("Office", f"{app}: macros from the internet are allowed by policy", WARN,
                          ["Office normally blocks macros in files from the internet and email."],
                          "HKCU", base, "blockcontentexecutionfrominternet", 0)
                pv = c.reg.values("HKCU", rf"{base}\ProtectedView") or {}
                for name, what in (("DisableInternetFilesInPV", "files from the internet"),
                                   ("DisableAttachementsInPV", "email attachments"),
                                   ("DisableUnsafeLocationsInPV", "files in unsafe folders")):
                    c.watch("Office", "HKCU", rf"{base}\ProtectedView", name, pv.get(name))
                    if pv.get(name) == 1:
                        c.add("Office", f"{app}: Protected View is off for {what}", WARN if "unsafe" not in name else NOTE,
                              [f"Protected View opens {what} read-only, with macros and editing off, until you choose "
                               "to trust them. Turn it back on in Trust Center > Protected View."],
                              "HKCU", rf"{base}\ProtectedView", name, 1)
                trusted = rf"{base}\Trusted Locations"
                network = (c.reg.values("HKCU", trusted) or {}).get("AllowNetworkLocations")
                for loc in c.reg.subkeys("HKCU", trusted):
                    path = (c.reg.values("HKCU", rf"{trusted}\{loc}") or {}).get("Path")
                    if not path:
                        continue
                    c.watch("Office", "HKCU", rf"{trusted}\{loc}", "Path", path)
                    expanded = os.path.expandvars(str(path))
                    if RISKY_TRUSTED.search(expanded) or (network == 1 and expanded.startswith("\\\\")):
                        c.add("Office", f"{app} trusts everything in {expanded}", WARN,
                              ["Documents in a trusted location run their macros without asking. Downloads, the "
                               "Desktop, Documents and network shares are where unsafe files arrive."],
                              "HKCU", rf"{trusted}\{loc}", "Path", path)


def uac_and_rdp(c: Check) -> None:
    system = r"Software\Microsoft\Windows\CurrentVersion\Policies\System"
    uac = c.reg.values("HKLM", system) or {}
    for name in ("EnableLUA", "ConsentPromptBehaviorAdmin", "PromptOnSecureDesktop"):
        c.watch("UAC", "HKLM", system, name, uac.get(name))
    fix = dict(fix="open", fix_label="Open UAC settings", url="UserAccountControlSettings.exe")
    if uac.get("EnableLUA") == 0:
        c.add("UAC", "User Account Control is off", WARN,
              ["Every program runs with full administrator rights and nothing asks first. Turn UAC back on in "
               "Control Panel > User Accounts."], "HKLM", system, "EnableLUA", 0)
    elif uac.get("ConsentPromptBehaviorAdmin") == 0:
        c.add("UAC", "Programs get administrator rights without asking", WARN,
              ["UAC is set to \"Never notify\" for administrators. Malware gets full control silently."],
              "HKLM", system, "ConsentPromptBehaviorAdmin", 0)
    elif uac.get("PromptOnSecureDesktop") == 0:
        c.add("UAC", "Permission prompts don't use the secure desktop", NOTE,
              ["Without the dimmed secure desktop, another program could click \"Yes\" on the prompt for you."],
              "HKLM", system, "PromptOnSecureDesktop", 0)
    else:
        c.found.append(Finding("UAC", "User Account Control asks before giving administrator rights", OK, key="reg:uac:ok"))
    for f in c.found:
        if f.area == "UAC" and f.level != OK and not f.fix:
            f.fix, f.fix_label = fix["fix"], fix["fix_label"]
            f.data["url"] = fix["url"]

    ts = r"SYSTEM\CurrentControlSet\Control\Terminal Server"
    policy = (c.reg.values("HKLM", r"Software\Policies\Microsoft\Windows NT\Terminal Services") or {}).get(
        "fDenyTSConnections")
    deny = policy if policy is not None else (c.reg.values("HKLM", ts) or {}).get("fDenyTSConnections")
    nla = (c.reg.values("HKLM", rf"{ts}\WinStations\RDP-Tcp") or {}).get("UserAuthentication")
    c.watch("Remote Desktop", "HKLM", ts, "fDenyTSConnections", deny)
    c.watch("Remote Desktop", "HKLM", rf"{ts}\WinStations\RDP-Tcp", "UserAuthentication", nla)
    if deny == 0:
        c.add("Remote Desktop", "Remote Desktop is on" + (" without Network Level Authentication" if nla == 0 else ""),
              WARN if nla == 0 else NOTE,
              ["People on your network (or the internet, if your router forwards it) can try to sign in to this PC. "
               + ("Without Network Level Authentication they reach the sign-in screen without a password, which "
                  "has had serious security holes. " if nla == 0 else "")
               + "Turn it off in Settings > System > Remote Desktop if nobody uses it."],
              "HKLM", ts, "fDenyTSConnections", 0)
        c.found[-1].fix, c.found[-1].fix_label = "open", "Open Remote Desktop settings"
        c.found[-1].data["url"] = "ms-settings:remotedesktop"
    else:
        c.found.append(Finding("Remote Desktop", "Remote Desktop is off", OK, key="reg:rdp:off"))


# --- Running it all ------------------------------------------------------------------------------------------

def check_registry(reg: Registry | None = None) -> tuple[list[Finding], list[Spot]]:
    c = Check(reg or Registry())
    for part in (com_hijacks, uac_bypasses, startup_spots, password_settings, office_settings, uac_and_rdp):
        try:
            part(c)
        except Exception as exc:  # one broken part mustn't hide the others
            log.exception("Registry check %s failed", part.__name__)
            c.found.append(Finding("Registry", f"A check failed: {part.__name__}", NOTE, [str(exc)]))
    c.found += office_startup_folders() if reg is None else []
    hooks = sum(1 for f in c.found if f.area in ("Startup hooks", "Hijacks", "COM objects"))
    if not hooks:
        c.found.append(Finding("Registry", f"Nothing suspicious in the {len(c.spots)} registry values Atlas watches", OK, ["COM hijacks, administrator-prompt bypasses, Command Processor "
                                                  "AutoRun, Active Setup, AppInit/AppCert DLLs, silent process exit, "
                                                  "the crash debugger, netsh helpers, print monitors, time providers, "
                                                  "the screensaver, logon scripts, the .NET profiler and Office's "
                                                  "test DLL."], key="reg:hooks:ok"))
    return c.found, c.spots


# --- Change watch -----------------------------------------------------------------------------------------------

KEEP_CHANGES = timedelta(days=7)


def snapshot(spots: list[Spot]) -> dict[str, str]:
    return {s.id: _text(s.value) for s in spots if s.value not in (None, "", [])}


def diff(previous: dict[str, str] | None, spots: list[Spot], now: datetime) -> list[dict]:
    """Watched values that appeared or changed since the last snapshot (none on the first look)."""
    if previous is None:
        return []
    by_key = {s.id: s for s in spots}
    return [{"key": key, "now": value, "before": previous.get(key), "area": by_key[key].area,
             "location": by_key[key].location, "when": now.isoformat(timespec="minutes")}
            for key, value in snapshot(spots).items() if previous.get(key) != value]


def change_finding(change: dict) -> Finding:
    quiet = change["area"] in ("Office", "Remote Desktop", "UAC")
    before = change.get("before")
    return Finding("Registry changes", f"{change['area']}: {'changed' if before is not None else 'new entry'} at "
                   f"{change['location'][:90]}", NOTE if quiet else WARN,
                   [f"Now: {change['now'][:300]}",
                    f"Before: {before[:300]}" if before is not None else "It wasn't there at the check before.",
                    f"Noticed {change['when'].replace('T', ' ')}",
                    "Changes here happen when you install or update software, and when malware sets itself up. "
                    "Worth a look if you didn't install anything around then."],
                   key=f"reg:change:{change['key'].lower()}:{_digest(change['now'])}",
                   data={"registry": change["location"]})


def watch_changes(store, spots: list[Spot], now: datetime | None = None) -> list[Finding]:
    """Compare with the last check, remember the new values, and list the changes from the past week."""
    now = now or datetime.now()
    saved = store.cached_extra("registry", "snapshot", 24 * 365 * 10) or {}
    recent = [c for c in saved.get("changes", [])
              if now - datetime.fromisoformat(c["when"]) < KEEP_CHANGES] + diff(saved.get("values"), spots, now)
    store.cache_extra("registry", "snapshot", {"values": snapshot(spots), "changes": recent[-200:]})
    latest = {c["key"]: c for c in recent}  # the newest change per value
    return [change_finding(c) for c in latest.values()]
