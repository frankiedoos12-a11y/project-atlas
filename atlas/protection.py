"""System checks in one place: Defender (atlas.defender), hijacks (atlas.hijack), software and
Windows updates (atlas.softwareupdates) and disk health (atlas.health), plus the Fix buttons.

Atlas only changes things after you press a button and confirm:
- your own proxy setting and browser policies set in your own account (with a backup first)
- Defender's extra attack protection, through Windows' own administrator prompt (and back off again)
- a program update, run by winget in a window you can watch
Everything else either opens the right page in Windows Security, Settings or the browser, or (for
the hosts file) opens it in Notepad as administrator so you can edit it yourself.
"""

from __future__ import annotations

import ctypes
import json
import logging
import os
import subprocess
import sys
import time
from pathlib import Path

from atlas import config
from atlas.browsers import SETTINGS_PAGES
from atlas import defender, health, remoteaccess, softwareupdates
from atlas.defender import check_defender
from atlas.findings import NOTE, OK, WARN, Finding
from atlas.hijack import HOSTS, INTERNET_SETTINGS, check_hijacks

log = logging.getLogger(__name__)

NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
ORDER = {WARN: 0, NOTE: 1, OK: 2}


def check_system(scanner=None) -> list[Finding]:
    """Every system check, worst first. `scanner` (optional) lets sites and addresses be looked up."""
    lookup = scanner.lookup if scanner is not None and scanner.vt is not None else None
    threshold = scanner.settings.malicious_threshold if scanner is not None else 3
    settings = config.Settings.load()  # fresh: "It's mine" may have changed the trusted tools since the tray started
    found = check_defender() + check_hijacks(lookup, threshold)
    for part in (lambda: softwareupdates.check_updates(scanner.store if scanner is not None else None),
                 health.check_disks,
                 lambda: remoteaccess.check_remote_access(settings.trusted_remote_tools,
                                                          [Path(f) for f in settings.watch_folders])):
        try:
            found += part()
        except Exception as exc:  # one broken check mustn't hide the others
            log.exception("System check failed")
            found.append(Finding("Atlas", "A check failed", NOTE, [str(exc)], key="system:failed"))
    return sorted(found, key=lambda f: ORDER.get(f.level, 3))


def _backup(name: str, data: dict) -> Path:
    folder = config.data_dir() / "backups"
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{name}-{time.strftime('%Y%m%d-%H%M%S')}.json"
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    return path


def describe_fix(f: Finding) -> str:
    """What pressing Fix will do, for the confirmation question."""
    return {
        "proxy-off": "Turn off the proxy setting in your account? Your current settings are saved to a backup file "
                     "first. If a VPN or antivirus you use needs it, it will turn it back on.",
        "remove-policy": f"Remove the \"{f.data.get('name')}\" policy from your account, so you can change "
                         "the setting yourself again? A backup is saved first. Restart the browser afterwards.",
        "edit-hosts": "Open the hosts file in Notepad as administrator? Windows will ask for permission. Delete the "
                      "lines Atlas pointed out, then save.",
        "winget-upgrade-all": f"Update {len(f.data.get('ids', []))} programs? winget opens in a window and updates "
                              "them one after another, so you can watch. Close them first.",
        "end-remote": f"End {f.data.get('tool')} now? Anyone connected through it is cut off. If a stranger was "
                      "connected, also change the passwords of anything you logged in to while they were.",
        "trust-remote": f"Mark {f.data.get('tool')} as yours? Atlas then stops warning about it, including when it "
                        "starts. Only do this if you or someone you trust (family, your IT person) use it.",
        "untrust-remote": f"Warn about {f.data.get('tool')} again?",
        "winget-upgrade": f"Update {f.data.get('name')}? winget opens in a window so you can watch. Close the program "
                          "first. If winget asks you to accept its source agreement, that's your call.",
        "defender-harden": "Turn on Defender's extra attack protection? Windows asks for administrator permission, then "
                           f"switches on {len(defender.ASR_RULES)} attack surface reduction rules and network protection. "
                           "If one ever gets in the way, Atlas can turn them off again. Press Check now afterwards.",
        "defender-undo": "Turn Defender's extra attack protection off again? Windows asks for administrator "
                         "permission. Press Check now afterwards.",
    }.get(f.fix or "", "")


def apply_fix(f: Finding) -> str:
    """Do what the finding's Fix button says. Returns a message for the user."""
    if f.fix == "open":
        os.startfile(f.data["url"])
        return ""
    if f.fix == "browser-settings":
        scheme = SETTINGS_PAGES.get(f.data["browser"], "chrome")
        args = ["cmd", "/c", "start", "", f.data["exe"].removesuffix(".exe")]
        if f.data.get("profile"):
            args.append(f"--profile-directory={f.data['profile']}")
        subprocess.Popen(args + [f"{scheme}://settings/{f.data.get('page', 'onStartup')}"], creationflags=NO_WINDOW)
        return ""
    if f.fix == "proxy-off":
        return _proxy_off(f)
    if f.fix == "remove-policy":
        return _remove_policy(f)
    if f.fix == "winget-upgrade":
        subprocess.Popen(softwareupdates.upgrade_command(f.data["id"]), creationflags=subprocess.CREATE_NEW_CONSOLE)
        softwareupdates.ask_again()
        return "winget is updating it in its own window. Press Check now when it's done."
    if f.fix == "winget-upgrade-all":
        subprocess.Popen(softwareupdates.upgrade_all_command(f.data["ids"]),
                         creationflags=subprocess.CREATE_NEW_CONSOLE)
        softwareupdates.ask_again()
        return "winget is updating them in its own window. Press Check now when it's done."
    if f.fix == "end-remote":
        from atlas.processes import end_processes

        problems = end_processes(set(f.data["pids"]))
        log.warning("Ended remote-access program %s (%s)", f.data["tool"], problems or "ok")
        ended = "\n".join(problems) if problems else f"{f.data['tool']} has been ended."
        return ended + "\n\nIf it starts again by itself, uninstall it in the Installed tab."
    if f.fix in ("trust-remote", "untrust-remote"):
        settings = config.Settings.load()
        trusted = [t for t in settings.trusted_remote_tools if t.lower() != f.data["tool"].lower()]
        if f.fix == "trust-remote":
            trusted.append(f.data["tool"])
        settings.trusted_remote_tools = trusted
        settings.save()
        return "Saved. Press Check now to see the change."
    if f.fix in ("defender-harden", "defender-undo"):
        script = defender.HARDEN_SCRIPT if f.fix == "defender-harden" else defender.UNDO_SCRIPT
        _run_as_admin("powershell.exe", f'-NoProfile -Command "{script}"')
        log.info("Asked Windows to run %s as administrator", f.fix)
        return "Done once you said yes to Windows' prompt. Press Check now to see the result."
    if f.fix == "edit-hosts":
        _run_as_admin("notepad.exe", str(HOSTS), show=1)
        return ""
    raise ValueError(f"Nothing to fix for {f.title}")


def start_defender_scan(offline: bool) -> None:
    """Defender's full scan, or its offline scan (restarts the PC). Windows asks for administrator permission."""
    from atlas.fullscan import DEFENDER_FULL, DEFENDER_OFFLINE

    _run_as_admin("powershell.exe", f'-NoProfile -Command "{DEFENDER_OFFLINE if offline else DEFENDER_FULL}"')
    log.info("Asked Windows to start Defender's %s scan", "offline" if offline else "full")


def _run_as_admin(program: str, args: str, show: int = 0) -> None:
    result = ctypes.windll.shell32.ShellExecuteW(None, "runas", program, args, None, show)
    if result <= 32:
        raise OSError(f"{program} wasn't started (permission was refused?)")


def _proxy_off(f: Finding) -> str:
    import winreg

    backup = _backup("proxy", f.data)
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS, 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
        try:
            winreg.DeleteValue(key, "AutoConfigURL")
        except FileNotFoundError:
            pass
    _tell_windows_internet_settings_changed()
    log.info("Proxy turned off (backup %s)", backup)
    return f"The proxy is off. Backup of the old settings: {backup}"


def _tell_windows_internet_settings_changed() -> None:
    if sys.platform != "win32":
        return
    wininet = ctypes.windll.wininet
    wininet.InternetSetOptionW(None, 39, None, 0)  # INTERNET_OPTION_SETTINGS_CHANGED
    wininet.InternetSetOptionW(None, 37, None, 0)  # INTERNET_OPTION_REFRESH


def _remove_policy(f: Finding) -> str:
    import winreg

    backup = _backup("browser-policy", f.data)
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, f.data["key"], 0, winreg.KEY_SET_VALUE) as key:
        winreg.DeleteValue(key, f.data["name"])
    log.info("Removed browser policy %s\\%s (backup %s)", f.data["key"], f.data["name"], backup)
    return f"Policy removed. Restart the browser, then set it the way you want. Backup: {backup}"
