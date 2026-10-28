"""Registry check: every check against a fake registry, plus the change watch."""

from datetime import datetime, timedelta

import pytest

from atlas import registry
from atlas.findings import NOTE, OK, WARN

LSA_DEFAULT = {"Authentication Packages": ["msv1_0"], "Security Packages": ['""'],
               "Notification Packages": ["scecli"], "RunAsPPL": 2}
UAC_DEFAULT = {"EnableLUA": 1, "ConsentPromptBehaviorAdmin": 5, "PromptOnSecureDesktop": 1}
TS = r"SYSTEM\CurrentControlSet\Control\Terminal Server"


class FakeRegistry(registry.Registry):
    """{(hive, path): {name: value}}; subkeys come from the paths underneath."""

    def __init__(self, keys: dict | None = None, clean: bool = True):
        self.keys = {}
        if clean:
            self.keys.update({("HKLM", registry.LSA): dict(LSA_DEFAULT),
                              ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Policies\System"): dict(UAC_DEFAULT),
                              ("HKLM", TS): {"fDenyTSConnections": 1},
                              ("HKLM", rf"{TS}\WinStations\RDP-Tcp"): {"UserAuthentication": 1}})
        self.keys.update({(h, p.lower()): v for (h, p), v in (keys or {}).items()})
        self.keys = {(h, p.lower()): v for (h, p), v in self.keys.items()}

    def values(self, hive, path):
        v = self.keys.get((hive, path.lower()))
        return dict(v) if v is not None else None

    def subkeys(self, hive, path):
        prefix = path.lower() + "\\"
        names = {p[len(prefix):].split("\\")[0] for h, p in self.keys if h == hive and p.startswith(prefix)}
        return sorted(names)

    def changed(self, hive, path):
        return datetime(2026, 10, 1, 9, 30) if (hive, path.lower()) in self.keys else None


def run(keys, clean=True):
    found, spots = registry.check_registry(FakeRegistry(keys, clean))
    return found, spots


def titles(found, level=None):
    return [f.title for f in found if level is None or f.level == level]


def test_clean_registry_is_all_ok():
    found, spots = run({})
    assert all(f.level == OK for f in found)
    assert "Nothing suspicious in the" in " ".join(titles(found))
    assert spots  # LSA, UAC, RDP values are watched even when fine


def test_com_override_of_windows_component():
    clsid = "{BCDE0395-E52F-467C-8E3D-C4579291692E}"
    found, _ = run({
        ("HKLM", rf"Software\Classes\CLSID\{clsid}\InprocServer32"): {"": r"%SystemRoot%\System32\MMDevApi.dll"},
        ("HKCU", rf"Software\Classes\CLSID\{clsid}\InprocServer32"): {"": r"C:\Users\me\AppData\Roaming\x\evil.dll"},
    })
    hit = next(f for f in found if "overrides a Windows component" in f.title)
    assert hit.level == WARN and hit.data["path"].endswith("evil.dll")
    assert any("Key last changed 2026-10-01 09:30" in d for d in hit.details)


def test_com_same_file_or_user_only_object_is_fine():
    clsid = "{11111111-2222-3333-4444-555555555555}"
    found, _ = run({
        ("HKLM", rf"Software\Classes\CLSID\{clsid}\InprocServer32"): {"": r"C:\Windows\System32\shell32.dll"},
        ("HKCU", rf"Software\Classes\CLSID\{clsid}\InprocServer32"): {"": r"C:\Windows\System32\shell32.dll"},
        ("HKCU", r"Software\Classes\CLSID\{99999999-0000-0000-0000-000000000000}\InprocServer32"):
            {"": r"C:\Users\me\AppData\Local\Microsoft\OneDrive\FileSyncShell64.dll"},
    })
    assert not titles(found, WARN)


def test_com_scriptlet():
    clsid = "{AAAAAAAA-0000-0000-0000-000000000000}"
    found, _ = run({("HKCU", rf"Software\Classes\CLSID\{clsid}\InprocServer32"): {"": "scrobj.dll"},
                    ("HKCU", rf"Software\Classes\CLSID\{clsid}\ScriptletURL"): {"": "https://evil.example/x.sct"}})
    assert any("script from a web address" in t for t in titles(found, WARN))


@pytest.mark.parametrize("path", [r"Software\Classes\ms-settings\shell\open\command",
                                  r"Software\Classes\mscfile\shell\open\command",
                                  r"Software\Classes\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\Shell\open\command"])
def test_uac_bypass_keys(path):
    found, _ = run({("HKCU", path): {"": r"C:\Users\me\AppData\Local\Temp\x.exe", "DelegateExecute": ""}})
    hit = next(f for f in found if "prompt bypass" in f.title)
    assert hit.level == WARN and hit.data["path"].endswith("x.exe")


def test_exe_file_type_hijack():
    found, _ = run({("HKCU", r"Software\Classes\.exe"): {"": "evilfile"}})
    assert any(".exe files" in t for t in titles(found, WARN))


def test_command_processor_autorun():
    found, _ = run({("HKCU", r"Software\Microsoft\Command Processor"): {"AutoRun": "powershell -w hidden -enc AAA"}})
    assert any("AutoRun" in t for t in titles(found, WARN))
    found, _ = run({("HKCU", r"Software\Microsoft\Command Processor"):
                    {"AutoRun": r'"C:\Program Files\clink\clink.exe" inject'}})
    assert any("AutoRun" in t for t in titles(found, NOTE))


def test_active_setup_only_flags_odd_stubs():
    base = r"Software\Microsoft\Active Setup\Installed Components"
    found, _ = run({
        ("HKLM", rf"{base}\{{A}}"): {"": "Windows Mail", "StubPath": "/UserInstall"},
        ("HKLM", rf"{base}\{{B}}"): {"StubPath": r"C:\Windows\System32\Rundll32.exe C:\Windows\System32\mscories.dll,Install"},
        ("HKLM", rf"{base}\{{C}}"): {"": "Updater", "StubPath": r"C:\Users\Public\up.exe"},
        ("HKLM", rf"{base}\{{D}}"): {"StubPath": r"rundll32.exe C:\Users\me\AppData\Local\a.dll,Run"},
    })
    warns = titles(found, WARN)
    assert any("Updater" in t for t in warns) and any("{d}" in t.lower() for t in warns)
    assert len([t for t in warns if "Active Setup" in t]) == 2


def test_appinit_needs_load_flag():
    path = rf"{registry.WINDOWS_NT}\Windows"
    found, _ = run({("HKLM", path): {"AppInit_DLLs": r"C:\x\hook.dll", "LoadAppInit_DLLs": 0}})
    assert not titles(found, WARN)
    found, _ = run({("HKLM", path): {"AppInit_DLLs": r"C:\x\hook.dll", "LoadAppInit_DLLs": 1}})
    assert any("AppInit" in t for t in titles(found, WARN))


def test_appcert_silent_exit_and_aedebug():
    found, _ = run({
        ("HKLM", r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls"): {"x": r"C:\x\cert.dll"},
        ("HKLM", rf"{registry.WINDOWS_NT}\SilentProcessExit\notepad.exe"): {"MonitorProcess": r"C:\x\m.exe"},
        ("HKLM", rf"{registry.WINDOWS_NT}\AeDebug"): {"Debugger": r"C:\Users\me\AppData\dbg.exe -p %ld"},
    })
    warns = " | ".join(titles(found, WARN))
    assert "AppCert" in warns and "notepad.exe closes" in warns and "crash debugger" in warns


def test_aedebug_windows_default_is_fine():
    found, _ = run({("HKLM", rf"{registry.WINDOWS_NT}\AeDebug"):
                    {"Debugger": r'"C:\Windows\system32\vsjitdebugger.exe" -p %ld -e %ld'}})
    assert not titles(found, WARN)


def test_netsh_print_monitor_time_provider():
    found, _ = run({
        ("HKLM", r"Software\Microsoft\NetSh"): {"ifmon": "ifmon.dll", "evil": r"C:\ProgramData\nh.dll"},
        ("HKLM", r"SYSTEM\CurrentControlSet\Control\Print\Monitors\Bad"): {"Driver": r"C:\Temp\pm.dll"},
        ("HKLM", r"SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient"):
            {"DllName": r"%systemroot%\system32\w32time.dll"},
        ("HKLM", r"SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\Odd"): {"DllName": r"C:\x\tp.dll"},
    })
    warns = " | ".join(titles(found, WARN))
    assert "netsh helper DLL: C:\\ProgramData\\nh.dll" in warns and "ifmon" not in warns
    assert "Print monitor" in warns and "Time provider" in warns and "NtpClient" not in warns


def test_screensaver_logon_script_and_profiler():
    found, _ = run({
        ("HKCU", r"Control Panel\Desktop"): {"SCRNSAVE.EXE": r"C:\Users\me\AppData\x.scr"},
        ("HKCU", "Environment"): {"UserInitMprLogonScript": r"C:\x\l.bat", "COR_ENABLE_PROFILING": "1",
                                  "COR_PROFILER": "{GUID}", "COR_PROFILER_PATH": r"C:\Users\me\AppData\p.dll"},
    })
    warns = " | ".join(titles(found, WARN))
    assert "Screensaver" in warns and "logon script" in warns and ".NET profiler" in warns


def test_windows_screensaver_is_fine():
    found, _ = run({("HKCU", r"Control Panel\Desktop"): {"SCRNSAVE.EXE": r"C:\Windows\system32\Bubbles.scr"}})
    assert not titles(found, WARN)


def test_office_test_dll():
    found, _ = run({("HKCU", r"Software\Microsoft\Office test\Special\Perf"): {"": r"C:\x\perf.dll"}})
    assert any("test DLL" in t for t in titles(found, WARN))


def test_lsa_unknown_packages_wdigest_and_ppl_off():
    lsa = dict(LSA_DEFAULT, **{"Notification Packages": ["scecli", "pwfilter"], "RunAsPPL": 0})
    found, _ = run({("HKLM", registry.LSA): lsa,
                    ("HKLM", r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"): {"UseLogonCredential": 1}})
    assert any("pwfilter" in t for t in titles(found, WARN))
    assert any("WDigest" in t for t in titles(found, WARN))
    ppl = next(f for f in found if f.title == "LSA protection is off")
    assert ppl.level == NOTE and ppl.fix == "open" and ppl.data["url"].startswith("windowsdefender://")


def test_office_macros_protected_view_and_trusted_locations():
    sec = r"Software\Microsoft\Office\16.0\Word\Security"
    found, _ = run({
        ("HKCU", r"Software\Microsoft\Office\16.0\Word"): {},
        ("HKCU", sec): {"VBAWarnings": 1},
        ("HKCU", rf"{sec}\ProtectedView"): {"DisableInternetFilesInPV": 1},
        ("HKCU", rf"{sec}\Trusted Locations\Location0"): {"Path": r"%APPDATA%\Microsoft\Templates"},
        ("HKCU", rf"{sec}\Trusted Locations\Location9"): {"Path": r"C:\Users\me\Downloads\\"},
        ("HKCU", r"Software\Policies\Microsoft\Office\16.0\Outlook\Security"): {"Level": 1},
    })
    warns = " | ".join(titles(found, WARN))
    assert "Word: all macros run" in warns and "Outlook: all macros run" in warns
    assert "Protected View is off for files from the internet" in warns
    assert "Downloads" in warns and "Templates" not in warns


def test_uac_off_and_never_notify():
    path = r"Software\Microsoft\Windows\CurrentVersion\Policies\System"
    found, _ = run({("HKLM", path): dict(UAC_DEFAULT, EnableLUA=0)})
    hit = next(f for f in found if f.area == "UAC")
    assert hit.level == WARN and "off" in hit.title and hit.fix == "open"
    found, _ = run({("HKLM", path): dict(UAC_DEFAULT, ConsentPromptBehaviorAdmin=0)})
    assert next(f for f in found if f.area == "UAC").level == WARN


def test_rdp_on_without_nla_and_policy_wins():
    found, _ = run({("HKLM", TS): {"fDenyTSConnections": 0}, ("HKLM", rf"{TS}\WinStations\RDP-Tcp"): {"UserAuthentication": 0}})
    hit = next(f for f in found if f.area == "Remote Desktop")
    assert hit.level == WARN and "without Network Level" in hit.title
    found, _ = run({("HKLM", TS): {"fDenyTSConnections": 0}})
    assert next(f for f in found if f.area == "Remote Desktop").level == NOTE
    found, _ = run({("HKLM", TS): {"fDenyTSConnections": 0},
                    ("HKLM", r"Software\Policies\Microsoft\Windows NT\Terminal Services"): {"fDenyTSConnections": 1}})
    assert next(f for f in found if f.area == "Remote Desktop").level == OK


def test_one_broken_part_does_not_hide_the_rest(monkeypatch):
    def boom(c):
        raise RuntimeError("nope")

    monkeypatch.setattr(registry, "com_hijacks", boom)
    found, _ = registry.check_registry(FakeRegistry({}))
    assert any("check failed" in t for t in titles(found))
    assert any(f.area == "UAC" for f in found)


def test_office_startup_folders(tmp_path):
    (tmp_path / "evil.dotm").write_text("x")
    (tmp_path / "notes.txt").write_text("x")
    found = registry.office_startup_folders([tmp_path, tmp_path / "missing"])
    levels = {f.title.split(": ")[1]: f.level for f in found}
    assert levels == {"evil.dotm": WARN, "notes.txt": NOTE}


def test_file_of_resolves_bare_dll_names():
    assert registry.file_of("ifmon.dll").lower().endswith(r"system32\ifmon.dll")
    assert registry.file_of(r'"C:\x\a.exe" /run') == r"C:\x\a.exe"


# --- Change watch -----------------------------------------------------------------------------------------

def test_change_watch_first_look_is_quiet_then_alerts_once(store):
    t0 = datetime(2026, 10, 20, 12, 0)
    _, spots = run({})
    assert registry.watch_changes(store, spots, t0) == []

    _, spots = run({("HKCU", r"Software\Microsoft\Command Processor"): {"AutoRun": r"C:\x\a.bat"}})
    changes = registry.watch_changes(store, spots, t0 + timedelta(hours=1))
    assert len(changes) == 1 and changes[0].level == WARN and "new entry" in changes[0].title
    key = changes[0].key

    # Still listed (same key, so the tray doesn't alert again) on the next check...
    again = registry.watch_changes(store, spots, t0 + timedelta(hours=2))
    assert [f.key for f in again] == [key]
    # ...and dropped after a week.
    assert registry.watch_changes(store, spots, t0 + timedelta(days=8)) == []


def test_change_watch_value_change_and_quiet_areas(store):
    t0 = datetime(2026, 10, 20, 12, 0)
    _, spots = run({})
    registry.watch_changes(store, spots, t0)
    _, spots = run({("HKLM", TS): {"fDenyTSConnections": 0}})
    changes = registry.watch_changes(store, spots, t0 + timedelta(hours=1))
    rdp = next(f for f in changes if f.area == "Registry changes" and "Remote Desktop" in f.title)
    assert rdp.level == NOTE and "changed" in rdp.title and any(d.startswith("Before: 1") for d in rdp.details)
