import json
from pathlib import Path

import pytest
from conftest import FakeVT

from atlas import autoruns, config
from atlas.autoruns import Autorun, AutorunMonitor, assess, resolve, split_command
from atlas.local_checks import Signature, sha256_file
from atlas.scanner import Verdict

MS = Signature(status="Valid", signer="Microsoft Windows")
UNSIGNED = Signature(status="NotSigned")


@pytest.fixture
def program_files(tmp_path) -> Path:
    d = tmp_path / "Program Files" / "Good App"
    d.mkdir(parents=True)
    (d / "good app.exe").write_bytes(b"MZ good")
    return d


# --- Command lines -------------------------------------------------------------

def test_split_quoted_command(program_files):
    exe = program_files / "good app.exe"
    assert split_command(f'"{exe}" --minimized') == (str(exe), "--minimized")


def test_split_unquoted_command_with_spaces(program_files):
    exe = program_files / "good app.exe"
    assert split_command(f"{exe} /background") == (str(exe), "/background")


def test_environment_variables_expand(program_files, monkeypatch):
    monkeypatch.setenv("ATLAS_TEST_DIR", str(program_files))
    entry = resolve(Autorun("Registry Run", "HKCU", "x", r'"%ATLAS_TEST_DIR%\good app.exe" -q'))
    assert entry.path == program_files / "good app.exe"


def test_script_host_resolves_to_the_script(tmp_path):
    script = tmp_path / "AppData" / "updater.vbs"
    script.parent.mkdir()
    script.write_text("WScript.Echo 1")
    entry = resolve(Autorun("Registry Run", "HKCU", "upd", f'wscript.exe //B "{script}"'))
    assert entry.host == "wscript.exe"
    assert entry.path == script


def test_rundll32_resolves_to_the_dll(tmp_path):
    dll = tmp_path / "helper.dll"
    dll.write_bytes(b"MZ")
    entry = resolve(Autorun("Registry Run", "HKCU", "h", f"rundll32.exe {dll},Start"))
    assert entry.path == dll


def test_userinit_trailing_comma():
    entry = resolve(Autorun("Winlogon", r"HKLM\Winlogon", "Userinit", r"C:\Windows\system32\userinit.exe,"))
    assert entry.path is not None and entry.path.name.lower() == "userinit.exe"
    assert assess(entry, MS, None).verdict is Verdict.CLEAN


def test_deleted_program_is_a_leftover_not_unknown():
    # Real case: an old GoogleUpdater version folder removed, its service left behind.
    entry = resolve(Autorun("Service", "HKLM", "GoogleUpdaterService134",
                            r'"C:\Program Files (x86)\Google\GoogleUpdater\134.0.6947.0\updater.exe" --system'))
    result = assess(entry, None, None)
    assert result.verdict is Verdict.CLEAN
    assert "no longer exists" in result.reasons[0]


def test_systemroot_prefix_is_understood():
    entry = resolve(Autorun("Driver", "HKLM", "x", r"\SystemRoot\System32\drivers\null.sys"))
    assert entry.path is not None and entry.path.name.lower() == "null.sys"


# --- Judging -------------------------------------------------------------------

def test_microsoft_items_skip_virustotal(make_scanner):
    vt = FakeVT()
    entry = resolve(Autorun("Service", "HKLM", "x", r"C:\Windows\System32\svchost.exe"))
    result = assess(entry, MS, make_scanner(vt))
    assert result.verdict is Verdict.CLEAN
    assert vt.calls == []


def test_missing_file_is_noted_not_flagged():
    entry = Autorun("Registry Run", "HKCU", "old", r'"C:\Gone\old.exe"', path=Path(r"C:\Gone\old.exe"))
    result = assess(entry, None, None)
    assert result.verdict is Verdict.CLEAN
    assert "no longer exists" in result.reasons[0]


def test_unsigned_program_in_temp_is_suspicious(tmp_path, make_scanner):
    exe = tmp_path / "AppData" / "Local" / "Temp" / "x1.exe"
    exe.parent.mkdir(parents=True)
    exe.write_bytes(b"MZ")
    entry = Autorun("Registry Run", "HKCU", "x1", f'"{exe}"', path=exe)
    assert assess(entry, UNSIGNED, make_scanner(FakeVT())).verdict is Verdict.SUSPICIOUS


def test_encoded_powershell_is_suspicious():
    entry = resolve(Autorun("Scheduled task", "\\", "t",
                            "powershell.exe -NoProfile -WindowStyle Hidden -enc SQBFAFgA"))
    result = assess(entry, MS, None)
    assert result.verdict is Verdict.SUSPICIOUS
    assert "encoded PowerShell" in result.reasons[0]


def test_replaced_windows_shell_is_suspicious():
    entry = resolve(Autorun("Winlogon", r"HKLM\Winlogon", "Shell", "explorer.exe, C:\\evil.exe"))
    entry.path = Path(r"C:\Windows\explorer.exe")
    assert assess(entry, MS, None).verdict is Verdict.SUSPICIOUS


def test_normal_winlogon_is_clean():
    entry = resolve(Autorun("Winlogon", r"HKLM\Winlogon", "Shell", "explorer.exe"))
    assert assess(entry, MS, None).verdict is Verdict.CLEAN


def test_virustotal_flags_unsigned_startup_program(program_files, make_scanner):
    exe = program_files / "good app.exe"
    vt = FakeVT(files={sha256_file(exe): {"malicious": 30, "undetected": 40, "label": "adware.agent"}})
    entry = resolve(Autorun("Registry Run", "HKCU", "app", f'"{exe}"'))
    result = assess(entry, UNSIGNED, make_scanner(vt))
    assert result.verdict is Verdict.MALICIOUS
    assert exe.exists()  # startup items are reported, never moved


def test_unknown_unsigned_startup_program(program_files, make_scanner, monkeypatch):
    # pytest's own scratch folder lives in %TEMP%, which would trip the Temp-folder rule.
    monkeypatch.setattr(autoruns, "TEMP_HINTS", ("\\not-a-real-temp\\",))
    entry = resolve(Autorun("Registry Run", "HKCU", "app", f'"{program_files / "good app.exe"}"'))
    assert assess(entry, UNSIGNED, make_scanner(FakeVT())).verdict is Verdict.UNKNOWN


# --- Monitoring ----------------------------------------------------------------

def test_monitor_alerts_only_on_new_items_after_first_run(program_files, tmp_path, make_scanner, store, monkeypatch):
    exe = program_files / "good app.exe"
    adware = tmp_path / "AppData" / "Roaming" / "ShopHelper" / "helper.exe"
    adware.parent.mkdir(parents=True)
    adware.write_bytes(b"MZ ads")

    current = [Autorun("Registry Run", "HKCU", "GoodApp", f'"{exe}"')]
    monkeypatch.setattr(autoruns, "enumerate_all", lambda: [resolve(Autorun(**vars(e))) for e in current])
    monkeypatch.setattr(autoruns, "check_signatures",
                        lambda paths: {str(p): Signature("Valid", "Good Corp") for p in paths})

    found = []
    monitor = AutorunMonitor(make_scanner(FakeVT(files={sha256_file(exe): {"undetected": 60}})), store, 10,
                             lambda e, r, new: found.append((e.name, r.verdict, new)))

    monitor.check()  # first run: records what's there, stays quiet because nothing is bad
    assert found == []

    monitor.check()  # nothing changed: nothing re-checked
    assert found == []

    current.append(Autorun("Registry Run", "HKCU", "ShopHelper", f'"{adware}"'))
    monitor.check()
    assert found == [("ShopHelper", Verdict.CLEAN, True)]  # new, signed, unknown to VirusTotal: still reported

    current.pop()
    monitor.check()
    assert "Registry Run|HKCU|ShopHelper" not in store.autoruns_seen()


def test_monitor_first_run_reports_existing_problems(tmp_path, make_scanner, store, monkeypatch):
    bad = tmp_path / "AppData" / "Local" / "Temp" / "svc.exe"
    bad.parent.mkdir(parents=True)
    bad.write_bytes(b"MZ")
    monkeypatch.setattr(autoruns, "enumerate_all",
                        lambda: [resolve(Autorun("Registry Run", "HKCU", "svc", f'"{bad}"'))])
    monkeypatch.setattr(autoruns, "check_signatures", lambda paths: {str(p): UNSIGNED for p in paths})
    found = []
    AutorunMonitor(make_scanner(FakeVT()), store, 10, lambda e, r, new: found.append(r.verdict)).check()
    assert found == [Verdict.SUSPICIOUS]


def test_switched_off_items_do_not_alert(tmp_path, make_scanner, store, monkeypatch):
    bad = tmp_path / "AppData" / "Local" / "Temp" / "svc.exe"
    bad.parent.mkdir(parents=True)
    bad.write_bytes(b"MZ")
    monkeypatch.setattr(autoruns, "enumerate_all",
                        lambda: [resolve(Autorun("Registry Run", "HKCU", "svc", f'"{bad}"', enabled=False))])
    monkeypatch.setattr(autoruns, "check_signatures", lambda paths: {str(p): UNSIGNED for p in paths})
    found = []
    AutorunMonitor(make_scanner(FakeVT()), store, 10, lambda *a: found.append(a)).check()
    assert found == []


def test_atlas_does_not_flag_its_own_launcher(monkeypatch, tmp_path, make_scanner):
    scripts = tmp_path / ".venv" / "Scripts"
    scripts.mkdir(parents=True)
    tray = scripts / "atlas-tray.exe"
    tray.write_bytes(b"MZ launcher")
    monkeypatch.setattr(autoruns.sys, "executable", str(scripts / "python.exe"))
    entry = resolve(Autorun("Startup folder", "Startup", "Project Atlas.lnk", f'"{tray}"'))
    result = assess(entry, UNSIGNED, make_scanner(FakeVT()))
    assert result.verdict is Verdict.CLEAN
    assert result.reasons == ["This is Project Atlas itself"]


def test_old_database_gains_detail_columns(tmp_path):
    import sqlite3

    from atlas.db import Store

    db = tmp_path / "old.db"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE autoruns (key TEXT PRIMARY KEY, category TEXT NOT NULL, name TEXT NOT NULL,"
                 " command TEXT NOT NULL, path TEXT, verdict TEXT, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL)")
    conn.execute("INSERT INTO autoruns VALUES ('k', 'Registry Run', 'x', 'x.exe', NULL, 'clean', 't', 't')")
    conn.commit()
    conn.close()
    store = Store(db)
    (row,) = store.autorun_rows()
    assert row["key"] == "k" and row["signer"] is None and row["reasons"] is None
    store.close()


def test_window_groups_startup_items(program_files, tmp_path, make_scanner, store, monkeypatch):
    from atlas.gui import autorun_group

    exe = program_files / "good app.exe"
    entries = [resolve(Autorun("Registry Run", "HKCU", "GoodApp", f'"{exe}"')),
               resolve(Autorun("Service", "HKLM", "Gone", r'"C:\Gone\gone.exe"')),
               resolve(Autorun("Service", "HKLM", "Win", r"C:\Windows\System32\svchost.exe"))]
    sigs = {str(exe): Signature("Valid", "Good Corp"), r"C:\Windows\System32\svchost.exe": MS}
    monkeypatch.setattr(autoruns, "check_signatures", lambda paths: {str(p): sigs.get(str(p)) for p in paths})
    results = autoruns.assess_all(entries, make_scanner(FakeVT(files={sha256_file(exe): {"undetected": 60}})))
    store.sync_autoruns(entries, {e.key: r for e, r in results})
    groups = {r["name"]: autorun_group(r) for r in store.autorun_rows()}
    assert groups == {"GoodApp": "third-party", "Gone": "leftover", "Win": "microsoft"}


# --- Settings and tray ---------------------------------------------------------

def test_old_settings_gain_desktop(tmp_path):
    cfg = config.config_dir() / "config.json"
    cfg.parent.mkdir(parents=True)
    cfg.write_text(json.dumps({"watch_folders": [r"C:\Users\me\Downloads"], "malicious_threshold": 5}))
    settings = config.Settings.load()
    assert settings.watch_folders[0] == r"C:\Users\me\Downloads"
    assert any(f.lower().endswith("desktop") for f in settings.watch_folders)
    assert settings.malicious_threshold == 5  # user choices survive the upgrade
    assert json.loads(cfg.read_text())["config_version"] == config.CONFIG_VERSION


def test_tray_icon_draws_every_state():
    from atlas.tray import STATE_COLORS, make_icon

    for state in STATE_COLORS:
        assert make_icon(state).size == (64, 64)
