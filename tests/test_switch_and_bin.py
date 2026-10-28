"""Switching startup items off/on, and emptying the Recycle Bin. Registry and bin are faked."""

import struct
import winreg

import pytest

from atlas import autoruns, cleanup
from atlas.autoruns import approved_value, can_switch, set_enabled
from atlas.cleanup import JunkItem, clean

RUN = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
HKLM_RUN32 = r"HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"


@pytest.fixture
def written(monkeypatch):
    calls = []
    monkeypatch.setattr(autoruns, "_write_approved", lambda hive, sub, name, on: calls.append((hive, sub, name, on)))
    return calls


def test_approved_value_matches_task_manager():
    assert approved_value(True) == bytes([2]) + bytes(11)
    off = approved_value(False, now=0)
    assert off[:4] == bytes([3, 0, 0, 0]) and len(off) == 12
    assert struct.unpack("<Q", off[4:])[0] == 116444736000000000  # 1970 as a Windows FILETIME
    # Atlas's own reader agrees on what these mean
    assert not (approved_value(True)[0] & 1) and approved_value(False)[0] & 1


def test_switch_registry_run_items(written):
    set_enabled("Registry Run", RUN, "Spotify", False)
    set_enabled("Registry Run", HKLM_RUN32, "Updater", True)
    assert written == [(winreg.HKEY_CURRENT_USER, "Run", "Spotify", False),
                       (winreg.HKEY_LOCAL_MACHINE, "Run32", "Updater", True)]


def test_switch_startup_folder_item(written, monkeypatch, tmp_path):
    monkeypatch.setattr(autoruns, "known_folder", lambda _: tmp_path / "ProgramData Startup")
    set_enabled("Startup folder", str(tmp_path / "My Startup"), "Discord.lnk", False)
    set_enabled("Startup folder", str(tmp_path / "ProgramData Startup"), "Shared.lnk", False)
    assert [(h, s, n) for h, s, n, _ in written] == [(winreg.HKEY_CURRENT_USER, "StartupFolder", "Discord.lnk"),
                                                     (winreg.HKEY_LOCAL_MACHINE, "StartupFolder", "Shared.lnk")]


@pytest.mark.parametrize("category, location", [
    ("Registry Run", r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("Registry Run", r"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
    ("Service", "HKLM\\SYSTEM\\CurrentControlSet\\Services"),
    ("Driver", "HKLM\\SYSTEM\\CurrentControlSet\\Services"),
    ("Winlogon", "HKLM\\...\\Winlogon"),
])
def test_items_without_an_off_switch_are_refused(category, location, written):
    assert can_switch(category, location)
    with pytest.raises(ValueError):
        set_enabled(category, location, "x", False)
    assert written == []


def test_scheduled_task_switch(monkeypatch):
    calls = []
    monkeypatch.setattr(autoruns, "run_powershell_json",
                        lambda script, items, timeout: calls.append(items) or [{"ok": True}])
    set_enabled("Scheduled task", "\\Vendor\\", "Updater (action 2)", False)
    assert calls == [["\\Vendor\\", "Updater", "off"]]


def test_scheduled_task_access_denied_asks_for_admin(monkeypatch):
    monkeypatch.setattr(autoruns, "run_powershell_json",
                        lambda *a, **k: [{"ok": False, "error": "Access is denied."}])
    with pytest.raises(PermissionError, match="administrator"):
        set_enabled("Scheduled task", "\\Microsoft\\Windows\\", "Thing", False)


def test_switch_state_is_saved(store):
    from atlas.autoruns import Autorun

    entry = Autorun("Registry Run", RUN, "Spotify", "spotify.exe")
    store.sync_autoruns([entry], {})
    store.set_autorun_enabled(entry.key, False)
    assert store.autorun_rows()[0]["enabled"] == 0


# --- Recycle Bin ---------------------------------------------------------------------

def test_recycle_bin_is_listed_but_never_preselected(monkeypatch):
    monkeypatch.setattr(cleanup, "recycle_bin_contents", lambda: (20 * 1024**3, 73))
    (item,) = cleanup.find_recycle_bin().items
    assert item.how == "empty-bin" and not item.selected and "73 items" in item.label


def test_empty_recycle_bin_reports_space_freed(monkeypatch, tmp_path):
    state = {"size": 5000, "emptied": 0}
    monkeypatch.setattr(cleanup, "recycle_bin_contents", lambda: (state["size"], 1))

    def empty():
        state["emptied"] += 1
        state["size"] = 0

    monkeypatch.setattr(cleanup, "empty_recycle_bin", empty)
    result = clean([JunkItem("Recycle Bin (1 items)", None, 5000, how="empty-bin", selected=True)], tmp_path)
    assert state["emptied"] == 1 and result.freed == 5000 and result.removed == 1


def test_empty_bin_with_nothing_found_is_not_listed(monkeypatch):
    monkeypatch.setattr(cleanup, "recycle_bin_contents", lambda: (0, 0))
    assert cleanup.find_recycle_bin().items == []
