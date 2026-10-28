"""Cleanup tests. Everything happens in throwaway folders; the Recycle Bin and registry are faked."""

import os
import stat
import time
from pathlib import Path

import pytest

from atlas import cleanup
from atlas.autoruns import Autorun
from atlas.cleanup import JunkItem, clean, find_leftover_startup, find_orphaned_app_data, has_home, measure

NOW = time.time()
OLD = NOW - 10 * cleanup.DAY


def make(path: Path, size: int = 100, mtime: float = OLD) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"x" * size)
    os.utime(path, (mtime, mtime))
    return path


def backdate(folder: Path, mtime: float) -> None:
    """A folder's own timestamp counts as use too, so tests must age the folders they build."""
    os.utime(folder, (mtime, mtime))


@pytest.fixture
def recycled(monkeypatch):
    bin_: list[Path] = []
    monkeypatch.setattr(cleanup, "_recycle", lambda p: bin_.append(p))
    return bin_


def test_measure_counts_nested_files(tmp_path):
    make(tmp_path / "a" / "one.bin", 300)
    now = time.time()  # not NOW: folders made just now count too, and the suite may be minutes old
    make(tmp_path / "a" / "b" / "two.bin", 200, mtime=now)
    size, newest = measure(tmp_path / "a")
    assert size == 500
    assert newest == pytest.approx(now, abs=2)


def test_temp_skips_recently_used(tmp_path):
    make(tmp_path / "old.tmp")
    make(tmp_path / "old_dir" / "f.log")
    make(tmp_path / "busy_dir" / "old.log")
    make(tmp_path / "busy_dir" / "new.log", mtime=NOW)  # still in use: whole folder kept
    backdate(tmp_path / "old_dir", OLD)
    backdate(tmp_path / "busy_dir", OLD)
    items = cleanup._age_filtered_children(tmp_path, 1, NOW, "delete")
    assert sorted(i.label for i in items) == ["old.tmp", "old_dir"]


def test_temp_used_by_startup_item_is_locked(tmp_path):
    # Real case: HP's "SystemOptimizerTemp" scheduled task runs an .exe from %TEMP%\HP.
    exe = make(tmp_path / "HP" / "SystemOptimizerTemp" / "SystemOptimizer.exe")
    backdate(exe.parent, OLD)
    backdate(tmp_path / "HP", OLD)
    make(tmp_path / "junk.tmp")
    task = Autorun("Scheduled task", "\\", "SystemOptimizerTemp", f'"{exe}"', path=exe)
    items = {i.label: i for i in cleanup.find_temp_files(NOW, startup_entries=[task], folders=[tmp_path]).items}
    assert items["HP"].blocked == 'Used by startup item "SystemOptimizerTemp"'
    assert items["junk.tmp"].blocked is None


def test_clean_deletes_files_and_reports_space(tmp_path):
    a = make(tmp_path / "temp" / "a.tmp", 1000)
    d = make(tmp_path / "temp" / "dir" / "b.tmp", 500).parent
    root = tmp_path / "temp"
    result = clean([JunkItem("a", a, 1000, root=root), JunkItem("dir", d, 500, root=root)], tmp_path / "bk")
    assert result.removed == 2 and result.freed == 1500
    assert not a.exists() and not d.exists()


def test_clean_removes_read_only_files(tmp_path):
    # Real case: Explorer copies photos from a zip into %TEMP% and marks them read-only.
    root = tmp_path / "Temp"
    folder = root / "76a40a8a_iCloud Photos (9).zip.289"
    photo = make(folder / "iCloud Photos" / "IMG_5631.JPEG", 1000)
    loose = make(root / "readonly.tmp", 50)
    for f in (photo, loose):
        os.chmod(f, stat.S_IREAD)
    result = clean([JunkItem("zip", folder, 1000, root=root), JunkItem("loose", loose, 50, root=root)],
                   tmp_path / "bk")
    assert not folder.exists() and not loose.exists()
    assert result.skipped == [] and result.freed == 1050


def test_clean_empties_cache_but_keeps_folder(tmp_path):
    cache = tmp_path / "Chrome" / "Default" / "Cache"
    make(cache / "data_0", 400)
    make(cache / "sub" / "data_1", 600)
    clean([JunkItem("cache", cache, 1000, how="contents", root=tmp_path / "Chrome")], tmp_path / "bk")
    assert cache.is_dir() and not any(cache.iterdir())


def test_clean_refuses_paths_outside_their_folder(tmp_path):
    victim = make(tmp_path / "Documents" / "important.docx")
    item = JunkItem("sneaky", victim, 100, root=tmp_path / "Temp")
    result = clean([item], tmp_path / "bk")
    assert victim.exists()
    assert result.removed == 0 and "outside" in result.skipped[0]


def test_clean_skips_blocked_items(tmp_path):
    cache = make(tmp_path / "Cache" / "f")
    result = clean([JunkItem("c", cache.parent, 100, how="contents", root=tmp_path, blocked="Close Chrome first")],
                   tmp_path / "bk")
    assert cache.exists() and result.skipped == ["c: Close Chrome first"]


def test_recycle_items_go_to_recycle_bin(tmp_path, recycled):
    setup = make(tmp_path / "Downloads" / "setup.exe", 5000)
    result = clean([JunkItem("setup.exe", setup, 5000, how="recycle")], tmp_path / "bk")
    assert recycled == [setup] and result.freed == 5000


def test_one_failure_does_not_stop_the_rest(tmp_path, monkeypatch):
    def boom(_):
        raise OSError("file in use")

    monkeypatch.setattr(cleanup, "_recycle", boom)
    ok = make(tmp_path / "t" / "ok.tmp")
    result = clean([JunkItem("busy", tmp_path / "x", 1, how="recycle"),
                    JunkItem("ok", ok, 100, root=tmp_path / "t")], tmp_path / "bk")
    assert result.removed == 1 and not ok.exists()
    assert result.skipped == ["busy: file in use"]


def test_registry_items_are_backed_up_first(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(cleanup, "_remove_registry_value",
                        lambda hive, key, value, bk: calls.append((hive, key, value)) or bk / "x.reg")
    item = JunkItem("OldApp", None, how="registry",
                    registry=("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run", "OldApp"))
    result = clean([item], tmp_path / "bk")
    assert calls == [("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run", "OldApp")]
    assert result.backups == [tmp_path / "bk" / "x.reg"]


def test_machine_wide_registry_entries_are_refused(tmp_path):
    with pytest.raises(PermissionError):
        cleanup._remove_registry_value("HKLM", r"Software\X", "v", tmp_path)


def test_leftover_startup_entries(tmp_path):
    shortcut = make(tmp_path / "Startup" / "OldTool.lnk", 50)
    entries = [
        Autorun("Registry Run", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "OldApp",
                r'"C:\Gone\old.exe"', path=Path(r"C:\Gone\old.exe")),
        Autorun("Registry Run", r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run", "OldSvc",
                r'"C:\Gone\svc.exe"', path=Path(r"C:\Gone\svc.exe")),
        Autorun("Startup folder", str(tmp_path / "Startup"), "OldTool.lnk", r'"C:\Gone\tool.exe"',
                path=Path(r"C:\Gone\tool.exe")),
        Autorun("Service", r"HKLM\SYSTEM\CurrentControlSet\Services", "GoogleUpdaterService134",
                r'"C:\Gone\updater.exe"', path=Path(r"C:\Gone\updater.exe")),
        Autorun("Registry Run", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "Alive",
                f'"{shortcut}"', path=shortcut),  # still exists: not a leftover
    ]
    items = {i.label: i for i in find_leftover_startup(entries).items}
    assert set(items) == {"OldApp", "OldSvc", "OldTool.lnk", "GoogleUpdaterService134"}
    assert items["OldApp"].how == "registry" and not items["OldApp"].blocked
    assert items["OldApp"].registry == ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run", "OldApp")
    assert items["OldTool.lnk"].how == "recycle" and items["OldTool.lnk"].path == shortcut
    assert items["OldSvc"].blocked and items["GoogleUpdaterService134"].blocked


def test_has_home_matching():
    installed = {"zoomworkplace", "zoomvideocommunicationsinc", "mozillafirefox", "mozilla", "spotify", "obsstudio"}
    assert has_home("Zoom", installed)
    assert has_home("Mozilla", installed)
    assert has_home("obs-studio", installed)
    assert has_home("Microsoft", set())  # Windows' own
    assert has_home("{3F2504E0-4F89}", set())  # GUID folders aren't judged
    assert not has_home("ShopperHelperPro", installed)


def test_orphaned_app_data_needs_no_match_and_long_idle(tmp_path):
    roaming = tmp_path / "Roaming"
    make(roaming / "Zoom" / "data.db", mtime=NOW - 400 * cleanup.DAY)  # has a home
    make(roaming / "OldGameLauncher" / "cfg.ini", 2000, mtime=NOW - 400 * cleanup.DAY)  # orphan
    make(roaming / "NewThing" / "cfg.ini", mtime=NOW - 5 * cleanup.DAY)  # used recently
    for name in ("Zoom", "OldGameLauncher", "NewThing"):
        backdate(roaming / name, NOW - 400 * cleanup.DAY)
    cat = find_orphaned_app_data(NOW, installed={"zoomworkplace"}, roots=[roaming])
    assert [i.label for i in cat.items] == ["OldGameLauncher"]
    assert cat.items[0].how == "recycle" and not cat.items[0].selected


def test_old_installers_not_preselected(tmp_path, monkeypatch):
    monkeypatch.setattr(cleanup, "known_folder", lambda _: tmp_path)
    make(tmp_path / "old_setup.exe", mtime=NOW - 90 * cleanup.DAY)
    make(tmp_path / "new_setup.exe", mtime=NOW)
    make(tmp_path / "photo.jpg", mtime=NOW - 90 * cleanup.DAY)
    cat = cleanup.find_old_installers(NOW)
    assert [i.label for i in cat.items] == ["old_setup.exe"]
    assert not cat.items[0].selected


def test_human_size():
    assert cleanup.human_size(512) == "512 bytes"
    assert cleanup.human_size(1536) == "1.5 KB"
    assert cleanup.human_size(3 * 1024**3) == "3.0 GB"


def test_shader_caches_found_in_driver_folders(tmp_path, monkeypatch):
    local = tmp_path / "Local"
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    make(local / "NVIDIA" / "DXCache" / "a.nvph", 300)
    make(tmp_path / "LocalLow" / "NVIDIA" / "DXCache" / "b.nvph", 200)
    make(local / "D3DSCache" / "1933c870be838b51" / "cache.idx", 50)
    (local / "AMD" / "VkCache").mkdir(parents=True)  # empty: not worth listing
    cat = cleanup.find_shader_caches()
    sizes = {i.label: i.size for i in cat.items}
    assert sizes == {"NVIDIA DirectX cache": 300, "NVIDIA DirectX cache (LocalLow)": 200,
                     "DirectX shader cache": 50}
    assert all(i.how == "contents" and i.root == i.path for i in cat.items)


def test_emptying_skips_files_in_use_and_keeps_going(tmp_path, monkeypatch):
    cache = tmp_path / "DXCache"
    make(cache / "busy.nvph", 100)
    make(cache / "old1.nvph", 100)
    make(cache / "old2.nvph", 100)
    real_delete = cleanup._delete

    def delete(path):
        if path.name == "busy.nvph":
            raise PermissionError("in use by game.exe")
        real_delete(path)

    monkeypatch.setattr(cleanup, "_delete", delete)
    result = clean([JunkItem("NVIDIA DirectX cache", cache, 300, how="contents", root=cache)], tmp_path)
    assert result.freed == 200 and result.removed == 1
    assert sorted(p.name for p in cache.iterdir()) == ["busy.nvph"]
    assert "partly in use" in result.skipped[0]


def test_emptying_when_everything_is_in_use(tmp_path, monkeypatch):
    cache = tmp_path / "DXCache"
    make(cache / "busy.nvph", 100)
    monkeypatch.setattr(cleanup, "_delete", lambda p: (_ for _ in ()).throw(PermissionError("in use")))
    result = clean([JunkItem("NVIDIA DirectX cache", cache, 100, how="contents", root=cache)], tmp_path)
    assert result.freed == 0 and result.removed == 0
    assert "close the program" in result.skipped[0]
