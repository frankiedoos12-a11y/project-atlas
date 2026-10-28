"""Right-click scanning: folder expansion, the hand-off queue, and menu registration (faked registry)."""

from pathlib import Path

import pytest

from atlas import contextmenu, scanwindow
from atlas.scanwindow import expand, take_queued


def touch(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"x")
    return path


def test_expand_files_and_folders(tmp_path):
    a = touch(tmp_path / "a.exe")
    b = touch(tmp_path / "dir" / "b.zip")
    c = touch(tmp_path / "dir" / "sub" / "c.dll")
    files, skipped = expand([a, tmp_path / "dir", tmp_path / "missing.exe"])
    assert sorted(files) == sorted([a, b, c]) and skipped == 0


def test_expand_caps_huge_folders(tmp_path):
    for i in range(7):
        touch(tmp_path / "big" / f"{i}.bin")
    files, skipped = expand([tmp_path / "big"], limit=5)
    assert len(files) == 5 and skipped == 2


def test_queue_hands_paths_to_the_open_window(isolated_dirs):
    assert take_queued() == []
    q = scanwindow.queue_file()
    q.parent.mkdir(parents=True, exist_ok=True)
    q.write_text("C:\\one.exe\nC:\\two folder\\two.zip\n\n", encoding="utf-8")
    assert take_queued() == ["C:\\one.exe", "C:\\two folder\\two.zip"]
    assert not q.exists() and take_queued() == []


def test_command_line_passes_the_clicked_item(monkeypatch, tmp_path):
    scripts = tmp_path / "Scripts"
    touch(scripts / "atlas-gui.exe")
    monkeypatch.setattr(contextmenu.sys, "executable", str(scripts / "python.exe"))
    assert contextmenu.command_line() == f'"{scripts / "atlas-gui.exe"}" --scan "%1"'


class FakeRegistry:
    """Just enough of winreg for contextmenu, keyed by subkey path."""
    HKEY_CURRENT_USER = "HKCU"
    REG_SZ = 1

    def __init__(self):
        self.keys: dict[str, dict] = {}

    def CreateKeyEx(self, hive, sub):
        values = self.keys.setdefault(sub, {})

        class Key:
            def __enter__(self_):
                return values

            def __exit__(self_, *a):
                return False
        return Key()

    def OpenKey(self, hive, sub):
        if sub not in self.keys:
            raise FileNotFoundError(sub)
        return self.CreateKeyEx(hive, sub)

    def SetValueEx(self, values, name, _, kind, data):
        values[name] = data

    def QueryValueEx(self, values, name):
        return values[name], self.REG_SZ

    def DeleteKey(self, hive, sub):
        if sub not in self.keys:
            raise FileNotFoundError(sub)
        if any(k.startswith(sub + "\\") for k in self.keys):
            raise PermissionError("delete subkeys first, like the real registry")
        del self.keys[sub]


@pytest.fixture
def registry(monkeypatch, isolated_dirs):
    fake = FakeRegistry()
    monkeypatch.setattr(contextmenu, "winreg", fake)
    monkeypatch.setattr(contextmenu, "command_line", lambda: '"atlas-gui.exe" --scan "%1"')
    return fake


def test_menu_entry_for_files_and_folders(registry):
    assert not contextmenu.is_enabled()
    contextmenu.enable()
    assert contextmenu.is_enabled()
    for base in (r"Software\Classes\*\shell", r"Software\Classes\Directory\shell"):
        assert registry.keys[rf"{base}\ProjectAtlas.Scan"][""] == "Scan with Project Atlas"
        assert registry.keys[rf"{base}\ProjectAtlas.Scan"]["Icon"].endswith("atlas.ico")
        assert registry.keys[rf"{base}\ProjectAtlas.Scan\command"][""] == '"atlas-gui.exe" --scan "%1"'
    assert Path(registry.keys[r"Software\Classes\*\shell\ProjectAtlas.Scan"]["Icon"]).exists()


def test_menu_entry_removal_leaves_nothing(registry):
    contextmenu.enable()
    contextmenu.disable()
    contextmenu.disable()  # twice is fine
    assert registry.keys == {} and not contextmenu.is_enabled()


def test_store_python_data_lives_where_explorer_can_see_it(monkeypatch, tmp_path):
    from atlas import config

    monkeypatch.delenv("ATLAS_DATA_DIR", raising=False)
    monkeypatch.delenv("ATLAS_CONFIG_DIR", raising=False)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "Local"))
    monkeypatch.setenv("APPDATA", str(tmp_path / "Roaming"))
    monkeypatch.setattr(config, "package_family", lambda: "PythonSoftwareFoundation.Python.3.13_abc")
    cache = tmp_path / "Local" / "Packages" / "PythonSoftwareFoundation.Python.3.13_abc" / "LocalCache"
    assert config.data_dir() == cache / "Local" / "ProjectAtlas"
    assert config.config_dir() == cache / "Roaming" / "ProjectAtlas"
    monkeypatch.setattr(config, "package_family", lambda: None)  # python.org install
    assert config.data_dir() == tmp_path / "Local" / "ProjectAtlas"
    assert config.config_dir() == tmp_path / "Roaming" / "ProjectAtlas"
