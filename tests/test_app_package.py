"""The packaged app (ProjectAtlas-Setup.exe): both programs start the right module, Atlas starts itself with
the app's programs, updates come from GitHub releases, and the uninstaller leaves other copies' settings alone."""

import sys
import types
from pathlib import Path

from atlas import autostart, browserext, cli, contextmenu, deepcheck, frozen, updates


def frozen_at(monkeypatch, folder: Path):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(folder / "ProjectAtlas.exe"))


def test_run_starts_default_or_dash_m_module(monkeypatch):
    started = []
    fake = types.SimpleNamespace(main=lambda: started.append(list(sys.argv)) or 3)
    monkeypatch.setattr(frozen.importlib, "import_module", lambda name: started.append(name) or fake)
    monkeypatch.setattr(sys, "argv", sys.argv[:])
    assert frozen.run(["atlas.exe", "scan", "x.exe"], "atlas.cli") == 3
    assert started == ["atlas.cli", ["atlas.exe", "scan", "x.exe"]]
    started.clear()
    frozen.run(["ProjectAtlas.exe", "-m", "atlas", "deep-check", "--collect"], "atlas.gui")
    assert started == ["atlas.cli", ["ProjectAtlas.exe", "deep-check", "--collect"]]
    assert frozen.run(["atlas.exe", "-m", "os"], "atlas.cli") == 2  # only Atlas's own modules


def test_launch_commands_use_the_app_programs(monkeypatch, tmp_path):
    frozen_at(monkeypatch, tmp_path)
    assert autostart._tray_command() == (tmp_path / "ProjectAtlas.exe", "-m atlas.tray")
    assert contextmenu.command_line() == f'"{tmp_path / "ProjectAtlas.exe"}" --scan "%1"'
    assert deepcheck._python() == str(tmp_path / "atlas.exe")


def test_browser_helper_runs_the_console_program(monkeypatch, tmp_path):
    frozen_at(monkeypatch, tmp_path)
    monkeypatch.setattr(browserext, "host_dir", lambda: tmp_path / "browser")
    browserext.write_host_files()
    launcher = (tmp_path / "browser" / "atlas-link-helper.bat").read_text(encoding="utf-8")
    assert f'"{tmp_path / "atlas.exe"}" -m atlas.nativehost' in launcher


def test_app_updates_from_github_releases(monkeypatch, tmp_path):
    frozen_at(monkeypatch, tmp_path)
    asked = []

    def get(url, timeout=None):
        asked.append(url)
        return types.SimpleNamespace(raise_for_status=lambda: None, json=lambda: {"tag_name": "v1.2.0"})

    assert updates.install_kind() == "app" and updates.can_update_itself()
    assert updates.latest_version(types.SimpleNamespace(get=get)) == "1.2.0"
    assert asked[0].endswith("/releases/latest")


def test_app_update_runs_the_new_setup_silently(monkeypatch, tmp_path):
    frozen_at(monkeypatch, tmp_path)
    started = []
    monkeypatch.setattr(updates.requests, "get", lambda url, timeout=None: types.SimpleNamespace(
        raise_for_status=lambda: None, content=b"MZ setup"))
    monkeypatch.setattr(updates.subprocess, "Popen", lambda args, **k: started.append(args))
    updates.start_update()
    assert started[0][0].endswith("ProjectAtlas-Setup.exe") and "/SILENT" in started[0]
    assert Path(started[0][0]).read_bytes() == b"MZ setup"


def test_uninstall_leaves_another_copys_settings_alone(monkeypatch, capsys):
    turned_off = []
    for module in (autostart, contextmenu, browserext):
        monkeypatch.setattr(module, "is_mine", lambda: False)
        monkeypatch.setattr(module, "disable", lambda m=module: turned_off.append(m))
    for command in ("autostart", "context-menu", "browser-extension"):
        assert cli.main([command, "off", "--only-mine"]) == 0
    assert turned_off == [] and "another copy" in capsys.readouterr().out
    monkeypatch.setattr(contextmenu, "is_mine", lambda: True)
    cli.main(["context-menu", "off", "--only-mine"])
    assert turned_off == [contextmenu]
