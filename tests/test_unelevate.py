"""v0.12.1: the tray and window never run as administrator."""

import sys
from pathlib import Path

from atlas import app, unelevate


def test_not_elevated_keeps_running(monkeypatch):
    monkeypatch.setattr(unelevate, "is_elevated", lambda: False)
    monkeypatch.setattr(unelevate, "run_unelevated", lambda cmd: (_ for _ in ()).throw(AssertionError("restarted")))
    assert unelevate.restart_unelevated(["atlas-tray.exe"]) is False


def test_elevated_restarts_with_normal_rights(monkeypatch):
    started = []
    monkeypatch.setattr(unelevate, "is_elevated", lambda: True)
    monkeypatch.setattr(unelevate, "run_unelevated", lambda cmd: started.append(cmd) or True)
    assert unelevate.restart_unelevated(["atlas-gui.exe", "--scan", "C:\\a b.eml"]) is True
    assert started == [["atlas-gui.exe", "--scan", "C:\\a b.eml"]]


def test_elevated_but_restart_fails_keeps_running(monkeypatch):
    monkeypatch.setattr(unelevate, "is_elevated", lambda: True)
    monkeypatch.setattr(unelevate, "run_unelevated", lambda cmd: False)
    assert unelevate.restart_unelevated(["atlas-tray.exe"]) is False


def test_real_checks_dont_crash():
    assert unelevate.is_elevated() in (True, False)  # the test run itself is normally not elevated


def test_restart_commands(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(tmp_path / "ProjectAtlas.exe"))
    gui_exe = str(app.frozen.gui_exe())
    assert app.tray_command() == [gui_exe, "-m", "atlas.tray"]
    assert app.gui_command() == [gui_exe, "-m", "atlas.gui"]
    monkeypatch.setattr(sys, "frozen", False, raising=False)
    monkeypatch.setattr(sys, "executable", str(tmp_path / "python.exe"))
    cmd = app.tray_command()
    assert Path(cmd[0]).name == "python.exe" and cmd[1:] == ["-m", "atlas", "tray"]
