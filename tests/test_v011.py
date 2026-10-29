"""v0.11: the window's sidebar (Home plus five groups of tabs) and Home's "Scan a file..." button."""

import sys
import types
from pathlib import Path

from atlas import app, gui


class FakeWidget:
    def __init__(self):
        self.calls = []

    def __getattr__(self, name):
        return lambda *a, **k: self.calls.append((name, a, k))


def fake_window():
    win = types.SimpleNamespace(page="", pages={g: FakeWidget() for g, _ in gui.GROUPS},
                                nav={g: FakeWidget() for g, _ in gui.GROUPS},
                                tab_frames={"Full scan": ("protection", "frame-fullscan")})
    win.show = lambda group, tab=None: gui.AtlasWindow.show(win, group, tab)
    return win


def test_show_swaps_pages_and_highlights_the_group():
    win = fake_window()
    win.show("home")
    win.show("pc")
    assert ("pack_forget", (), {}) in win.pages["home"].calls
    assert win.pages["pc"].calls[-1][0] == "pack" and win.page == "pc"
    assert win.nav["pc"].calls[-1][2]["background"] == gui.SIDEBAR_ON
    assert win.nav["home"].calls[-1][2]["background"] == gui.SIDEBAR_BG


def test_show_tab_opens_its_group_on_that_tab():
    win = fake_window()
    win.show("home")
    gui.AtlasWindow.show_tab(win, "Full scan")
    assert win.page == "protection"
    assert ("select", ("frame-fullscan",), {}) in win.pages["protection"].calls


def test_sidebar_starts_with_home_then_five_groups():
    assert [g for g, _ in gui.GROUPS] == ["home", "protection", "pc", "online", "clean", "history"]


def test_scan_command_matches_explorers_menu(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(tmp_path / "ProjectAtlas.exe"))
    assert app.scan_command(["C:\\a.exe", "C:\\b b.zip"]) == [str(tmp_path / "ProjectAtlas.exe"), "--scan",
                                                             "C:\\a.exe", "C:\\b b.zip"]
    monkeypatch.setattr(sys, "frozen", False, raising=False)
    monkeypatch.setattr(sys, "executable", str(tmp_path / "python.exe"))
    cmd = app.scan_command(["x.exe"])
    assert Path(cmd[0]).name == "python.exe" and cmd[1:] == ["-m", "atlas.gui", "--scan", "x.exe"]
