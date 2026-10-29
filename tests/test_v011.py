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


# --- v0.11.1: registry changes explained ------------------------------------------------------------------------

from atlas import registry  # noqa: E402
from atlas.findings import NOTE, WARN  # noqa: E402
from atlas.local_checks import Signature  # noqa: E402

CHROME = r'"C:\Program Files\Google\Chrome\Application\{}\Installer\chrmstp.exe" --configure-user-settings --system-level'


def chrome_change(before="155.0.8059.40", now="156.0.8078.49"):
    return registry.change_finding({"key": "HKLM|StubPath", "area": "Active Setup", "when": "2026-10-28T15:41",
                                    "location": r"HKLM\Software\Microsoft\Active Setup\Installed Components\{8A}",
                                    "before": CHROME.format(before) if before else None, "now": CHROME.format(now)})


def test_version_update_spots_only_version_changes():
    assert registry.version_update(CHROME.format("155.0.8059.40"), CHROME.format("156.0.8078.49")) == "156.0.8078.49"
    assert registry.version_update(None, CHROME.format("1.2")) is None
    assert registry.version_update(CHROME.format("1.2"), r'"C:\Users\me\AppData\evil.exe"') is None
    assert registry.version_update(CHROME.format("1.2"), CHROME.format("1.2") + " --payload") is None


def test_change_finding_points_at_its_program():
    f = chrome_change()
    assert f.data["path"] == r"C:\Program Files\Google\Chrome\Application\156.0.8078.49\Installer\chrmstp.exe"


def test_signed_clean_update_becomes_a_note():
    f, = registry.explain_changes([chrome_change()], lambda p: (Signature("Valid", "Google LLC"), "clean", "vt"))
    assert f.level == NOTE and "Google LLC program updated itself to 156.0.8078.49" in f.title
    assert f.vt_link == "vt" and "VirusTotal: clean" in f.details


def test_unsigned_or_flagged_update_still_needs_a_look():
    for judged in [(Signature("NotSigned"), "clean", None), (Signature("Valid", "Google LLC"), "malicious", "vt")]:
        f, = registry.explain_changes([chrome_change()], lambda p, j=judged: j)
        assert f.level == WARN and f.details[0].startswith("Program: ")
    new_entry, = registry.explain_changes([chrome_change(before=None)],
                                          lambda p: (Signature("Valid", "Google LLC"), "clean", None))
    assert new_entry.level == WARN  # a new entry isn't an update


def test_missing_program_leaves_the_finding_alone():
    f = chrome_change()
    assert registry.explain_changes([f], lambda p: None) == [f]


def test_regedit_path():
    assert registry.regedit_path(r"HKLM\Software\Microsoft\Active Setup > StubPath") == \
        r"Computer\HKEY_LOCAL_MACHINE\Software\Microsoft\Active Setup"
    assert registry.regedit_path(r"HKCU\Software\X") == r"Computer\HKEY_CURRENT_USER\Software\X"
