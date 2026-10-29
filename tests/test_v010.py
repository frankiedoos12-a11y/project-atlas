"""v0.10: remote-access guard, scam check, health score and weekly report, privacy clean, full scan, grouped updates.
No real processes, browsers, drives or VirusTotal here."""

import os
import time
import types
from datetime import date, timedelta
from pathlib import Path

from atlas import cleanup, config, fullscan, processes, protection, remoteaccess, report, scam, score
from atlas import softwareupdates as su
from atlas.findings import NOTE, OK, WARN, Finding
from atlas.scanner import Verdict

# --- Remote access ---------------------------------------------------------------------------------------------


def test_tools_matched_by_file_and_program_name():
    assert remoteaccess.match_file("AnyDesk.exe").name == "AnyDesk"
    assert remoteaccess.match_file("anydesk (1).exe").name == "AnyDesk"
    assert remoteaccess.match_file("TeamViewer_Setup_x64.exe").name == "TeamViewer"
    assert remoteaccess.match_file("QuickAssist.exe").name == "Quick Assist"
    assert remoteaccess.match_file("notepad.exe") is None and remoteaccess.match_file("level.exe") is None
    assert remoteaccess.match_program("ScreenConnect Client (1a2b3c)").name.startswith("ScreenConnect")
    assert remoteaccess.match_program("Zoom Workplace") is None


def test_running_downloaded_installed_and_trusted():
    tool = remoteaccess.match_file("AnyDesk.exe")
    tv = remoteaccess.match_file("TeamViewer.exe")
    rust = remoteaccess.match_file("rustdesk.exe")
    found = remoteaccess.remote_findings(
        running={"AnyDesk": (tool, {42}, {r"C:\Users\me\Downloads\AnyDesk.exe"})},
        installed={"TeamViewer": (tv, "TeamViewer")},
        downloaded={"RustDesk": (rust, [Path(r"C:\Users\me\Downloads\rustdesk.exe")])},
        trusted=[])
    by_tool = {f.data["tool"]: f for f in found}
    assert by_tool["AnyDesk"].level == WARN and by_tool["AnyDesk"].fix == "end-remote"
    assert by_tool["AnyDesk"].data["pids"] == [42] and "scam" in " ".join(by_tool["AnyDesk"].details)
    assert by_tool["RustDesk"].level == WARN and by_tool["RustDesk"].fix == "trust-remote"
    assert by_tool["TeamViewer"].level == NOTE
    trusted = remoteaccess.remote_findings({}, {"TeamViewer": (tv, "TeamViewer")}, {}, ["teamviewer"])
    assert trusted[0].level == OK and trusted[0].fix == "untrust-remote"
    assert remoteaccess.remote_findings({}, {}, {}, [])[0].key == "remote:none"


def test_only_recent_downloads_count(tmp_path):
    new, old = tmp_path / "AnyDesk.exe", tmp_path / "TeamViewer.exe"
    new.write_bytes(b"x")
    old.write_bytes(b"x")
    month_ago = time.time() - 40 * 86400
    os.utime(old, (month_ago, month_ago))
    assert list(remoteaccess.downloaded_copies([tmp_path, tmp_path / "missing"])) == ["AnyDesk"]


def test_trust_fix_saves_setting():
    f = Finding("Remote access", "x", WARN, fix="trust-remote", data={"tool": "AnyDesk"})
    assert "AnyDesk" in protection.describe_fix(f)
    protection.apply_fix(f)
    assert config.Settings.load().trusted_remote_tools == ["AnyDesk"]
    protection.apply_fix(Finding("Remote access", "x", OK, fix="untrust-remote", data={"tool": "anydesk"}))
    assert config.Settings.load().trusted_remote_tools == []


def test_new_program_watcher_speaks_up_once_per_half_hour(monkeypatch, make_scanner):
    told = []
    names = {1: "AnyDesk.exe", 2: "AnyDesk.exe", 3: "TeamViewer.exe"}
    monkeypatch.setattr("psutil.Process", lambda pid: types.SimpleNamespace(name=lambda: names[pid]))
    watcher = processes.NewProgramWatcher(make_scanner(None), lambda *a: told.append(a[0]))
    watcher._check_remote_access({1})
    watcher._check_remote_access({2})
    assert told == ["Atlas: AnyDesk just started"]
    s = config.Settings.load()
    s.trusted_remote_tools = ["TeamViewer"]
    s.save()
    watcher._check_remote_access({3})
    assert len(told) == 1


# --- Scam check ------------------------------------------------------------------------------------------------

SCAM_TEXT = ("URGENT: Your Norton subscription has been renewed for $399.99. If you did not authorize this, call "
             "(888) 555-0142 within 24 hours. Our technician will connect to your computer with AnyDesk. Pay the "
             "fee with Google Play gift cards and do not tell your bank.")


def test_scam_message():
    result = scam.check_message(SCAM_TEXT)
    titles = {r.title for r in result.reasons}
    assert result.verdict == scam.SCAM
    assert {"Asks for remote access", "Gift cards", "Call this number", "Keep it secret"} <= titles
    assert all(r.quote for r in result.reasons)


def test_ordinary_message_and_phone_alone():
    assert scam.check_message("Lunch moved to Thursday at noon, see you there!").verdict == scam.NOTHING
    # A signature with a phone number isn't "call this number" on its own.
    assert not [r for r in scam.word_reasons("Thanks, Pat. 555-123-4567") if r.title == "Call this number"]
    assert scam.check_message("Your invoice is attached.").verdict == scam.CAREFUL


def test_links_found_and_flagged_links_raise_the_score(make_scanner, monkeypatch):
    assert scam.links_in("see https://x.example/a, and www.paypal.com.login-check.xyz.") == \
        ["https://x.example/a", "www.paypal.com.login-check.xyz"]
    bad = types.SimpleNamespace(verdict=Verdict.MALICIOUS, reasons=["bad"], url="http://evil.example")
    monkeypatch.setattr(scam, "check_link", lambda scanner, url: bad)
    result = scam.check_message("Hello, please look at http://evil.example today")
    assert result.verdict == scam.SCAM and result.reasons[-1].title == "Dangerous link"


# --- Health score and weekly report ----------------------------------------------------------------------------

def test_health_score():
    assert score.health_score([Finding("Proxy", "fine", OK)]).value == 100
    updates = [Finding("Updates", f"Update soon: {n}", WARN) for n in "abc"]
    s = score.health_score(updates + [Finding("Defender", "PUA off", WARN)] + [Finding("X", "n", NOTE)] * 4)
    assert s.value == 100 - 15 - 8 - 3 - 3 - 4 and s.label == "Fair"
    assert s.warn[0] == "Defender: PUA off"  # serious first
    assert score.health_score([Finding("Defender", "off", WARN)] * 20).value == 100 - 15 - 3 * 19
    assert score.health_score([Finding("X", "n", NOTE)] * 50).value == 90


def test_weekly_report_compares_with_last_week(store):
    today = date(2026, 11, 4)
    old = score.Score(70, "Fair", ["Defender: PUA off", "Updates: Update soon: Git"], 3)
    score.record(store, old, today - timedelta(days=7))
    now = score.Score(85, "Fair", ["Updates: Update soon: Git", "Remote access: AnyDesk is running"], 2)
    weekly = report.build(store, now, today)
    assert weekly.before == 70 and weekly.change == "up 15"
    assert weekly.fixed == ["Defender: PUA off"] and weekly.new == ["Remote access: AnyDesk is running"]
    assert "2 things need a look" in weekly.summary
    page = report.to_html(dataclass_replace(weekly, new=["<script>x</script>"]))
    assert "<script>x" not in page and "&lt;script&gt;" in page


def dataclass_replace(obj, **changes):
    import dataclasses

    return dataclasses.replace(obj, **changes)


def test_report_due_weekly(store):
    today = date(2026, 11, 4)
    assert not report.due(store, today)  # the first one waits a week
    assert not report.due(store, today + timedelta(days=6))
    assert report.due(store, today + timedelta(days=7))
    report.mark_sent(store, today + timedelta(days=7))
    assert not report.due(store, today + timedelta(days=8))


def test_activity_since(store):
    from datetime import datetime

    store.record_scan("a.exe", "x", "malicious", [], None, None)
    store.record_cleanup("Temp", "t", None, "delete", 100)
    got = store.activity_since(datetime.now().astimezone() - timedelta(days=1))
    assert got["scans"] == {"malicious": 1} and got["cleaned_bytes"] == 100


# --- Privacy clean ---------------------------------------------------------------------------------------------

def test_privacy_items_never_ticked_and_clean_only_named_files(tmp_path, monkeypatch):
    root = tmp_path / "User Data"
    profile = root / "Default"
    (profile / "Network").mkdir(parents=True)
    (profile / "Preferences").write_text("{}")
    (profile / "History").write_bytes(b"h" * 10)
    (profile / "Network" / "Cookies").write_bytes(b"c" * 5)
    (profile / "Local Storage").mkdir()
    (profile / "Local Storage" / "leveldb").write_bytes(b"l" * 3)
    (profile / "Bookmarks").write_text("keep me")
    monkeypatch.setattr(cleanup, "BROWSERS", [("Chrome", "chrome.exe", lambda: root)])
    monkeypatch.setattr(cleanup, "_roaming", lambda: tmp_path / "Roaming")
    history = cleanup.find_browsing_history(set())
    cookies = cleanup.find_cookies({"chrome.exe"})
    assert [i.selected for i in history.items + cookies.items] == [False, False]
    assert history.items[0].files == ("History",) and history.items[0].size == 10
    assert cookies.items[0].blocked == "Close Chrome first"
    result = cleanup.clean(history.items + [dataclass_replace(cookies.items[0], blocked=None)], tmp_path / "b")
    assert result.removed == 2 and result.freed == 18
    assert not (profile / "History").exists() and not (profile / "Local Storage").exists()
    assert (profile / "Bookmarks").exists() and (profile / "Preferences").exists()


def test_files_item_refuses_names_outside_its_folder(tmp_path):
    (tmp_path / "keep.txt").write_text("x")
    item = cleanup.JunkItem("x", tmp_path / "sub", 1, how="files", root=tmp_path / "sub", files=("../keep.txt",))
    (tmp_path / "sub").mkdir()
    result = cleanup.clean([item], tmp_path / "b")
    assert result.removed == 0 and (tmp_path / "keep.txt").exists()


def test_recent_files_list(tmp_path, monkeypatch):
    recent = tmp_path / "Roaming" / "Microsoft" / "Windows" / "Recent"
    (recent / "AutomaticDestinations").mkdir(parents=True)
    (recent / "report.docx.lnk").write_bytes(b"l")
    monkeypatch.setattr(cleanup, "_roaming", lambda: tmp_path / "Roaming")
    cat = cleanup.find_recent_files()
    assert cat.items[0].files == ("report.docx.lnk",) and not cat.items[0].selected


# --- Full scan -------------------------------------------------------------------------------------------------

def test_program_files_and_risk_order(tmp_path, monkeypatch):
    for rel in ("Users/me/Downloads/new.exe", "Users/me/Downloads/readme.txt", "Program Files/App/app.dll",
                "Intel/tool.exe", "Users/me/proj/node_modules/x.exe", "quarantine/bad.exe"):
        f = tmp_path / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_bytes(b"MZ")
    files = fullscan.program_files([tmp_path], skip={str(tmp_path / "quarantine")})
    names = sorted(p.name for p, _, _ in files)
    assert names == ["app.dll", "new.exe", "tool.exe"]
    windows, pf = os.path.normcase(r"C:\Windows") + "\\", (os.path.normcase(r"C:\Program Files") + "\\",)
    paths = [r"C:\Users\me\Downloads\a.exe", r"C:\Users\me\Documents\b.exe", r"C:\Intel\c.exe",
             r"C:\Program Files\App\d.dll", r"C:\Windows\System32\e.dll"]
    assert [fullscan._risk(Path(p), windows, pf) for p in paths] == [0, 1, 2, 3, 4]


def test_full_scan_spends_only_its_budget(tmp_path, monkeypatch, make_scanner, store):
    for n in range(5):
        (tmp_path / f"f{n}.exe").write_bytes(bytes([n]))
    scanner = make_scanner(object())
    for n in range(5):  # f0 oldest, so it comes last; its answer is saved, so it's free even after the budget
        os.utime(tmp_path / f"f{n}.exe", (1_000_000 + n, 1_000_000 + n))
    monkeypatch.setattr(fullscan, "_hash", lambda s, path: path.stem)
    monkeypatch.setattr(store, "cached_hash", lambda path, size, mtime: Path(path).stem)
    monkeypatch.setattr(store, "cached_report", lambda kind, sha, hours: object() if sha == "f0" else None)
    judged = []

    def judge(s, files, say, cancel):
        judged.extend(f.path.stem for f in files)
        assert s.settings.cache_hours >= fullscan.FRESH_DAYS * 24  # a month-old answer is still good
        return []

    monkeypatch.setattr(fullscan, "judge_files", judge)
    report_ = fullscan.full_scan(scanner, budget=2, roots=[tmp_path])
    assert report_.found == 5 and len(judged) == 3 and "f0" in judged and report_.left == 2
    assert "left for another day" in fullscan.summary(report_)


def test_full_scan_needs_a_key(make_scanner):
    assert "VirusTotal key" in fullscan.summary(fullscan.full_scan(make_scanner(None), 10))


def test_defender_scans_ask_for_admin(monkeypatch):
    calls = []
    monkeypatch.setattr(protection, "_run_as_admin", lambda program, args, show=0: calls.append(args))
    protection.start_defender_scan(offline=False)
    protection.start_defender_scan(offline=True)
    assert "FullScan" in calls[0] and "Start-MpWDOScan" in calls[1]


# --- Grouped updates -------------------------------------------------------------------------------------------

def test_many_ordinary_updates_become_one_row():
    ups = [su.Upgrade(f"App {n}", f"Vendor.App{n}", "1.0", "2.0") for n in range(5)]
    kev = [{"cveID": "CVE-1", "product": "7-Zip", "dateAdded": "2026-01-01"}]
    found = su.update_findings(ups + [su.Upgrade("7-Zip 23.01", "7zip.7zip", "23.01", "26.05")], kev)
    assert [f.title for f in found] == ["5 programs have updates", "Update soon: 7-Zip 23.01"]
    assert found[0].fix == "winget-upgrade-all" and len(found[0].data["ids"]) == 5


def test_update_all_command_leaves_out_odd_ids():
    command = su.upgrade_all_command(["Git.Git", "bad & del *", "7zip.7zip"])
    assert command.startswith("cmd /k ") and "bad" not in command and command.count("winget upgrade") == 2
