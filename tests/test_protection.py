"""Defender, hijack, installed-programs, update and quota checks. Nothing here touches the real
registry, browsers, Defender or GitHub: every reader is replaced with canned data."""

import json
import subprocess
import sys
import types
from pathlib import Path

import pytest

from atlas import defender, hijack, installed, protection, updates
from atlas.browsers import Profile
from atlas.findings import NOTE, OK, WARN, Finding
from atlas.processes import NewProgramWatcher, RunningFile
from atlas.scanner import ScanResult, Verdict
from atlas.vt_client import Report, VTClient

from conftest import FakeVT


def levels(findings):
    return {f.title: f.level for f in findings}


# --- Defender -----------------------------------------------------------------------

def test_defender_all_on():
    found = defender.status_findings({"service": True, "antivirus": True, "realtime": True, "tamper": True,
                                      "behavior": True, "downloads": True, "age": 0, "pua": 1, "mode": "Normal"})
    assert all(f.level == OK for f in found)
    assert any("unwanted app blocking is on" in f.title for f in found)


def test_defender_off_settings_warn():
    found = defender.status_findings({"service": True, "antivirus": True, "realtime": False, "tamper": False,
                                      "behavior": True, "downloads": True, "age": 12, "pua": 0})
    warn = {f.title for f in found if f.level == WARN}
    assert warn == {"Real-time protection is off", "Tamper protection is off", "Virus definitions are 12 days old",
                    "Potentially unwanted app blocking is off"}
    assert all(f.fix == "open" and f.data["url"].startswith("windowsdefender:") for f in found if f.level == WARN)


def test_defender_other_antivirus_and_unreadable():
    assert defender.status_findings({"mode": "Passive Mode"})[0].level == NOTE
    assert defender.status_findings(None)[0].key == "defender:unreadable"


def test_defender_events():
    events = [
        {"id": 5007, "when": "2026-10-01 10:00", "text": "Old value: \r\nNew value: HKLM\\SOFTWARE\\Microsoft\\"
                                                         "Windows Defender\\Exclusions\\Paths\\C:\\Users\\x\\AppData = 0x0"},
        {"id": 5007, "when": "2026-10-02 10:00", "text": "New value: HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\"
                                                         "Real-Time Protection\\DisableRealtimeMonitoring = 0x1"},
        {"id": 5007, "when": "2026-10-03", "text": "New value: HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\"
                                                   "Signature Updates\\LastUpdate = 0x5"},  # routine: ignored
        {"id": 5001, "when": "2026-10-04"},
        {"id": 5013, "when": "2026-10-05"},
        {"id": 1116, "when": "2026-10-06", "text": "Name: Trojan:Win32/Wacatac.B!ml\r\nID: 1"},
    ]
    found = defender.event_findings(events)
    titles = [f.title for f in found]
    assert titles == ["An exclusion was added: C:\\Users\\x\\AppData",
                      "A Defender setting was switched off: DisableRealtimeMonitoring",
                      "Real-time protection was switched off",
                      "Tamper protection blocked a change to Defender",
                      "Defender found Trojan:Win32/Wacatac.B!ml"]
    assert "folder or file" in found[0].details[0]
    assert found[-1].level == NOTE


@pytest.mark.parametrize("code, out, clean, threats", [
    (0, "Scanning C:\\x.exe found no threats.", True, []),
    (2, "Threat                  : PUA:Win32/Presenoker\nResources: 1", False, ["PUA:Win32/Presenoker"]),
    (2, "", False, []),
    (5, "Failed with hr = 0x80508023", None, []),
])
def test_defender_second_opinion(monkeypatch, tmp_path, code, out, clean, threats):
    monkeypatch.setattr(defender, "mpcmdrun", lambda: tmp_path / "MpCmdRun.exe")
    calls = []

    def fake_run(args, **kw):
        calls.append(args)
        return subprocess.CompletedProcess(args, code, out.encode(), b"")

    monkeypatch.setattr(defender.subprocess, "run", fake_run)
    scan = defender.scan_file(tmp_path / "x.exe")
    assert (scan.clean, scan.threats) == (clean, threats)
    assert "-DisableRemediation" in calls[0]  # report only: Defender must not act on the file


def test_defender_second_opinion_without_defender(monkeypatch, tmp_path):
    monkeypatch.setattr(defender, "mpcmdrun", lambda: None)
    assert defender.scan_file(tmp_path / "x.exe").clean is None


# --- Hijacks ---------------------------------------------------------------------------

def domain_lookup(**reports):
    def lookup(kind, target):
        return Report(kind, target, True, **reports[target]) if target in reports else Report(kind, target, False)
    return lookup


def test_judge_url():
    assert hijack.judge_url("https://www.google.com/", "start page", None, 3)[0] == OK
    assert hijack.judge_url("{google:baseURL}search?q={searchTerms}", "search engine", None, 3)[0] == OK
    level, reasons, _ = hijack.judge_url("http://yahoo.genieo.com/?v=w3i8", "start page", None, 3)
    assert level == WARN and "genieo.com" in reasons[0]
    level, reasons, _ = hijack.judge_url("https://search.yahoo.com/search?hspart=iry&p={searchTerms}",
                                         "search engine", None, 3)
    assert level == WARN and "iry" in reasons[0]
    assert hijack.judge_url("https://myschool.org/", "start page", None, 3)[0] == NOTE
    assert hijack.judge_url("https://weird-search.net/?q={searchTerms}", "search engine", None, 3)[0] == WARN
    assert hijack.judge_url("http://192.168.1.1/", "start page", None, 3)[0] == NOTE


def test_judge_url_flagged_by_virustotal():
    lookup = domain_lookup(**{"evil.example": {"malicious": 6, "undetected": 60}})
    level, reasons, link = hijack.judge_url("https://evil.example/", "start page", lookup, 3)
    assert level == WARN and any("6 of 66" in r for r in reasons) and link


def test_chromium_start_pages_and_search(tmp_path):
    (tmp_path / "Preferences").write_text(json.dumps({
        "session": {"restore_on_startup": 4, "startup_urls": ["http://yahoo.genieo.com/?v=1", "https://bing.com/"]},
        "default_search_provider_data": {"template_url_data": {"url": "https://trovi.com/?q={searchTerms}"}},
    }), encoding="utf-8")
    (tmp_path / "Secure Preferences").write_text(json.dumps({"session": {"restore_on_startup": 1,
                                                                         "startup_urls": ["https://x.com/"]}}))
    profile = Profile("Chrome", "chrome.exe", tmp_path, "Profile 2")
    assert hijack._chromium_settings(profile) == [("start page", "http://yahoo.genieo.com/?v=1"),
                                                  ("start page", "https://bing.com/"),
                                                  ("search engine", "https://trovi.com/?q={searchTerms}")]


def test_browser_findings(monkeypatch, tmp_path):
    (tmp_path / "Preferences").write_text(json.dumps({"session": {"restore_on_startup": 4, "startup_urls": [
        "http://yahoo.genieo.com/", "https://www.google.com/"]}}))
    monkeypatch.setattr(hijack, "chromium_profiles", lambda: [Profile("Chrome", "chrome.exe", tmp_path, "Profile 2")])
    monkeypatch.setattr(hijack, "firefox_profiles", lambda: [])
    found = hijack.browser_findings(None)
    assert len(found) == 1  # google.com is fine and not listed
    f = found[0]
    assert f.level == WARN and f.area == "Chrome (Profile 2)" and f.fix == "browser-settings"
    assert f.data == {"browser": "Chrome", "exe": "chrome.exe", "profile": "Profile 2", "page": "onStartup"}


def test_policy_findings():
    rows = [("HKCU", "Chrome", "HomepageLocation", "http://mystartsearch.com/"),
            ("HKLM", "Edge", "ProxyMode", "fixed_servers")]
    found = hijack.policy_findings(None, reader=lambda: rows)
    assert [f.level for f in found] == [WARN, WARN]
    assert found[0].fix == "remove-policy" and found[0].data["name"] == "HomepageLocation"
    assert any("hijacker" in r for r in found[0].details)
    assert found[1].fix is None  # machine-wide: needs an administrator


def test_proxy_findings():
    assert levels(hijack.proxy_findings(None, values={})) == {"No proxy: your web traffic goes straight out": OK}
    found = hijack.proxy_findings(None, values={"ProxyEnable": 1, "ProxyServer": "127.0.0.1:8888"})
    assert found[0].level == WARN and "on this PC" in found[0].details[0] and found[0].fix == "proxy-off"
    found = hijack.proxy_findings(None, values={"ProxyEnable": 0, "ProxyServer": "1.2.3.4:80",
                                                "AutoConfigURL": "http://pac.bad.example/p.pac", "WinHttp": "5.6.7.8:3128"})
    assert [f.key for f in found] == ["proxy:pac:http://pac.bad.example/p.pac", "proxy:winhttp:5.6.7.8:3128"]


def test_hosts_findings():
    assert levels(hijack.hosts_findings("# comment\n127.0.0.1 localhost\n::1 localhost\n")) == \
        {"Hosts file is clean": OK}
    text = ("0.0.0.0 www.virustotal.com\n0.0.0.0 ads.example\n0.0.0.0 tracker.example\n"
            "45.33.32.156 www.mybank.com  # injected\n192.168.1.20 nas.local\n")
    found = hijack.hosts_findings(text)
    assert levels(found) == {"Blocks security or update sites: www.virustotal.com": WARN,
                             "Sends www.mybank.com to 45.33.32.156": WARN,
                             "Blocks 2 site(s)": NOTE,
                             "1 name(s) point at your home network": NOTE}
    assert all(f.fix == "edit-hosts" for f in found if f.level == WARN)


def test_dns_findings():
    lookup = domain_lookup(**{"185.141.27.53": {"malicious": 5, "undetected": 50, "owner": "Shady Hosting (RU)"}})
    rows = [{"adapter": "Wi-Fi", "servers": ["192.168.1.1", "8.8.8.8", "fec0:0:0:ffff::1"]},
            {"adapter": "Ethernet", "servers": ["185.141.27.53", "139.130.4.5"]}]
    found = hijack.dns_findings(lookup, rows=rows)
    assert levels(found) == {"Wi-Fi: your router or local network (192.168.1.1)": OK,
                             "Wi-Fi: Google Public DNS (8.8.8.8)": OK,
                             "Ethernet: 185.141.27.53 (Shady Hosting (RU)) is flagged by VirusTotal": WARN,
                             "Ethernet: 139.130.4.5": NOTE}


# --- Fix buttons (fake registry) -------------------------------------------------------

class FakeKey:
    def __init__(self, values):
        self.values = values

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def fake_winreg(values: dict):
    keys = {}

    def open_key(hive, path, *a):
        return FakeKey(keys.setdefault(path, values.setdefault(path, {})))

    def delete(key, name):
        if name not in key.values:
            raise FileNotFoundError(name)
        del key.values[name]

    return types.SimpleNamespace(HKEY_CURRENT_USER=1, KEY_SET_VALUE=2, REG_DWORD=4, OpenKey=open_key,
                                 SetValueEx=lambda key, name, _, kind, value: key.values.__setitem__(name, value),
                                 DeleteValue=delete)


def test_fix_proxy_off(monkeypatch):
    reg = {hijack.INTERNET_SETTINGS: {"ProxyEnable": 1, "ProxyServer": "1.2.3.4:80", "AutoConfigURL": "http://x/p"}}
    monkeypatch.setitem(sys.modules, "winreg", fake_winreg(reg))
    monkeypatch.setattr(protection, "_tell_windows_internet_settings_changed", lambda: None)
    f = Finding("Proxy", "A proxy server is set", WARN, fix="proxy-off", data=dict(reg[hijack.INTERNET_SETTINGS]))
    message = protection.apply_fix(f)
    assert reg[hijack.INTERNET_SETTINGS] == {"ProxyEnable": 0, "ProxyServer": "1.2.3.4:80"}
    backup = Path(message.rsplit(": ", 1)[1])
    assert json.loads(backup.read_text())["AutoConfigURL"] == "http://x/p"


def test_fix_remove_policy(monkeypatch):
    path = hijack.POLICY_BROWSERS["Chrome"]
    reg = {path: {"HomepageLocation": "http://mystartsearch.com/", "Other": 1}}
    monkeypatch.setitem(sys.modules, "winreg", fake_winreg(reg))
    f = Finding("Chrome policy", "Home page forced", WARN, fix="remove-policy",
                data={"key": path, "name": "HomepageLocation", "value": "http://mystartsearch.com/"})
    assert "Policy removed" in protection.apply_fix(f)
    assert reg[path] == {"Other": 1}


def test_describe_fix():
    assert "backup" in protection.describe_fix(Finding("Proxy", "x", WARN, fix="proxy-off"))
    assert protection.describe_fix(Finding("Defender", "x", WARN, fix="open")) == ""


# --- Installed programs -----------------------------------------------------------------

def test_list_installed():
    rows = [("all users", "k1", "a", {"DisplayName": "7-Zip 24.08", "Publisher": "Igor Pavlov", "InstallDate": "20260115",
                                      "EstimatedSize": 5120, "UninstallString": '"C:\\7z\\Uninstall.exe"'}),
            ("all users", "k2", "b", {"DisplayName": "Hidden part", "SystemComponent": 1}),
            ("all users", "k3", "c", {"DisplayName": "Some update", "ParentKeyName": "Office"}),
            ("this user", "k4", "d", {"DisplayName": "OneLaunch"}),
            ("all users", "k5", "e", {"Publisher": "no name"})]
    progs = installed.list_installed(rows)
    assert [p.name for p in progs] == ["7-Zip 24.08", "OneLaunch"]
    assert progs[0].installed_on == "2026-01-15" and progs[0].size_mb == 5.0 and progs[1].scope == "this user"


def program_with(report: Report, verdict: Verdict, name="uTorrent", publisher="BitTorrent Inc."):
    p = installed.InstalledProgram(name, publisher)
    p.file = RunningFile(Path("C:/x/app.exe"), "installed",
                         result=ScanResult(Path("C:/x/app.exe"), "ab" * 32, verdict, ["4 of 70 engines"],
                                           file_report=report))
    return p


def test_judge_program_unwanted_by_consensus():
    report = Report("file", "ab", True, malicious=8, undetected=60, label="pua.utorrent",
                    threat_kinds=["pua", "trojan"])
    p = program_with(report, Verdict.MALICIOUS)
    installed.judge_program(p)
    assert p.unwanted and p.verdict is Verdict.SUSPICIOUS and p.status == "UNWANTED"


def test_judge_program_malware_stays_malicious():
    report = Report("file", "ab", True, malicious=40, undetected=30, label="trojan.remcos",
                    threat_kinds=["trojan", "adware"])
    p = program_with(report, Verdict.MALICIOUS)
    installed.judge_program(p)
    assert not p.unwanted and p.verdict is Verdict.MALICIOUS and p.status == "MALICIOUS"


def test_judge_program_known_pup_by_name():
    p = installed.InstalledProgram("OneLaunch", "OneLaunch")
    installed.judge_program(p)
    assert p.verdict is Verdict.SUSPICIOUS and p.status == "UNWANTED"
    assert any("couldn't find its program file" in n for n in p.notes)
    shady = installed.InstalledProgram("Super PC Optimizer", "Someone")
    installed.judge_program(shady)
    assert shady.verdict is Verdict.CLEAN and shady.notes


@pytest.mark.parametrize("command, expected", [
    ("MsiExec.exe /I{12345678-ABCD-1234-ABCD-123456789012}", ("msiexec.exe", "/x {12345678-ABCD-1234-ABCD-123456789012}")),
    ('"C:\\Program Files\\App\\uninst.exe" /S', ("C:\\Program Files\\App\\uninst.exe", "/S")),
    ("C:\\Program Files\\App\\uninst.exe --remove", ("C:\\Program Files\\App\\uninst.exe", "--remove")),
])
def test_uninstall_command(command, expected):
    assert installed.uninstall_command(command) == expected


def test_check_installed_without_key(make_scanner):
    progs = installed.check_installed(make_scanner(None), programs=[installed.InstalledProgram("OneLaunch", "x"),
                                                                    installed.InstalledProgram("Notepad++", "Don Ho")])
    assert [p.name for p in progs] == ["OneLaunch", "Notepad++"]  # worst first


# --- Updates --------------------------------------------------------------------------------

def test_versions():
    assert updates.is_newer("0.6.1", "0.6.0") and updates.is_newer("1.0", "0.9.9")
    assert not updates.is_newer("0.6.0", "0.6.0") and not updates.is_newer("0.5.9", "0.6.0")


def test_install_kind(tmp_path):
    assert updates.install_kind(tmp_path) == "other"
    (tmp_path / "install.ps1").write_text("")
    (tmp_path / ".venv").mkdir()
    assert updates.install_kind(tmp_path) == "installer"
    (tmp_path / ".git").mkdir()
    assert updates.install_kind(tmp_path) == "git"


def test_latest_version():
    class Session:
        def get(self, url, timeout):
            assert url.endswith("/atlas/__init__.py")
            return types.SimpleNamespace(text='"""x"""\n__version__ = "9.1.0"\n', raise_for_status=lambda: None)

    assert updates.latest_version(Session()) == "9.1.0"


# --- Quota meter and "already told you" --------------------------------------------------------

def test_vt_usage(store):
    from atlas.app import vt_usage, vt_usage_text

    for kind, status in [("files", 200), ("files", 404), ("domains", 200), ("files", 429)]:
        store.count_vt_request(kind, status)
    u = vt_usage(store)
    assert (u["today"], u["month"], u["throttled_today"]) == (4, 4, 1)
    assert "4 VirusTotal lookups today" in vt_usage_text(store)


def test_vt_client_counts_requests():
    class Session:
        headers = {}

        def get(self, url, timeout):
            return types.SimpleNamespace(status_code=404, ok=False, text="")

    client = VTClient("key", session=Session())
    counted = []
    client.on_request = lambda kind, status: counted.append((kind, status))
    assert not client.domain_report("example.com").found
    assert counted == [("domains", 404)]


def test_new_findings(store):
    assert not store.has_seen_findings()
    assert store.new_findings(["a", "b"]) == ["a", "b"]
    assert store.new_findings(["b", "c", "c"]) == ["c"]
    assert store.has_seen_findings()


def test_system_monitor_alerts_only_on_new(monkeypatch, store):
    from atlas.tray import SystemMonitor

    current = [Finding("Defender", "PUA blocking is off", WARN, ["why"], key="defender:pua:off")]
    monkeypatch.setattr(protection, "check_system", lambda scanner=None: list(current))
    told = []
    monitor = SystemMonitor(None, store, 60, lambda *a: told.append(a))
    monitor.check()  # first run: a quiet baseline
    assert told == [] and monitor.needs_look == 1
    current.append(Finding("Proxy", "A proxy server is set", WARN, ["why"], key="proxy:server:1.2.3.4"))
    monitor.check()
    monitor.check()
    assert [t[1].splitlines()[0] for t in told] == ["A proxy server is set"]


# --- New programs ----------------------------------------------------------------------------------

def test_new_program_watcher(monkeypatch, tmp_path, make_scanner):
    import hashlib

    import psutil

    bad = tmp_path / "bad.exe"
    bad.write_bytes(b"MZ evil")
    good = tmp_path / "good.exe"
    good.write_bytes(b"MZ fine")
    sha = hashlib.sha256(bad.read_bytes()).hexdigest()
    scanner = make_scanner(FakeVT(files={sha: {"malicious": 30, "undetected": 40}}))
    running = {1: good, 2: good}

    class Proc:
        def __init__(self, pid):
            if pid not in running:
                raise psutil.NoSuchProcess(pid)
            self.pid = pid

        def exe(self):
            return str(running[self.pid])

        def name(self):
            return running[self.pid].name

    monkeypatch.setattr(psutil, "pids", lambda: list(running))
    monkeypatch.setattr(psutil, "Process", Proc)
    told = []
    watcher = NewProgramWatcher(scanner, lambda *a: told.append(a))
    watcher._known_pids = {1, 2}
    running[3] = bad
    running[4] = good
    watcher.tick()
    assert [t[0] for t in told] == ["Atlas: malicious program just started"]
    assert "bad.exe" in told[0][1]
    running[5] = bad  # started again: already told
    watcher.tick()
    assert len(told) == 1
    watcher.paused = True
    running[6] = bad
    watcher.tick()
    assert len(told) == 1
