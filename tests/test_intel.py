"""Richer VirusTotal use: site age and categories, threat names, sandbox behaviour,
network watch and the running programs check."""

import json
import time
from pathlib import Path

import pytest

from conftest import FakeVT
from test_scanner import write

from atlas import network, processes
from atlas.behaviour import describe_behaviour
from atlas.links import check_link
from atlas.local_checks import Signature, sha256_file
from atlas.network import Connection
from atlas.notify import toast_body
from atlas.processes import RunningFile
from atlas.scanner import Verdict, threat_lines
from atlas.sites import age_text, registered_domain, site_warnings
from atlas.tray import RunningMonitor
from atlas.vt_client import Report

DAY = 86400
NOW = time.time()
CLEAN = {"harmless": 60, "undetected": 20}
OLD_SITE = {**CLEAN, "created": int(NOW - 3000 * DAY)}
BAD = {"malicious": 30, "undetected": 40}


# --- VirusTotal report details ------------------------------------------------

def test_report_keeps_the_extra_details():
    attrs = {
        "last_analysis_stats": {"malicious": 40, "undetected": 20},
        "creation_date": 1700000000,
        "first_submission_date": 1790000000,
        "categories": {"Forcepoint ThreatSeeker": "phishing and other frauds", "Sophos": "Phishing and Fraud",
                       "BitDefender": "PHISHING AND OTHER FRAUDS"},
        "popularity_ranks": {"Alexa": {"rank": 5, "timestamp": 1500000000},  # stopped years ago: ignored
                             "Majestic": {"rank": 250000, "timestamp": int(NOW)}},
        "popular_threat_classification": {"suggested_threat_label": "trojan.remcos/rescoms",
                                          "popular_threat_name": [{"value": "remcos"}, {"value": "rescoms"}]},
        "sandbox_verdicts": {"CAPE Sandbox": {"category": "malicious", "sandbox_name": "CAPE Sandbox",
                                              "malware_classification": ["MALWARE", "RAT"],
                                              "malware_names": ["Remcos"]},
                             "Zenbox": {"category": "harmless", "sandbox_name": "Zenbox"}},
        "crowdsourced_yara_results": [{"rule_name": "win_remcos_auto"}],
        "sigma_analysis_results": [{"rule_level": "high", "rule_title": "UAC Bypass"},
                                   {"rule_level": "low", "rule_title": "Noise"}],
        "as_owner": "Bad Hosting Ltd", "country": "NL",
    }
    r = Report.from_attributes("file", "x", attrs)
    assert r.created == 1700000000 and r.first_seen == 1790000000
    assert r.categories == ["phishing and other frauds", "Phishing and Fraud"]  # case-insensitive duplicates go
    assert r.popularity == 250000
    assert r.threat_names == ["remcos", "rescoms"]  # the sandbox's "Remcos" is the same name
    assert r.sandbox == ["CAPE Sandbox: malicious (rat; Remcos)"]
    assert r.rules == ["win_remcos_auto", "UAC Bypass"]
    assert r.owner == "Bad Hosting Ltd, NL"


def test_reports_cached_by_older_versions_still_load(store):
    store._conn.execute("INSERT INTO vt_cache VALUES ('domain', 'old.example', ?, ?)",
                        (json.dumps({"kind": "domain", "target": "old.example", "found": True, "harmless": 5}),
                         "2099-01-01T00:00:00+00:00"))
    r = store.cached_report("domain", "old.example", 24 * 365 * 200)
    assert r.harmless == 5 and r.created is None and r.categories == []


def test_ip_report_link():
    assert Report(kind="ip", target="1.2.3.4", found=True).gui_link.endswith("/ip-address/1.2.3.4")


# --- Site age and categories ----------------------------------------------------

def lookup_from(domains):
    calls = []

    def lookup(kind, target):
        calls.append(target)
        stats = domains.get(target)
        return Report(kind, target, stats is not None, **(stats or {}))
    lookup.calls = calls
    return lookup


def test_brand_new_site_is_a_warning():
    lookup = lookup_from({"free-vlc-download.example": {**CLEAN, "created": int(NOW - 9 * DAY)}})
    [(warn, text)] = site_warnings(lookup, "free-vlc-download.example", now=NOW)
    assert warn and "registered 9 days ago" in text


def test_popular_new_site_is_not_a_warning():
    lookup = lookup_from({"launch.example": {**CLEAN, "created": int(NOW - 5 * DAY), "popularity": 800}})
    assert site_warnings(lookup, "launch.example", now=NOW) == [(False, "launch.example is fairly new: registered "
                                                                       "5 days ago")]


def test_old_site_says_nothing_and_young_site_is_mentioned():
    lookup = lookup_from({"sans.org": OLD_SITE, "shop.example": {**CLEAN, "created": int(NOW - 90 * DAY)}})
    assert site_warnings(lookup, "sans.org", now=NOW) == []
    [(warn, text)] = site_warnings(lookup, "shop.example", now=NOW)
    assert not warn and "3 months ago" in text


def test_subdomains_are_aged_by_their_registered_domain():
    lookup = lookup_from({"download.newsite.example": CLEAN,
                          "newsite.example": {**CLEAN, "created": int(NOW - 2 * DAY)}})
    [(warn, text)] = site_warnings(lookup, "download.newsite.example", now=NOW)
    assert warn and text.startswith("newsite.example was registered 2 days ago")
    assert lookup.calls == ["download.newsite.example", "newsite.example"]


def test_vendor_categories():
    lookup = lookup_from({"login.example": {**OLD_SITE, "categories": ["Phishing and Other Frauds", "business"]},
                          "toolbar.example": {**OLD_SITE, "categories": ["potentially unwanted software"]},
                          "parked.example": {**OLD_SITE, "categories": ["parked domain"]},
                          "news.example": {**OLD_SITE, "categories": ["news and media", "information technology"]}})
    assert site_warnings(lookup, "login.example", now=NOW) == [
        (True, 'Security vendors list login.example as "Phishing and Other Frauds"')]
    assert site_warnings(lookup, "toolbar.example", now=NOW)[0][0] is True
    assert site_warnings(lookup, "parked.example", now=NOW)[0][0] is False
    assert site_warnings(lookup, "news.example", now=NOW) == []


@pytest.mark.parametrize("host", ["192.168.1.1", "localhost", ""])
def test_addresses_without_a_registration_are_skipped(host):
    assert site_warnings(lookup_from({}), host) == []


def test_helpers():
    assert registered_domain("a.b.example.co.uk") == "example.co.uk"
    assert registered_domain("www.sans.org") == "sans.org"
    assert [age_text(d) for d in (0.5, 1.5, 9, 30, 400, 3000)] == [
        "today", "yesterday", "9 days ago", "4 weeks ago", "13 months ago", "8 years ago"]


def test_link_to_a_brand_new_site_is_suspicious(make_scanner):
    vt = FakeVT(domains={"get-obs-studio.example": {**CLEAN, "created": int(time.time() - 4 * DAY)}})
    check = check_link(make_scanner(vt), "https://get-obs-studio.example/download")
    assert check.verdict is Verdict.SUSPICIOUS
    assert any("registered 4 days ago" in r for r in check.reasons)


def test_download_from_a_brand_new_site_is_suspicious(make_scanner, downloads):
    f = write(downloads / "setup.exe", b"MZ fake installer", host_url="https://cdn.fresh-installer.example/setup.exe",
              referrer="https://fresh-installer.example/")
    vt = FakeVT(files={sha256_file(f): CLEAN},
                domains={"cdn.fresh-installer.example": CLEAN,
                         "fresh-installer.example": {**CLEAN, "created": int(time.time() - 3 * DAY)}})
    result = make_scanner(vt).scan(f, act=False)
    assert result.verdict is Verdict.SUSPICIOUS
    assert any("fresh-installer.example was registered 3 days ago" in r for r in result.reasons)


def test_brand_new_file_gets_a_note(make_scanner, downloads):
    f = write(downloads / "tool.exe", b"MZ new build")
    vt = FakeVT(files={sha256_file(f): {**CLEAN, "first_seen": int(time.time() - DAY / 2)}})
    result = make_scanner(vt).scan(f, act=False)
    assert result.verdict is Verdict.CLEAN
    assert result.reasons[0].startswith("No engines flagged this file")
    assert "first saw this file today" in result.reasons[1]


# --- What a flagged file does ---------------------------------------------------------

SUMMARY = {
    "verdicts": ["RAT", "STEALER", "MALWARE"],
    "tags": ["SELF_DELETE", "OBFUSCATED"],
    "registry_keys_set": [
        {"key": r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\Updater", "value": "x.exe"},
        {"key": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA", "value": "0"}],
    "command_executions": ["cmd /c vssadmin delete shadows /all /quiet",
                           "powershell -w hidden -enc SQBFAFgA", "schtasks /create /tn upd /tr x.exe"],
    "files_dropped": [{"path": r"C:\Users\<USER>\AppData\Roaming\upd.exe"}, {"path": "notes.txt"}],
    "dns_lookups": [{"hostname": "c2.evil.example"}, {"hostname": "www.msftncsi.com"}],
    "ip_traffic": [{"destination_ip": "45.153.34.113"}, {"destination_ip": "192.168.1.1"}],
    "mitre_attack_techniques": [{"severity": "IMPACT_SEVERITY_HIGH", "signature_description": "steal browser data"},
                                {"severity": "IMPACT_SEVERITY_INFO", "signature_description": "read clipboard"}],
}


def test_behaviour_in_plain_words():
    lines = describe_behaviour(SUMMARY)
    assert lines[:2] == ["Lets an attacker control the PC remotely",
                         "Steals passwords, browser cookies or other personal data"]
    text = "\n".join(lines)
    for expected in ("start with Windows", "User Account Control", "backup snapshots", "scheduled task",
                     "hidden or scrambled PowerShell", "1 other program file", "Contacts 2 server(s)",
                     "c2.evil.example, 45.153.34.113", "Deletes itself", "steal browser data"):
        assert expected in text
    assert "msftncsi" not in text and "192.168.1.1" not in text and "read clipboard" not in text
    assert describe_behaviour(None) == [] and describe_behaviour({}) == []


def test_flagged_files_get_their_behaviour_and_name(make_scanner, downloads):
    f = write(downloads / "invoice.exe", b"MZ remcos")
    sha = sha256_file(f)
    vt = FakeVT(files={sha: {**BAD, "label": "trojan.remcos/rescoms", "threat_names": ["remcos"],
                             "sandbox": ["CAPE Sandbox: malicious (rat; Remcos)"], "rules": ["win_remcos_auto"]}},
                behaviour={sha: SUMMARY})
    scanner = make_scanner(vt)
    result = scanner.scan(f, act=False)
    assert result.verdict is Verdict.MALICIOUS
    assert result.threat_text == "Remcos (trojan)"
    rows = threat_lines(result)
    assert rows[0] == ("Known as", "Remcos (trojan)", None)
    assert ("Does", "Lets an attacker control the PC remotely", None) in rows
    assert ("Rules", "win_remcos_auto", None) in rows
    assert "Known as Remcos (trojan): lets an attacker control" in toast_body(result)
    scanner.scan(f, act=False)
    assert vt.calls.count(("behaviour", sha)) == 1  # cached


def test_clean_files_skip_the_behaviour_lookup(make_scanner, downloads):
    f = write(downloads / "readme.exe", b"MZ fine")
    vt = FakeVT(files={sha256_file(f): CLEAN})
    result = make_scanner(vt).scan(f, act=False)
    assert ("behaviour", sha256_file(f)) not in vt.calls
    assert result.threat_text is None and threat_lines(result) == []


# --- Network watch ----------------------------------------------------------------

def fake_network(monkeypatch, conns, dns=None):
    monkeypatch.setattr(network, "connections", lambda: conns)
    monkeypatch.setattr(network, "dns_cache", lambda: dns)


def test_network_flags_bad_addresses_and_names_the_program(make_scanner, monkeypatch):
    fake_network(monkeypatch, [Connection(10, "updater.exe", r"C:\Temp\updater.exe", "45.153.34.113", 443),
                               Connection(11, "chrome.exe", None, "140.82.112.26", 443),
                               Connection(12, "chrome.exe", None, "104.16.1.1", 443)])
    vt = FakeVT(ips={"45.153.34.113": {**BAD, "owner": "Bad Hosting Ltd, NL"},
                     "140.82.112.26": {**CLEAN, "owner": "GitHub, Inc., US"},
                     "104.16.1.1": {"malicious": 1, "harmless": 60, "owner": "Cloudflare, Inc., US"}})
    report = network.check_network(make_scanner(vt))
    bad, *rest = report.addresses
    assert bad.target == "45.153.34.113" and bad.verdict is Verdict.SUSPICIOUS and bad.programs == ["updater.exe"]
    assert "Bad Hosting Ltd, NL" in bad.reasons[0]
    assert network.program_path(bad) == Path(r"C:\Temp\updater.exe")
    assert [c.verdict for c in rest] == [Verdict.CLEAN, Verdict.CLEAN]
    assert any("common for shared hosting" in r for c in rest for r in c.reasons)
    assert report.flagged == [bad] and not report.dns_available


def test_network_checks_recently_looked_up_sites_when_windows_allows(make_scanner, monkeypatch):
    fake_network(monkeypatch, [Connection(10, "chrome.exe", None, "203.0.113.9", 443)],
                 dns=[("a.cdn.example", "203.0.113.9"), ("b.cdn.example", "203.0.113.10"),
                      ("printer.local", "192.168.1.5"), ("new-scam.example", "198.51.100.7")])
    vt = FakeVT(domains={"a.cdn.example": OLD_SITE, "new-scam.example": {**CLEAN, "created": int(time.time() - DAY)}})
    report = network.check_network(make_scanner(vt))
    assert report.dns_available
    assert report.addresses[0].hostnames == ["a.cdn.example"]
    sites = {c.target: c for c in report.sites}
    assert set(sites) == {"a.cdn.example", "new-scam.example"}  # one per registered domain, no .local names
    assert sites["new-scam.example"].verdict is Verdict.SUSPICIOUS


def test_network_without_a_key(make_scanner, monkeypatch):
    fake_network(monkeypatch, [])
    assert network.check_network(make_scanner(None)).errors


@pytest.mark.parametrize("ip,expected", [("8.8.8.8", True), ("192.168.1.10", False), ("127.0.0.1", False),
                                         ("fe80::1%12", False), ("2607:f8b0::1", True)])
def test_internet_addresses(ip, expected):
    assert network.is_internet(ip) is expected


# --- Running programs ------------------------------------------------------------

@pytest.fixture
def running(monkeypatch, tmp_path):
    def make(*files):
        items = []
        for name, content, kind in files:
            path = tmp_path / name
            path.write_bytes(content)
            items.append(RunningFile(path, kind, {100 + len(items)}, {name}))
        monkeypatch.setattr(processes, "running_files", lambda include_dlls=False: (items, 2))
        return items
    return make


def test_running_programs_are_judged(make_scanner, running, monkeypatch):
    bad, signed, unsigned, fine = running(("evil.exe", b"MZ evil", "program"), ("vendor.exe", b"MZ v", "program"),
                                          ("odd.dll", b"MZ odd", "DLL"), ("ok.exe", b"MZ ok", "program"))
    sha = sha256_file(bad.path)
    vt = FakeVT(files={sha: {**BAD, "threat_names": ["redline"], "label": "trojan.redline/stealer"},
                       sha256_file(fine.path): CLEAN},
                behaviour={sha: {"verdicts": ["STEALER"]}})
    monkeypatch.setattr(processes, "check_signatures", lambda paths: {
        str(signed.path): Signature("Valid", "Vendor Ltd"), str(unsigned.path): Signature("NotSigned")})
    report = processes.check_running(make_scanner(vt))
    by_name = {f.path.name: f for f in report.files}
    assert by_name["evil.exe"].verdict is Verdict.MALICIOUS
    assert by_name["evil.exe"].result.behaviour == ["Steals passwords, browser cookies or other personal data"]
    assert by_name["vendor.exe"].verdict is Verdict.CLEAN and "signed by Vendor Ltd" in by_name["vendor.exe"].result.reasons[0]
    assert by_name["odd.dll"].verdict is Verdict.UNKNOWN
    assert by_name["ok.exe"].result.reasons == ["No engines flagged it (80 checked)"]
    assert [f.path.name for f in report.files][:2] == ["evil.exe", "odd.dll"]  # worst first
    assert report.flagged == [by_name["evil.exe"], by_name["odd.dll"]] and report.unreadable == 2


def test_lone_detections_on_signed_running_files_are_false_alarms(make_scanner, running, monkeypatch):
    signed, unsigned, signed_bad, gone = running(
        ("vmware.dll", b"MZ vm", "DLL"), ("odd.exe", b"MZ odd", "program"), ("signed-bad.exe", b"MZ sb", "program"),
        ("updated.dll", b"MZ old", "DLL"))
    gone.path.unlink()  # replaced by an update while still loaded
    one = {"malicious": 1, "undetected": 70}
    vt = FakeVT(files={sha256_file(signed.path): one, sha256_file(unsigned.path): one,
                       sha256_file(signed_bad.path): {"malicious": 5, "undetected": 60}})
    monkeypatch.setattr(processes, "check_signatures", lambda paths: {
        str(p): Signature("Valid", "VMware, Inc.") if p.name != "odd.exe" else Signature("NotSigned") for p in paths})
    by_name = {f.path.name: f for f in processes.check_running(make_scanner(vt)).files}
    assert by_name["vmware.dll"].verdict is Verdict.CLEAN
    assert by_name["vmware.dll"].result.reasons == ["1 of 71 engines flagged it, but it is validly signed by "
                                                    "VMware, Inc., and a lone detection on a signed file is "
                                                    "usually a false alarm"]
    assert by_name["odd.exe"].verdict is Verdict.SUSPICIOUS
    assert by_name["signed-bad.exe"].verdict is Verdict.MALICIOUS
    assert by_name["updated.dll"].verdict is Verdict.ERROR
    assert "updated itself while running" in by_name["updated.dll"].result.reasons[0]


def test_running_hashes_are_remembered(make_scanner, running, monkeypatch):
    [item] = running(("app.exe", b"MZ app", "program"))
    monkeypatch.setattr(processes, "check_signatures", lambda paths: {})
    scanner = make_scanner(FakeVT(files={sha256_file(item.path): CLEAN}))
    processes.check_running(scanner)
    monkeypatch.setattr(processes, "full_hash", lambda path: pytest.fail("hashed again"))
    assert processes.check_running(scanner).files[0].verdict is Verdict.CLEAN


def test_atlas_own_launchers_are_recognised(make_scanner, running, monkeypatch, tmp_path):
    monkeypatch.setattr(processes.sys, "prefix", str(tmp_path))
    assert processes.is_atlas_launcher(tmp_path / "Scripts" / "atlas-tray.exe")
    assert not processes.is_atlas_launcher(tmp_path / "Downloads" / "atlas-tray.exe")
    monkeypatch.setattr(processes.sys, "prefix", str(tmp_path.parent))  # the running fixture's files sit here
    monkeypatch.setattr(processes, "is_atlas_launcher", lambda path: path.name == "atlas-tray.exe")
    running(("atlas-tray.exe", b"MZ launcher", "program"), ("other.exe", b"MZ other", "program"))
    monkeypatch.setattr(processes, "check_signatures", lambda paths: {})
    vt = FakeVT()
    report = processes.check_running(make_scanner(vt))
    launcher = next(f for f in report.files if f.path.name == "atlas-tray.exe")
    assert launcher.verdict is Verdict.CLEAN and "own launcher" in launcher.result.reasons[0]
    assert len(vt.calls) == 1  # only other.exe was looked up


# --- Tray alerts ------------------------------------------------------------------

def test_tray_alerts_once_per_finding(make_scanner, running, monkeypatch):
    running(("evil.exe", b"MZ evil", "program"))
    fake_network(monkeypatch, [Connection(10, "evil.exe", None, "45.153.34.113", 443)])
    monkeypatch.setattr(processes, "check_signatures", lambda paths: {})
    vt = FakeVT(files={sha256_file(Path(processes.running_files()[0][0].path)): BAD}, ips={"45.153.34.113": BAD})
    told = []
    monitor = RunningMonitor(make_scanner(vt), 60, lambda *args: told.append(args))
    monitor.check()
    monitor.check()
    assert [t[0] for t in told] == ["Atlas: malicious program running", "Atlas: suspicious connection"]
    assert "evil.exe is talking to 45.153.34.113" in told[1][1]
