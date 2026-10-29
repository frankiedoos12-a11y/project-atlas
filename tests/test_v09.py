"""v0.9: software updates with CISA KEV, Defender's extra protection, SmartScreen, disk health,
leaked-password check and VirusTotal's AI analysis. No winget, PowerShell or network here."""

import subprocess
import types
from datetime import date

from atlas import defender, health, protection, pwned, softwareupdates as su
from atlas.findings import NOTE, OK, WARN, Finding
from atlas.scanner import ScanResult, Verdict, threat_lines
from atlas.vt_client import Report

WINGET = """\
   - \\ |
Name                                    Id                                 Version        Available    Source
---------------------------------------------------------------------------------------------------------------
7-Zip 23.01 (x64)                       7zip.7zip                          23.01          26.05        winget
Microsoft ODBC Driver 17 for SQL Server Microsoft.msodbcsql.17             17.10.6.1      17.11.1.1    winget
Zoom Workplace                          Zoom.Zoom.EXE                      7.1.9 (48550)  7.2.1 (48556) winget
Python Launcher                         Python.Launcher                    < 3.14.7       3.14.7       winget
4 upgrades available.
"""

KEV = [
    {"cveID": "CVE-2025-0411", "vendorProject": "7-Zip", "product": "7-Zip", "vulnerabilityName": "7-Zip MotW bypass",
     "dateAdded": "2025-02-06", "knownRansomwareCampaignUse": "Unknown"},
    {"cveID": "CVE-2026-0001", "vendorProject": "Microsoft", "product": "SQL Server", "dateAdded": "2026-01-01",
     "knownRansomwareCampaignUse": "Known"},
    {"cveID": "CVE-2026-0002", "vendorProject": "Google", "product": "Chromium V8", "dateAdded": "2026-09-01"},
    {"cveID": "CVE-2026-0003", "vendorProject": "Adobe", "product": "Acrobat and Reader", "dateAdded": "2026-05-01"},
    {"cveID": "CVE-2026-0004", "vendorProject": "Microsoft", "product": "Office", "dateAdded": "2026-03-01"},
]


# --- Software updates ------------------------------------------------------------------------------

def test_parse_winget_table_with_source_column_and_spinner():
    rows = su.parse_winget(WINGET)
    assert [r.id for r in rows] == ["7zip.7zip", "Microsoft.msodbcsql.17", "Zoom.Zoom.EXE", "Python.Launcher"]
    assert rows[2].version == "7.1.9 (48550)" and rows[2].available == "7.2.1 (48556)"
    assert rows[3].version == "< 3.14.7"


def test_parse_winget_without_source_column_and_nothing_to_update():
    text = "Name   Id      Version Available\n--------------------------------\nGit    Git.Git 2.54.0  2.56.0\n"
    assert [(r.name, r.available) for r in su.parse_winget(text)] == [("Git", "2.56.0")]
    assert su.parse_winget("No installed package found matching input criteria.") == []


def test_kev_matching():
    names = lambda n: [e["cveID"] for e in su.kev_matches(n, KEV)]  # noqa: E731
    assert names("7-Zip 23.01 (x64)") == ["CVE-2025-0411"]
    assert names("Microsoft ODBC Driver 17 for SQL Server") == []  # a driver for it, not the product
    assert names("Google Chrome") == names("Microsoft Edge") == ["CVE-2026-0002"]
    assert names("Adobe Acrobat Reader DC") == ["CVE-2026-0003"]
    assert names("Microsoft Office Professional Plus 2021") == ["CVE-2026-0004"]
    assert names("Zoom Workplace") == [] and names("Notepad") == []


def test_update_findings_kev_first_and_fix_button():
    found = su.update_findings(su.parse_winget(WINGET), KEV)
    zip_ = next(f for f in found if "7-Zip" in f.title)
    assert zip_.level == WARN and zip_.title.startswith("Update soon") and zip_.fix == "winget-upgrade"
    assert zip_.data["id"] == "7zip.7zip" and "cisa.gov" in zip_.vt_link
    assert any("CVE-2025-0411" in d for d in zip_.details)
    zoom = next(f for f in found if "Zoom" in f.title)
    assert zoom.level == NOTE and zoom.vt_link is None
    assert su.update_findings([], KEV)[0].level == OK
    assert su.update_findings(None, KEV)[0].key == "updates:no-winget"


def test_windows_update_findings():
    today = date(2026, 10, 28)
    assert su.windows_update_findings(date(2026, 10, 20), False, today)[0].level == OK
    old = su.windows_update_findings(date(2026, 8, 1), True, today)
    assert [f.level for f in old] == [NOTE, WARN] and "Restart" in old[0].title
    assert old[1].data["url"] == "ms-settings:windowsupdate"


def test_winget_cache_and_ask_again(store, monkeypatch):
    calls = []

    def run(*a, **k):
        calls.append(a)
        return types.SimpleNamespace(stdout=WINGET.encode())

    monkeypatch.setattr(su.subprocess, "run", run)
    assert len(su.winget_upgrades(store)) == 4
    su.winget_upgrades(store)
    assert len(calls) == 1  # saved for 12 hours
    su.ask_again()
    su.winget_upgrades(store)
    assert len(calls) == 2


def test_winget_fix_opens_console_and_refreshes(monkeypatch):
    started = []
    monkeypatch.setattr(protection.subprocess, "Popen", lambda args, **k: started.append(args))
    monkeypatch.setattr(subprocess, "CREATE_NEW_CONSOLE", 16, raising=False)
    f = Finding("Updates", "Update available: 7-Zip", NOTE, fix="winget-upgrade", data={"id": "7zip.7zip", "name": "7-Zip"})
    assert "7-Zip" in protection.describe_fix(f)
    protection.apply_fix(f)
    assert started[0][-5:] == ["--id", "7zip.7zip", "--exact", "--source", "winget"]
    assert su._ask_again


# --- Defender's extra protection --------------------------------------------------------------------

STATUS = {"mode": "Normal", "cloud": 2, "firstsight": True, "network": 0, "cfa": 0, "asr_ids": [None], "asr_actions": []}


def test_extra_protection_off_offers_to_turn_on():
    found = defender.protection_findings(STATUS)
    hit = next(f for f in found if "Extra attack protection" in f.title)
    assert hit.level == NOTE and hit.fix == "defender-harden" and "0 of 14" in hit.title


def test_extra_protection_on():
    ids = list(defender.ASR_RULES)
    status = dict(STATUS, network=1, asr_ids=[i.upper() for i in ids], asr_actions=[1] * (len(ids) - 1) + [6])
    hit = next(f for f in defender.protection_findings(status) if "Extra attack" in f.title)
    assert hit.level == OK and hit.fix == "defender-undo"


def test_audit_mode_rules_dont_count_and_cloud_off_warns():
    ids = list(defender.ASR_RULES)
    status = dict(STATUS, cloud=0, asr_ids=ids, asr_actions=[2] * len(ids))
    found = defender.protection_findings(status)
    assert any(f.title == "Cloud-delivered protection is off" and f.level == WARN for f in found)
    assert any("0 of 14" in f.title for f in found)


def test_other_antivirus_skips_defender_extras():
    assert defender.protection_findings(dict(STATUS, mode="Passive mode")) == []
    assert defender.protection_findings(None) == []


def test_harden_scripts_are_safe_to_quote():
    assert '"' not in defender.HARDEN_SCRIPT and '"' not in defender.UNDO_SCRIPT
    assert all(i in defender.HARDEN_SCRIPT for i in defender.ASR_RULES)


def test_harden_fix_asks_for_admin(monkeypatch):
    calls = []
    monkeypatch.setattr(protection, "_run_as_admin", lambda program, args, show=0: calls.append((program, args)))
    f = Finding("Defender", "x", NOTE, fix="defender-harden")
    assert "administrator" in protection.describe_fix(f)
    protection.apply_fix(f)
    assert calls[0][0] == "powershell.exe" and "Add-MpPreference" in calls[0][1]


def test_smartscreen():
    assert [f.title for f in defender.smartscreen_findings({"windows": None, "sac": 1})] == \
        ["SmartScreen is on", "Smart App Control is on"]
    found = defender.smartscreen_findings({"windows": "Off", "edge": 0, "sac": 0})
    assert [f.level for f in found] == [WARN, WARN, NOTE]
    policy = defender.smartscreen_findings({"windows": "Warn", "windows_policy": 0})
    assert "policy" in policy[0].details[0]


# --- Disk health ------------------------------------------------------------------------------------------

def test_disk_findings():
    disk = {"name": "KIOXIA", "media": "SSD", "health": "Healthy", "status": "OK", "size": 954}
    assert health.disk_findings([disk])[0].level == OK
    assert health.disk_findings([dict(disk, health="Unhealthy")])[0].level == WARN
    worn = health.disk_findings([disk], [{"name": "KIOXIA", "wear": 93, "temperature": 40, "read_errors": 0}])
    assert worn[0].level == WARN and "93%" in worn[0].title
    errors = health.disk_findings([disk], [{"name": "KIOXIA", "wear": 5, "read_errors": 3}])
    assert errors[0].level == WARN and "read error" in errors[0].title


# --- Leaked passwords -------------------------------------------------------------------------------------

def test_pwned_sends_only_the_prefix():
    sent = []

    def get(url, headers=None, timeout=None):
        sent.append(url)
        # SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        return types.SimpleNamespace(text="0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n"
                                          "1E4C9B93F3F0682250B6CF8331B7EE68FD8:9545824\r\n", raise_for_status=lambda: None)

    assert pwned.times_leaked("password", get=get) == 9545824
    assert sent == [pwned.RANGE_URL + "5BAA6"]
    assert pwned.times_leaked("something else entirely", get=get) == 0
    assert "9,545,824" in pwned.verdict(9545824) and "Not found" in pwned.verdict(0)


# --- VirusTotal's AI analysis -------------------------------------------------------------------------------

def test_vt_ai_analysis_parsed_and_shown_for_flagged_files():
    attrs = {"last_analysis_stats": {"malicious": 40, "undetected": 20},
             "crowdsourced_ai_results": [
                 {"category": "code_insight", "source": "palm", "analysis": "This script  downloads\n a payload."},
                 {"category": "references_summary", "analysis": "Linked to Emotet campaigns."},
                 {"category": "code_insight", "analysis": "  "}]}
    report = Report.from_attributes("file", "abc", attrs)
    assert report.ai == ["Code Insight: This script downloads a payload.", "What reports say: Linked to Emotet campaigns."]
    result = ScanResult(path=None, verdict=Verdict.MALICIOUS, file_report=report)
    rows = [r for r in threat_lines(result) if r[0] == "VT AI"]
    assert len(rows) == 2


def test_vt_ai_not_shown_for_clean_files_and_old_cache_loads():
    report = Report.from_attributes("file", "abc", {"last_analysis_stats": {"undetected": 60},
                                                    "crowdsourced_ai_results": [{"category": "code_insight",
                                                                                 "analysis": "Harmless."}]})
    assert not [r for r in threat_lines(ScanResult(path=None, verdict=Verdict.CLEAN, file_report=report))
                if r[0] == "VT AI"]
    assert Report(kind="file", target="x", found=True).ai == []
