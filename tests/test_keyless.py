"""v0.13: without a VirusTotal key, Microsoft Defender checks programs and View on VirusTotal still works."""

from pathlib import Path

from atlas import defender
from atlas.links import LinkCheck, check_link
from atlas.local_checks import sha256_file
from atlas.scanner import ScanResult, Verdict
from atlas.vt_client import GUI_BASE, Report


def write(path: Path, content: bytes, downloaded: bool = False) -> Path:
    path.write_bytes(content)
    if downloaded:
        Path(f"{path}:Zone.Identifier").write_text("[ZoneTransfer]\nZoneId=3\nHostUrl=https://example.org/x\n")
    return path


def fake_defender(monkeypatch, clean, message="Defender found no threats (12:00)"):
    scanned = []

    def scan_file(path, timeout=600):
        scanned.append(path)
        return defender.DefenderScan(path, clean, [], message)

    monkeypatch.setattr(defender, "scan_file", scan_file)
    return scanned


def test_defender_finds_a_threat(make_scanner, downloads, monkeypatch):
    fake_defender(monkeypatch, False, "Defender found Trojan:Win32/Fake")
    f = write(downloads / "bad.exe", b"MZ evil")
    result = make_scanner(None).scan(f, act=False)
    assert result.verdict is Verdict.MALICIOUS
    assert "Microsoft Defender found Trojan:Win32/Fake" in result.reasons
    assert result.vt_link == f"{GUI_BASE}/file/{sha256_file(f)}"


def test_unsigned_download_defender_clean_is_unknown(make_scanner, downloads, monkeypatch):
    fake_defender(monkeypatch, True)
    f = write(downloads / "setup.exe", b"MZ who knows", downloaded=True)
    result = make_scanner(None).scan(f, act=False)
    assert result.verdict is Verdict.UNKNOWN
    assert "View on VirusTotal" in result.reasons[-1]


def test_unsigned_local_program_defender_clean_is_clean(make_scanner, downloads, monkeypatch):
    fake_defender(monkeypatch, True)
    result = make_scanner(None).scan(write(downloads / "tool.exe", b"MZ mine"), act=False)
    assert result.verdict is Verdict.CLEAN
    assert result.reasons[-1].startswith("Microsoft Defender found no threats")


def test_defender_unavailable_is_an_error(make_scanner, downloads, monkeypatch):
    fake_defender(monkeypatch, None, "Defender's scanner (MpCmdRun.exe) wasn't found")
    result = make_scanner(None).scan(write(downloads / "tool.exe", b"MZ"), act=False)
    assert result.verdict is Verdict.ERROR
    assert "VirusTotal isn't connected" in result.reasons[-1]


def test_files_that_cant_run_code_skip_defender(make_scanner, downloads, monkeypatch):
    scanned = fake_defender(monkeypatch, True)
    result = make_scanner(None).scan(write(downloads / "notes.txt", b"hello"), act=False)
    assert result.verdict is Verdict.CLEAN and scanned == []


def test_vt_link_only_when_useful():
    assert ScanResult(Path("x"), sha256="ab" * 32).vt_link == f"{GUI_BASE}/file/{'ab' * 32}"
    looked_up_unknown = ScanResult(Path("x"), sha256="ab" * 32, file_report=Report("file", "ab" * 32, found=False))
    assert looked_up_unknown.vt_link is None  # VirusTotal already said it has never seen it
    assert ScanResult(Path("x")).vt_link is None


def test_link_vt_link_without_a_key_names_only_the_site():
    check = check_link(None, "https://login.example.com/reset?token=secret")
    assert check.vt_link == f"{GUI_BASE}/domain/login.example.com"
    assert "secret" not in check.vt_link
    assert LinkCheck("http://203.0.113.9/x").vt_link == f"{GUI_BASE}/ip-address/203.0.113.9"
