import time
from pathlib import Path

from conftest import FakeVT

from atlas import watcher
from atlas.local_checks import read_motw, sha256_file
from atlas.quarantine import restore_file
from atlas.scanner import Verdict
from atlas.vt_client import url_id


def write(path: Path, content: bytes, host_url: str | None = None,
          referrer: str = "https://example.org/") -> Path:
    path.write_bytes(content)
    if host_url:
        Path(f"{path}:Zone.Identifier").write_text(
            f"[ZoneTransfer]\nZoneId=3\nReferrerUrl={referrer}\nHostUrl={host_url}\n"
        )
    return path


def test_clean_file(make_scanner, downloads):
    f = write(downloads / "notes.txt", b"hello")
    vt = FakeVT(files={sha256_file(f): {"undetected": 60, "harmless": 5}})
    result = make_scanner(vt).scan(f)
    assert result.verdict is Verdict.CLEAN
    assert "65 checked" in result.reasons[0]
    assert f.exists()


def test_malicious_file_is_quarantined_and_restorable(make_scanner, store, downloads):
    f = write(downloads / "invoice.exe", b"MZ evil")
    vt = FakeVT(files={sha256_file(f): {"malicious": 40, "undetected": 30, "label": "trojan.agent"}})
    result = make_scanner(vt).scan(f)
    assert result.verdict is Verdict.MALICIOUS
    assert result.action.startswith("quarantined #")
    assert not f.exists()
    assert "trojan.agent" in result.reasons[0]

    (entry,) = store.quarantined()
    assert entry["original_path"] == str(f)
    assert not entry["stored_path"].endswith(".exe")
    assert restore_file(entry["id"], store) == f
    assert f.read_bytes() == b"MZ evil"
    assert store.quarantined() == []


def test_scan_without_act_does_not_move(make_scanner, downloads):
    f = write(downloads / "bad.exe", b"MZ evil")
    vt = FakeVT(files={sha256_file(f): {"malicious": 40}})
    result = make_scanner(vt).scan(f, act=False)
    assert result.verdict is Verdict.MALICIOUS
    assert result.action is None and f.exists()


def test_few_detections_is_suspicious_not_quarantined(make_scanner, downloads):
    f = write(downloads / "tool.exe", b"MZ maybe")
    vt = FakeVT(files={sha256_file(f): {"malicious": 1, "undetected": 70}})
    result = make_scanner(vt).scan(f)
    assert result.verdict is Verdict.SUSPICIOUS
    assert f.exists()


def test_unknown_unsigned_executable(make_scanner, downloads):
    f = write(downloads / "setup.bat", b"@echo off")
    result = make_scanner(FakeVT()).scan(f)
    assert result.verdict is Verdict.UNKNOWN


def test_known_but_never_scanned_is_unknown(make_scanner, downloads):
    # VirusTotal can hold a hash with no engine results (e.g. password-protected archives).
    f = write(downloads / "exercise.pcap.zip", b"PK locked")
    vt = FakeVT(files={sha256_file(f): {}})
    result = make_scanner(vt).scan(f)
    assert result.verdict is Verdict.UNKNOWN
    assert "no engine has scanned it" in result.reasons[0]


def test_unknown_document_is_clean(make_scanner, downloads):
    f = write(downloads / "photo.jpg", b"\xff\xd8\xff")
    result = make_scanner(FakeVT()).scan(f)
    assert result.verdict is Verdict.CLEAN


def test_motw_and_malicious_download_url(make_scanner, downloads):
    url = "https://bad.example.net/free-codec.zip"
    f = write(downloads / "free-codec.zip", b"PK", host_url=url)
    motw = read_motw(f)
    assert motw.zone_name == "Internet" and motw.host_url == url

    vt = FakeVT(urls={url: {"malicious": 9}})
    result = make_scanner(vt).scan(f)
    assert result.verdict is Verdict.MALICIOUS
    assert any("Download URL" in r for r in result.reasons)


def test_bad_domain_alone_only_warns(make_scanner, downloads):
    url = "https://sharehost.example/file.pdf"
    f = write(downloads / "file.pdf", b"%PDF", host_url=url)
    vt = FakeVT(domains={"sharehost.example": {"malicious": 12}})
    result = make_scanner(vt).scan(f)
    assert result.verdict is Verdict.SUSPICIOUS
    assert f.exists()


def test_bad_linking_page_warns(make_scanner, downloads):
    # A fake download page serving its file from legitimate cloud storage.
    f = write(downloads / "reader.exe", b"MZ", host_url="https://bucket.r2.cloudflarestorage.com/reader.exe?sig=x",
              referrer="https://free-pdf-reader.example/download?q=pdf")
    vt = FakeVT(domains={"free-pdf-reader.example": {"malicious": 8}})
    result = make_scanner(vt).scan(f)
    assert result.verdict is Verdict.SUSPICIOUS
    assert any("Linking page site free-pdf-reader.example" in r for r in result.reasons)
    assert f.exists()
    # Only the page's domain is sent, never its full URL.
    assert ("domain", "free-pdf-reader.example") in vt.calls
    assert not any("download?q=pdf" in target for _, target in vt.calls)


def test_stray_votes_on_a_site_are_ignored(make_scanner, downloads):
    # Real case: www.foxit.com carried 0 malicious / 1 suspicious of 92 engines.
    f = write(downloads / "reader.exe", b"MZ", host_url="https://cdn.example.com/reader.exe",
              referrer="https://www.foxit.com/")
    vt = FakeVT(files={sha256_file(f): {"undetected": 64}},
                domains={"www.foxit.com": {"suspicious": 1, "harmless": 60, "undetected": 31},
                         "cdn.example.com": {"malicious": 2, "undetected": 80}})
    result = make_scanner(vt).scan(f)
    assert result.verdict is Verdict.CLEAN


def test_linking_page_on_same_site_is_not_looked_up_twice(make_scanner, downloads):
    f = write(downloads / "a.zip", b"PK", host_url="https://example.org/a.zip", referrer="https://example.org/files")
    vt = FakeVT()
    make_scanner(vt).scan(f)
    assert vt.calls.count(("domain", "example.org")) == 1


def test_reports_are_cached(make_scanner, downloads):
    f = write(downloads / "a.txt", b"same")
    vt = FakeVT(files={sha256_file(f): {"undetected": 10}})
    scanner = make_scanner(vt)
    scanner.scan(f)
    scanner.scan(f)
    assert vt.calls.count(("file", sha256_file(f))) == 1


def test_no_api_key_reports_error(make_scanner, downloads):
    f = write(downloads / "a.exe", b"MZ")
    result = make_scanner(None).scan(f)
    assert result.verdict is Verdict.ERROR
    assert f.exists()


def test_history_is_recorded(make_scanner, store, downloads):
    f = write(downloads / "a.txt", b"x")
    make_scanner(FakeVT()).scan(f)
    (row,) = store.recent_scans()
    assert row["path"] == str(f) and row["verdict"] == "clean"


def test_toast_shows_signer_and_source(make_scanner, downloads):
    from atlas.local_checks import Signature
    from atlas.notify import toast_body

    f = write(downloads / "setup.exe", b"MZ", host_url="https://cdn.example.com/dl/setup.exe")
    result = make_scanner(FakeVT()).scan(f, act=False)
    result.signature = Signature(status="NotSigned")
    body = toast_body(result)
    assert "Not signed · From cdn.example.com via example.org" in body

    result.signature = Signature(status="Valid", signer="Example Corp")
    assert "Signed by Example Corp" in toast_body(result)


def test_short_url_drops_tokens():
    from atlas.scanner import short_url

    url = "https://bucket.r2.cloudflarestorage.com/pkg/setup.exe?X-Amz-Signature=abc123&X-Amz-Expires=7200"
    assert short_url(url) == "https://bucket.r2.cloudflarestorage.com/pkg/setup.exe"


def test_history_stores_url_without_tokens(make_scanner, store, downloads):
    f = write(downloads / "a.txt", b"x", host_url="https://cdn.example.com/a.txt?token=secret")
    make_scanner(FakeVT()).scan(f)
    assert store.recent_scans()[0]["source_url"] == "https://cdn.example.com/a.txt"


def test_url_id_matches_virustotal_format():
    assert url_id("http://www.example.com/") == "aHR0cDovL3d3dy5leGFtcGxlLmNvbS8"


def test_watcher_scans_finished_downloads_only(make_scanner, downloads, monkeypatch, tmp_path):
    monkeypatch.setattr(watcher, "SETTLE_SECONDS", 0.2)
    scanned: list[Path] = []
    scanner = make_scanner(FakeVT())
    real_scan = scanner.scan
    monkeypatch.setattr(scanner, "scan", lambda p, act=True: scanned.append(p) or real_scan(p, act))

    guard = watcher.DownloadGuard(scanner, [downloads], ignore_dirs=[tmp_path / "data"], notifications=False)
    import threading

    t = threading.Thread(target=guard.run, daemon=True)
    t.start()
    time.sleep(0.5)

    partial = downloads / "big.zip.crdownload"
    partial.write_bytes(b"PK partial")
    time.sleep(0.3)
    partial.rename(downloads / "big.zip")

    deadline = time.time() + 10
    while not scanned and time.time() < deadline:
        time.sleep(0.1)
    guard.stop()
    t.join(5)
    assert [p.name for p in scanned] == ["big.zip"]
