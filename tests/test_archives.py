"""Scanning inside ZIPs. ZIPs are built in memory; VirusTotal is faked."""

import hashlib
import io
import zipfile
from pathlib import Path

import pytest

from atlas.archives import MAX_HASHED, disguised_name, inspect_zip
from atlas.scanner import Verdict
from conftest import FakeVT

EXE = b"MZ" + b"\x90" * 500
CLEAN = {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 70}
BAD = {"malicious": 40, "suspicious": 2, "harmless": 0, "undetected": 28}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def make_zip(path, members: dict[str, bytes]):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return path


def zip_bytes(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    make_zip(buf, members)
    return buf.getvalue()


def test_known_malware_inside_a_new_zip_is_caught(tmp_path, make_scanner):
    z = make_zip(tmp_path / "invoice.zip", {"readme.txt": b"hi", "invoice.exe": EXE})
    scanner = make_scanner(FakeVT(files={sha(EXE): BAD}))
    result = scanner.scan(z)
    assert result.verdict is Verdict.MALICIOUS
    assert any("Inside the ZIP: invoice.exe" in r for r in result.reasons)
    assert result.action and result.action.startswith("quarantined")
    assert not z.exists()


def test_only_programs_inside_are_looked_up(tmp_path, make_scanner):
    z = make_zip(tmp_path / "photos.zip", {"a.jpg": b"jpg", "b.png": b"png", "tool.exe": EXE})
    vt = FakeVT(files={sha(EXE): CLEAN})
    make_scanner(vt).scan(z)
    looked_up = [t for k, t in vt.calls if k == "file"]
    assert sha(EXE) in looked_up and sha(b"jpg") not in looked_up


def test_new_zip_of_known_clean_programs_is_clean(tmp_path, make_scanner):
    z = make_zip(tmp_path / "tools.zip", {"tool.exe": EXE})
    result = make_scanner(FakeVT(files={sha(EXE): CLEAN})).scan(z)
    assert result.verdict is Verdict.CLEAN
    assert any("every program inside the ZIP is known" in r for r in result.reasons)


def test_new_zip_of_photos_is_clean(tmp_path, make_scanner):
    z = make_zip(tmp_path / "holiday.zip", {"a.jpg": b"jpg"})
    result = make_scanner(FakeVT()).scan(z)
    assert result.verdict is Verdict.CLEAN
    assert any("nothing inside the ZIP can run code" in r for r in result.reasons)


def test_unknown_program_inside_is_unknown(tmp_path, make_scanner):
    z = make_zip(tmp_path / "tools.zip", {"new.exe": EXE})
    result = make_scanner(FakeVT()).scan(z)
    assert result.verdict is Verdict.UNKNOWN
    assert any("never seen 1 program(s) inside the ZIP: new.exe" in r for r in result.reasons)


def test_nested_zip_is_opened(tmp_path, make_scanner):
    inner = zip_bytes({"payload.exe": EXE})
    z = make_zip(tmp_path / "outer.zip", {"inner.zip": inner})
    result = make_scanner(FakeVT(files={sha(EXE): BAD})).scan(z, act=False)
    assert result.verdict is Verdict.MALICIOUS
    assert any("inner.zip > payload.exe" in r for r in result.reasons)


def test_disguised_program_names():
    assert disguised_name("Invoice.pdf.exe")
    assert disguised_name("scan.JPG.scr")
    assert not disguised_name("setup.exe")
    assert not disguised_name("archive.tar.gz")
    assert not disguised_name("report.final.pdf")


def test_double_extension_is_suspicious(tmp_path, make_scanner):
    z = make_zip(tmp_path / "docs.zip", {"Invoice.pdf.exe": EXE})
    result = make_scanner(FakeVT(files={sha(EXE): CLEAN})).scan(z, act=False)
    assert result.verdict is Verdict.SUSPICIOUS
    assert any("disguised as a document" in r for r in result.reasons)


def test_password_protected_programs_are_flagged(tmp_path):
    z = make_zip(tmp_path / "locked.zip", {"setup.exe": EXE, "notes.txt": b"x"})
    raw = bytearray(z.read_bytes())
    # Set the "encrypted" flag on every entry, as a password-protected ZIP would have.
    for sig in (b"PK\x03\x04", b"PK\x01\x02"):
        start = 0
        while (i := raw.find(sig, start)) != -1:
            flag_at = i + (6 if sig == b"PK\x03\x04" else 8)
            raw[flag_at] |= 1
            start = i + 4
    z.write_bytes(bytes(raw))
    listing = inspect_zip(z)
    assert all(m.encrypted and m.sha256 is None for m in listing.members)
    assert any("Password-protected ZIP holding programs (setup.exe)" in p for p in listing.problems)


def test_zip_bomb_is_not_expanded(tmp_path):
    z = tmp_path / "bomb.zip"
    with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as zf:
        with zf.open("huge.exe", "w", force_zip64=True) as fh:
            chunk = bytes(1024 * 1024)
            for _ in range(150):
                fh.write(chunk)  # 150 MB of zeros squeezes into well under 1 MB
    listing = inspect_zip(z)
    assert listing.members[0].sha256 is None
    assert any("zip bomb" in p for p in listing.problems)


def test_lookups_are_capped(tmp_path):
    z = make_zip(tmp_path / "many.zip", {f"tool{i}.exe": EXE + bytes([i]) for i in range(MAX_HASHED + 5)})
    listing = inspect_zip(z)
    assert len(listing.hashed) == MAX_HASHED
    assert any(f"first {MAX_HASHED} programs" in n for n in listing.notes)


@pytest.mark.parametrize("name", ["setup.exe", "app.jar", "tool.msix"])
def test_programs_that_are_zips_underneath_are_not_vouched_for(tmp_path, make_scanner, name):
    # e.g. a self-extracting installer: a program with a ZIP of harmless-looking files attached
    f = tmp_path / name
    f.write_bytes(EXE + zip_bytes({"__main__.py": b"print('hi')", "readme.txt": b"x"}))
    result = make_scanner(FakeVT()).scan(f, act=False)
    assert result.verdict is Verdict.UNKNOWN
    assert not any("inside the ZIP" in r for r in result.reasons)


def test_broken_zip_is_reported_not_crashed(tmp_path, make_scanner):
    z = tmp_path / "broken.zip"
    z.write_bytes(zip_bytes({"a.exe": EXE})[:-30])  # chop off the directory at the end
    result = make_scanner(FakeVT()).scan(z, act=False)
    assert result.verdict is Verdict.UNKNOWN  # a new ZIP Atlas couldn't see inside


# --- 7z, RAR and ISO ------------------------------------------------------------------

import subprocess  # noqa: E402

from atlas import archives  # noqa: E402

SEVEN = archives.find_7zip()
needs_7zip = pytest.mark.skipif(SEVEN is None, reason="7-Zip isn't installed")


def make_7z(path, members: dict[str, bytes], password: str | None = None, hide_names: bool = False):
    src = path.parent / (path.stem + "_src")
    src.mkdir()
    for name, data in members.items():
        (src / name).parent.mkdir(parents=True, exist_ok=True)
        (src / name).write_bytes(data)
    args = [SEVEN, "a", "-bd", str(path), str(src / "*")]
    if password:
        args.append(f"-p{password}")
    if hide_names:
        args.append("-mhe=on")
    subprocess.run(args, check=True, capture_output=True)
    return path


@needs_7zip
def test_malware_inside_a_7z_is_caught(tmp_path, make_scanner):
    z = make_7z(tmp_path / "invoice.7z", {"docs/readme.txt": b"hi", "docs/invoice.exe": EXE})
    result = make_scanner(FakeVT(files={sha(EXE): BAD})).scan(z, act=False)
    assert result.verdict is Verdict.MALICIOUS
    assert any("Inside the 7z archive: docs/invoice.exe" in r for r in result.reasons)


@needs_7zip
def test_new_7z_of_known_clean_programs_is_clean(tmp_path, make_scanner):
    z = make_7z(tmp_path / "tools.7z", {"tool.exe": EXE, "notes.txt": b"x"})
    result = make_scanner(FakeVT(files={sha(EXE): CLEAN})).scan(z, act=False)
    assert result.verdict is Verdict.CLEAN
    assert any("every program inside the 7z archive is known" in r for r in result.reasons)


@needs_7zip
def test_password_protected_7z_with_programs_is_suspicious(tmp_path):
    z = make_7z(tmp_path / "locked.7z", {"setup.exe": EXE}, password="infected")
    listing = archives.inspect(z)
    assert listing.members and listing.members[0].encrypted and listing.members[0].sha256 is None
    assert any("Password-protected 7z archive holding programs (setup.exe)" in p for p in listing.problems)


@needs_7zip
def test_7z_with_hidden_names_never_hangs_and_is_not_vouched(tmp_path, make_scanner):
    z = make_7z(tmp_path / "hidden.7z", {"setup.exe": EXE}, password="infected", hide_names=True)
    result = make_scanner(FakeVT()).scan(z, act=False)  # would hang here if 7-Zip asked for a password
    assert result.verdict is Verdict.UNKNOWN
    assert any("password-protected, file names and all" in r for r in result.reasons)


@needs_7zip
def test_built_in_tar_is_the_fallback(tmp_path, monkeypatch, make_scanner):
    z = make_7z(tmp_path / "tools.7z", {"tool.exe": EXE})
    monkeypatch.setattr(archives, "find_7zip", lambda: None)
    result = make_scanner(FakeVT(files={sha(EXE): BAD})).scan(z, act=False)
    assert result.verdict is Verdict.MALICIOUS


def test_disc_image_tar_cannot_read_is_never_called_empty(tmp_path, monkeypatch, make_scanner):
    # Windows' tar lists UDF disc images (most modern ISOs) as having no files at all.
    iso = tmp_path / "course.iso"
    iso.write_bytes(bytes(200 * 1024))
    monkeypatch.setattr(archives, "find_7zip", lambda: None)
    monkeypatch.setattr(archives, "_list_tar", lambda tar, path: ([], None))
    result = make_scanner(FakeVT()).scan(iso, act=False)
    assert result.verdict is Verdict.UNKNOWN
    assert any("Couldn't see any files inside this disc image" in r and "7-Zip" in r for r in result.reasons)
    assert not any("none of which can run code" in r for r in result.reasons)


def test_7zip_listing_is_parsed(monkeypatch):
    out = ("Path = setup\\Install.exe\nFolder = -\nSize = 1234\nEncrypted = -\n\n"
           "Path = setup\nFolder = +\nSize = 0\n\n"
           "Path = secret.dll\nSize = 99\nEncrypted = +\nAttributes = A\n\n")
    monkeypatch.setattr(archives, "_run",
                        lambda args, timeout=0: subprocess.CompletedProcess(args, 0, out.encode(), b""))
    members, error = archives._list_7zip("7z.exe", Path("x.7z"))
    assert error is None
    assert [(m.name, m.size, m.encrypted) for m in members] == [("setup/Install.exe", 1234, False),
                                                                ("secret.dll", 99, True)]
