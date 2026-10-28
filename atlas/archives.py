"""Look inside ZIP, 7z, RAR and ISO files without extracting them.

Malware is often delivered zipped: the ZIP itself is new to VirusTotal (it was just
made), while the program inside is well known. So the guard hashes the files inside
that can run code and looks those up too.

Nothing is written to disk. Members are streamed and hashed in memory, with limits so
a "zip bomb" (a tiny ZIP that expands to terabytes) can't hang or fill the machine.

ZIPs are read with Python's own zipfile. 7z, RAR and ISO use 7-Zip when it's installed,
otherwise Windows' built-in tar. tar can't read UDF disc images (most modern ISOs) and
reports them as empty, so an empty listing of a non-empty file is treated as "couldn't
see inside", never as "nothing inside".
"""

from __future__ import annotations

import hashlib
import io
import os
import re
import shutil
import subprocess
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from atlas.local_checks import RISKY_EXTENSIONS

MB = 1024 * 1024
MAX_MEMBERS = 2000  # entries listed
MAX_HASHED = 25  # inner files looked up on VirusTotal (each lookup uses API quota)
MAX_MEMBER_SIZE = 512 * MB  # bigger inner files are listed but not hashed
MAX_TOTAL = 2048 * MB  # total bytes decompressed per ZIP, nested ones included
MAX_RATIO = 200  # compressed -> uncompressed growth that marks a zip bomb
MAX_DEPTH = 2  # ZIPs inside ZIPs inside ZIPs

# Document types people expect to open, which a program can pretend to be.
DECOY_EXTENSIONS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".jpg", ".jpeg", ".png", ".mp3",
                    ".mp4", ".rtf", ".csv", ".ppt", ".pptx"}


@dataclass
class Member:
    name: str  # path inside the archive, e.g. "setup/Invoice.pdf.exe" or "outer.zip > inner.exe"
    size: int
    sha256: str | None = None  # None when not hashed (not risky, too big, encrypted, over the limit)
    encrypted: bool = False


@dataclass
class ZipListing:
    kind: str = "ZIP"  # how messages name it: "ZIP", "7z archive", "RAR archive", "disc image"
    members: list[Member] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)  # reasons to be wary, independent of VirusTotal
    notes: list[str] = field(default_factory=list)  # limits hit, things that couldn't be checked

    @property
    def hashed(self) -> list[Member]:
        return [m for m in self.members if m.sha256]

    @property
    def risky(self) -> list[Member]:
        return [m for m in self.members if _risky(m.name)]


def _risky(name: str) -> bool:
    return PurePosixPath(name).suffix.lower() in RISKY_EXTENSIONS


def disguised_name(name: str) -> bool:
    """True for e.g. "Invoice.pdf.exe" or "photo.jpg      .scr": a program dressed up as a document."""
    p = PurePosixPath(name.rstrip())
    suffixes = [s.lower().strip() for s in p.suffixes]
    return len(suffixes) >= 2 and suffixes[-1] in RISKY_EXTENSIONS and suffixes[-2] in DECOY_EXTENSIONS


def is_zip(path: Path) -> bool:
    """A plain .zip archive. Many other files are ZIPs underneath (self-extracting .exe installers,
    .jar, .msix, .docm) but run code themselves, so their contents must never vouch for them."""
    if path.suffix.lower() != ".zip":
        return False
    try:
        return zipfile.is_zipfile(path)
    except OSError:
        return False


def inspect_zip(path: Path) -> ZipListing:
    listing = ZipListing()
    budget = [MAX_TOTAL]
    try:
        with zipfile.ZipFile(path) as zf:
            _walk(zf, "", 0, listing, budget)
    except (zipfile.BadZipFile, OSError, RuntimeError, NotImplementedError) as exc:
        listing.notes.append(f"The ZIP could not be fully read: {exc}")
    return listing


def _hash(zf: zipfile.ZipFile, info: zipfile.ZipInfo, budget: list[int]) -> tuple[str, bytes | None]:
    """SHA-256 of a member, plus its bytes if it's a small nested ZIP worth opening."""
    h = hashlib.sha256()
    keep = info.filename.lower().endswith(".zip") and info.file_size <= 64 * MB
    kept = bytearray() if keep else None
    read = 0
    with zf.open(info) as fh:
        while block := fh.read(MB):
            read += len(block)
            budget[0] -= len(block)
            # file_size comes from the archive and can lie; count what actually comes out.
            if read > MAX_MEMBER_SIZE or budget[0] < 0:
                raise OverflowError("expands to far more than it says")
            h.update(block)
            if kept is not None:
                kept += block
    return h.hexdigest(), bytes(kept) if kept is not None else None


def _walk(zf: zipfile.ZipFile, prefix: str, depth: int, listing: ZipListing, budget: list[int]) -> None:
    infos = [i for i in zf.infolist() if not i.is_dir()]
    if len(infos) > MAX_MEMBERS:
        listing.notes.append(f"Only the first {MAX_MEMBERS} of {len(infos)} files inside were checked")
        infos = infos[:MAX_MEMBERS]
    for info in infos:
        name = prefix + info.filename
        member = Member(name, info.file_size, encrypted=bool(info.flag_bits & 0x1))
        listing.members.append(member)
        if disguised_name(info.filename):
            listing.problems.append(f"{name} is a program disguised as a document (double extension)")
        nested = info.filename.lower().endswith(".zip")
        if not (_risky(info.filename) or nested) or member.encrypted:
            continue
        if info.compress_size and info.file_size / info.compress_size > MAX_RATIO and info.file_size > 100 * MB:
            listing.problems.append(f"{name} looks like a zip bomb: {info.compress_size:,} bytes that "
                                    f"expand to {info.file_size:,}")
            continue
        if info.file_size > MAX_MEMBER_SIZE:
            listing.notes.append(f"{name} is too big to check inside the ZIP ({info.file_size // MB} MB)")
            continue
        if len(listing.hashed) >= MAX_HASHED:
            listing.notes.append(f"Only the first {MAX_HASHED} programs inside were looked up")
            break
        try:
            member.sha256, data = _hash(zf, info, budget)
        except OverflowError as exc:
            listing.problems.append(f"{name} {exc}: possibly a zip bomb")
            return
        except (zipfile.BadZipFile, OSError, RuntimeError, NotImplementedError, EOFError) as exc:
            listing.notes.append(f"{name} could not be read: {exc}")
            continue
        if data is not None:
            if depth + 1 >= MAX_DEPTH:
                listing.notes.append(f"{name} is a ZIP nested too deep to open")
                continue
            try:
                with zipfile.ZipFile(io.BytesIO(data)) as inner:
                    _walk(inner, f"{name} > ", depth + 1, listing, budget)
            except zipfile.BadZipFile:
                pass

    encrypted_risky = [m.name for m in listing.members if m.encrypted and _risky(m.name)]
    if depth == 0 and encrypted_risky:
        listing.problems.append(
            "Password-protected ZIP holding programs (" + ", ".join(encrypted_risky[:3]) +
            "). Scanners can't see inside, which is why malware is often sent this way")


# --- 7z, RAR and ISO (via 7-Zip or Windows' tar) -----------------------------------

OTHER_ARCHIVES = {".7z": "7z archive", ".rar": "RAR archive", ".iso": "disc image"}
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
LIST_TIMEOUT = 120


def find_7zip() -> str | None:
    for base in (os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)"), os.environ.get("ProgramW6432")):
        if base and Path(base, "7-Zip", "7z.exe").is_file():
            return str(Path(base, "7-Zip", "7z.exe"))
    return shutil.which("7z")


def find_tar() -> str | None:
    system = Path(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "tar.exe")
    return str(system) if system.is_file() else shutil.which("tar")


def can_inspect(path: Path) -> bool:
    return is_zip(path) or path.suffix.lower() in OTHER_ARCHIVES


def inspect(path: Path) -> ZipListing:
    """List and hash the programs inside any supported archive."""
    if is_zip(path):
        return inspect_zip(path)
    listing = ZipListing(kind=OTHER_ARCHIVES.get(path.suffix.lower(), "archive"))
    seven, tar = find_7zip(), find_tar()
    if seven:
        entries, error = _list_7zip(seven, path)
        extract = lambda name: [seven, "e", "-so", "-spd", "-pAtlasNoPassword", "-bd", str(path), name]
    elif tar:
        entries, error = _list_tar(tar, path)
        extract = lambda name: [tar, "-xOf", str(path), name]
    else:
        listing.notes.append(f"Couldn't look inside this {listing.kind}: neither 7-Zip nor Windows' tar is available")
        return listing
    if error:
        listing.notes.append(f"Couldn't look inside this {listing.kind}: {error}")
        return listing
    if not entries:
        if path.stat().st_size > 64 * 1024:
            hint = "" if seven else " Installing 7-Zip lets Atlas read every kind of disc image."
            listing.notes.append(f"Couldn't see any files inside this {listing.kind}.{hint}")
        return listing
    if len(entries) > MAX_MEMBERS:
        listing.notes.append(f"Only the first {MAX_MEMBERS} of {len(entries)} files inside were checked")
        entries = entries[:MAX_MEMBERS]
    budget = [MAX_TOTAL]
    for member in entries:
        listing.members.append(member)
        if disguised_name(member.name):
            listing.problems.append(f"{member.name} is a program disguised as a document (double extension)")
        if not _risky(member.name) or member.encrypted:
            continue
        if member.size > MAX_MEMBER_SIZE:
            listing.notes.append(f"{member.name} is too big to check inside the {listing.kind} "
                                 f"({member.size // MB} MB)")
            continue
        if len(listing.hashed) >= MAX_HASHED:
            listing.notes.append(f"Only the first {MAX_HASHED} programs inside were looked up")
            break
        try:
            member.sha256 = _hash_stream(extract(member.name), budget)
        except OverflowError as exc:
            listing.problems.append(f"{member.name} {exc}: possibly an archive bomb")
            break
        except (OSError, subprocess.SubprocessError) as exc:
            listing.notes.append(f"{member.name} could not be read: {exc}")
    encrypted_risky = [m.name for m in listing.members if m.encrypted and _risky(m.name)]
    if encrypted_risky:
        listing.problems.append(
            f"Password-protected {listing.kind} holding programs (" + ", ".join(encrypted_risky[:3]) +
            "). Scanners can't see inside, which is why malware is often sent this way")
    return listing


def _run(args: list[str], timeout: int = LIST_TIMEOUT) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, stdin=subprocess.DEVNULL, timeout=timeout,
                          creationflags=NO_WINDOW)


def _list_7zip(seven: str, path: Path) -> tuple[list[Member], str | None]:
    # -slt: one "Key = value" block per entry; -p: a dummy password, so it can never stop and ask
    try:
        out = _run([seven, "l", "-slt", "-ba", "-pAtlasNoPassword", str(path)])
    except subprocess.TimeoutExpired:
        return [], "listing took too long"
    text = out.stdout.decode("utf-8", "replace")
    if out.returncode != 0 and not text.strip():
        err = out.stderr.decode("utf-8", "replace")
        if "password" in err.lower() or "encrypted" in err.lower():
            return [], "it is password-protected, file names and all"
        return [], (err.strip().splitlines() or ["7-Zip could not open it"])[-1]
    members = []
    for block in re.split(r"\r?\n\r?\n", text):
        fields = dict(line.split(" = ", 1) for line in block.splitlines() if " = " in line)
        if not fields.get("Path") or fields.get("Folder") == "+" or "D" in fields.get("Attributes", "")[:1]:
            continue
        members.append(Member(fields["Path"].replace("\\", "/"), int(fields.get("Size") or 0),
                              encrypted=fields.get("Encrypted") == "+"))
    return members, None


def _list_tar(tar: str, path: Path) -> tuple[list[Member], str | None]:
    try:
        out = _run([tar, "-tvf", str(path)])
    except subprocess.TimeoutExpired:
        return [], "listing took too long"
    if out.returncode != 0:
        err = out.stderr.decode("utf-8", "replace").strip()
        return [], (err.splitlines() or ["tar could not open it"])[-1]
    members = []
    for line in out.stdout.decode("utf-8", "replace").splitlines():
        # -rw-r--r--  0 0      0           8 Oct 27 19:28 a.exe
        parts = line.split(None, 8)
        if len(parts) == 9 and not line.startswith("d"):
            members.append(Member(parts[8], int(parts[4]) if parts[4].isdigit() else 0))
    return members, None


def _hash_stream(args: list[str], budget: list[int]) -> str:
    """SHA-256 of a member extracted to a pipe (never to disk), stopping at the size limits."""
    h = hashlib.sha256()
    read = 0
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
                            creationflags=NO_WINDOW)
    try:
        while block := proc.stdout.read(MB):
            read += len(block)
            budget[0] -= len(block)
            if read > MAX_MEMBER_SIZE or budget[0] < 0:
                raise OverflowError("expands to far more than it says")
            h.update(block)
        if proc.wait(timeout=60) != 0 and read == 0:
            raise OSError("the archive tool could not extract it")
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.stdout.close()
    return h.hexdigest()
