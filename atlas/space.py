"""Disk space: duplicate files and big files you may no longer need.

Safety rules this module follows:

- Cloud-only OneDrive files are never opened. Reading one makes OneDrive download it, so
  they're matched by name and size only and labelled "not compared".
- Duplicates are confirmed byte-for-byte (SHA-256) before they're called duplicates.
  Hashes are cached by path, size and modified time, so rescans are quick.
- Disks used by a registered VirtualBox or VMware virtual machine are never touched.
- Files too big for the Recycle Bin aren't recycled: Windows would silently delete them
  for good. Move them to another folder or drive instead.
- At least one copy of every duplicate is always kept.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import shutil
import subprocess
import sys
import threading
import xml.etree.ElementTree as ET
from collections import defaultdict
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)

NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
MB = 1024 * 1024
GB = 1024 * MB

# Windows file attributes used by OneDrive and other cloud storage.
FILE_ATTRIBUTE_OFFLINE = 0x1000
FILE_ATTRIBUTE_RECALL_ON_OPEN = 0x40000
FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x400000
CLOUD_ONLY = FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_RECALL_ON_OPEN | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS

# Folders never worth walking: app internals, code dependencies, caches.
SKIP_DIRS = {"appdata", ".venv", "venv", "node_modules", ".git", "site-packages", "__pycache__",
             "$recycle.bin", ".cache", ".nuget", ".gradle", ".m2", ".cargo", ".rustup"}

KINDS = {
    "Disk image": {".iso", ".img", ".dmg", ".sqfs", ".squashfs"},
    "VM disk": {".vdi", ".vmdk", ".vhd", ".vhdx", ".qcow2", ".ova", ".ovf"},
    "Archive": {".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".xz", ".bz2", ".zst"},
    "Video": {".mp4", ".mkv", ".mov", ".avi", ".wmv", ".webm", ".m4v"},
    "Installer": {".exe", ".msi", ".msix", ".appx"},
    "Backup": {".bak", ".backup", ".pst", ".ost"},
}


class Cancelled(Exception):
    pass


@dataclass
class FileInfo:
    path: Path
    size: int
    mtime: float
    atime: float
    cloud_only: bool = False
    in_onedrive: bool = False
    used_by_vm: str | None = None  # name of the VM this disk belongs to
    selected: bool = False

    @property
    def disk_size(self) -> int:
        """Space it actually takes on this PC (cloud-only files take none)."""
        return 0 if self.cloud_only else self.size

    @property
    def last_used(self) -> float:
        return max(self.mtime, self.atime)

    @property
    def kind(self) -> str:
        ext = self.path.suffix.lower()
        return next((k for k, exts in KINDS.items() if ext in exts), "Other")

    @property
    def where(self) -> str:
        if self.cloud_only:
            return "OneDrive (online only)"
        return "OneDrive (on this PC)" if self.in_onedrive else "This PC"


@dataclass
class DuplicateGroup:
    files: list[FileInfo]
    verified: bool  # True: identical byte-for-byte. False: same name and size, a cloud copy wasn't compared.

    @property
    def size(self) -> int:
        return self.files[0].size

    @property
    def reclaimable(self) -> int:
        """Space freed by keeping one copy. A cloud-only copy can be the one kept, freeing all local copies."""
        local = [f.disk_size for f in self.files if not f.cloud_only]
        if not local:
            return 0
        return sum(local) - (0 if any(f.cloud_only for f in self.files) else max(local))


def onedrive_roots() -> list[Path]:
    roots = {os.environ.get(v) for v in ("OneDrive", "OneDriveConsumer", "OneDriveCommercial")}
    return [Path(r) for r in roots if r]


def _inside_any(path: Path, roots: list[Path]) -> bool:
    return any(path.is_relative_to(r) for r in roots)


def walk(roots: list[Path], min_size: int, cancel: threading.Event | None = None,
         progress: Callable[[str], None] | None = None, skip: list[Path] = ()) -> list[FileInfo]:
    """Every file of at least min_size under roots. Never opens files; never follows links."""
    onedrive = onedrive_roots()
    skip = [Path(s) for s in skip]
    found: list[FileInfo] = []
    seen_dirs = 0
    stack = [Path(r) for r in roots if Path(r).is_dir()]
    while stack:
        if cancel and cancel.is_set():
            raise Cancelled
        folder = stack.pop()
        seen_dirs += 1
        if progress and seen_dirs % 500 == 0:
            progress(f"Looking through folders... {seen_dirs:,} checked, {len(found):,} candidates")
        try:
            entries = os.scandir(folder)
        except OSError:
            continue
        with entries:
            for e in entries:
                try:
                    if e.is_dir(follow_symlinks=False):
                        if e.name.lower() not in SKIP_DIRS and not e.is_junction() and not e.is_symlink() \
                                and not _inside_any(Path(e.path), skip):
                            stack.append(Path(e.path))
                        continue
                    if e.is_symlink():
                        continue
                    st = e.stat(follow_symlinks=False)
                    if st.st_size < min_size:
                        continue
                    attrs = getattr(st, "st_file_attributes", 0)
                    path = Path(e.path)
                    found.append(FileInfo(path, st.st_size, st.st_mtime, st.st_atime,
                                          cloud_only=bool(attrs & CLOUD_ONLY),
                                          in_onedrive=_inside_any(path, onedrive)))
                except OSError:
                    continue
    return found


# --- Hashing ----------------------------------------------------------------------

CHUNK = 8 * MB
SAMPLE = 1 * MB


@contextmanager
def _reading(path: Path) -> Iterator:
    """Open a file for hashing without changing its "last used" date.

    Reading updates the last-access time, which would make every compared file look used today.
    """
    st = path.stat()
    try:
        with path.open("rb") as fh:
            yield fh
    finally:
        try:
            os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns))
        except OSError:
            pass


def quick_fingerprint(path: Path, size: int) -> str:
    """Hash of three 1 MB samples (start, middle, end). Cheap way to rule out most same-size files."""
    h = hashlib.sha256()
    with _reading(path) as fh:
        for offset in sorted({0, max(0, size // 2 - SAMPLE // 2), max(0, size - SAMPLE)}):
            fh.seek(offset)
            h.update(fh.read(SAMPLE))
    return h.hexdigest()


def full_hash(path: Path, cancel: threading.Event | None = None,
              on_bytes: Callable[[int], None] | None = None) -> str:
    h = hashlib.sha256()
    with _reading(path) as fh:
        while block := fh.read(CHUNK):
            if cancel and cancel.is_set():
                raise Cancelled
            h.update(block)
            if on_bytes:
                on_bytes(len(block))
    return h.hexdigest()


def find_duplicates(files: list[FileInfo], hash_cache=None, cancel: threading.Event | None = None,
                    progress: Callable[[str], None] | None = None) -> list[DuplicateGroup]:
    """Group identical files. `hash_cache` (a Store) remembers full hashes between scans."""
    by_size: dict[int, list[FileInfo]] = defaultdict(list)
    for f in files:
        by_size[f.size].append(f)
    candidates = [g for g in by_size.values() if len(g) > 1]

    # Work out how much reading full hashes will take, for progress.
    to_hash = []
    groups: list[DuplicateGroup] = []
    for same_size in candidates:
        local = [f for f in same_size if not f.cloud_only]
        by_quick: dict[str, list[FileInfo]] = defaultdict(list)
        for f in local:
            if cancel and cancel.is_set():
                raise Cancelled
            try:
                by_quick[quick_fingerprint(f.path, f.size)].append(f)
            except OSError:
                continue
        to_hash += [g for g in by_quick.values() if len(g) > 1]

    total = sum(f.size for g in to_hash for f in g)
    done = 0

    def advance(n: int) -> None:
        nonlocal done
        done += n
        if progress and total:
            progress(f"Comparing possible duplicates byte-for-byte... {done / GB:.1f} of {total / GB:.1f} GB")

    verified_paths: set[Path] = set()
    for group in to_hash:
        by_hash: dict[str, list[FileInfo]] = defaultdict(list)
        for f in group:
            cached = hash_cache.cached_hash(str(f.path), f.size, f.mtime) if hash_cache else None
            try:
                digest = cached or full_hash(f.path, cancel, advance)
            except OSError:
                continue
            if cached:
                advance(f.size)
            elif hash_cache:
                hash_cache.cache_hash(str(f.path), f.size, f.mtime, digest)
            by_hash[digest].append(f)
        for same in by_hash.values():
            if len(same) > 1:
                groups.append(DuplicateGroup(same, verified=True))
                verified_paths.update(f.path for f in same)

    # Cloud-only copies can't be compared without downloading them: match on name and size.
    for same_size in candidates:
        cloud = [f for f in same_size if f.cloud_only]
        if not cloud:
            continue
        by_name: dict[str, list[FileInfo]] = defaultdict(list)
        for f in same_size:
            by_name[f.path.name.lower()].append(f)
        for named in by_name.values():
            if len(named) < 2 or not any(f.cloud_only for f in named):
                continue
            existing = next((g for g in groups if any(f in g.files for f in named if not f.cloud_only)), None)
            if existing:
                existing.files += [f for f in named if f.cloud_only and f not in existing.files]
                existing.verified = False
            else:
                groups.append(DuplicateGroup(named, verified=False))

    groups.sort(key=lambda g: -g.reclaimable)
    return groups


def big_files(files: list[FileInfo], min_size: int) -> list[FileInfo]:
    return sorted((f for f in files if f.size >= min_size), key=lambda f: -f.size)


# --- Virtual machine disks --------------------------------------------------------

def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def virtualbox_disks(home: Path | None = None) -> dict[str, str]:
    """Disk path (lower-case) -> VM name, for VMs registered in VirtualBox."""
    home = home or Path.home()
    disks: dict[str, str] = {}
    registry = home / ".VirtualBox" / "VirtualBox.xml"
    if not registry.exists():
        return disks
    try:
        machines = [e.get("src") for e in ET.parse(registry).iter() if _local_name(e.tag) == "MachineEntry"]
    except ET.ParseError:
        return disks
    for src in filter(None, machines):
        vbox = Path(src)
        try:
            tree = ET.parse(vbox)
        except (OSError, ET.ParseError):
            continue
        name = next((e.get("name") for e in tree.iter() if _local_name(e.tag) == "Machine"), vbox.stem)
        for e in tree.iter():
            if _local_name(e.tag) == "HardDisk" and e.get("location"):
                disk = Path(e.get("location"))
                disk = disk if disk.is_absolute() else vbox.parent / disk
                disks[str(disk).lower()] = f"VirtualBox VM \"{name}\""
    return disks


_VMX_DISK = re.compile(r'^\s*(?:scsi|sata|nvme|ide)\d+:\d+\.fileName\s*=\s*"([^"]+\.vmdk)"', re.I | re.M)
_VMX_NAME = re.compile(r'^\s*displayName\s*=\s*"([^"]*)"', re.I | re.M)
_VMLS_CONFIG = re.compile(r'^\s*vmlist\d+\.config\s*=\s*"([^"]+)"', re.I | re.M)


def vmware_disks(appdata: Path | None = None) -> dict[str, str]:
    appdata = appdata or Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    disks: dict[str, str] = {}
    inventory = appdata / "VMware" / "inventory.vmls"
    try:
        configs = _VMLS_CONFIG.findall(inventory.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return disks
    for config in configs:
        vmx = Path(config)
        try:
            text = vmx.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        name = (_VMX_NAME.search(text) or [None, vmx.stem])[1]
        for disk in _VMX_DISK.findall(text):
            path = Path(disk) if Path(disk).is_absolute() else vmx.parent / disk
            disks[str(path).lower()] = f"VMware VM \"{name}\""
    return disks


def mark_vm_disks(files: list[FileInfo]) -> None:
    disks = {**virtualbox_disks(), **vmware_disks()}
    for f in files:
        f.used_by_vm = disks.get(str(f.path).lower())


# --- Actions ----------------------------------------------------------------------

def recycle_bin_limit(path: Path) -> int | None:
    """Most the Recycle Bin on this file's drive will hold, in bytes. 0 if recycling is off; None if unknown."""
    if sys.platform != "win32":
        return None
    import ctypes
    import winreg

    buf = ctypes.create_unicode_buffer(64)
    if not ctypes.windll.kernel32.GetVolumeNameForVolumeMountPointW(path.anchor, buf, 64):
        return None
    guid = re.search(r"\{[0-9A-Fa-f-]+\}", buf.value)
    if not guid:
        return None
    key = rf"Software\Microsoft\Windows\CurrentVersion\Explorer\BitBucket\Volume\{guid.group(0)}"
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key) as k:
            values = {}
            for name in ("MaxCapacity", "NukeOnDelete"):
                try:
                    values[name] = winreg.QueryValueEx(k, name)[0]
                except OSError:
                    pass
    except OSError:
        return None
    if values.get("NukeOnDelete"):
        return 0
    return values["MaxCapacity"] * MB if "MaxCapacity" in values else None


def blocked_reason(f: FileInfo, action: str, recycle_limit: int | None = None) -> str | None:
    """Why `action` ("recycle", "move" or "free") can't be done to this file, or None if it can."""
    if f.used_by_vm:
        return f"Disk of {f.used_by_vm}: remove the VM in its own app instead, or it will break"
    if action == "free":
        if not f.in_onedrive:
            return "Not in OneDrive"
        if f.cloud_only:
            return "Already online only"
        return None
    if f.cloud_only and action == "move":
        return "Online-only OneDrive file: it would have to download first"
    if action == "recycle":
        if recycle_limit == 0:
            return "The Recycle Bin is turned off for this drive"
        if recycle_limit is None and f.disk_size > GB:
            return "Recycle Bin size limit unknown: use Move to folder instead"
        if recycle_limit is not None and f.disk_size > recycle_limit:
            return (f"Too big for the Recycle Bin (limit {recycle_limit / GB:.0f} GB): Windows would delete it "
                    "for good. Use Move to folder instead")
    return None


def recycle(f: FileInfo) -> None:
    from send2trash import send2trash

    send2trash(str(f.path))


def move_to(f: FileInfo, folder: Path) -> Path:
    dest = folder / f.path.name
    n = 1
    while dest.exists():
        dest = folder / f"{f.path.stem} ({n}){f.path.suffix}"
        n += 1
    shutil.move(str(f.path), str(dest))
    return dest


def free_up_space(f: FileInfo) -> None:
    """OneDrive's "Free up space": keep the file in the cloud, remove the local copy."""
    subprocess.run(["attrib", "+U", "-P", str(f.path)], check=True, capture_output=True, creationflags=NO_WINDOW)


def keeps_a_copy(group: DuplicateGroup, removing: set[Path]) -> bool:
    return any(f.path not in removing for f in group.files)


@dataclass
class ActionResult:
    done: int = 0
    freed: int = 0
    skipped: list[str] = field(default_factory=list)


def apply(action: str, files: list[FileInfo], groups: list[DuplicateGroup] = (),
          folder: Path | None = None, on_done: Callable[[FileInfo, int], None] | None = None) -> ActionResult:
    """Do `action` to each file, skipping blocked ones and any that would remove a duplicate's last copy."""
    result = ActionResult()
    removing = {f.path for f in files} if action in ("recycle", "move") else set()
    unsafe = set()
    for g in groups:
        if not keeps_a_copy(g, removing):
            unsafe.update(f.path for f in g.files)
    limits: dict[str, int | None] = {}
    for f in files:
        if f.path in unsafe:
            result.skipped.append(f"{f.path.name}: every copy was selected; at least one is always kept")
            continue
        limit = None
        if action == "recycle":
            anchor = f.path.anchor
            if anchor not in limits:
                limits[anchor] = recycle_bin_limit(f.path)
            limit = limits[anchor]
        reason = blocked_reason(f, action, limit)
        if reason:
            result.skipped.append(f"{f.path.name}: {reason}")
            continue
        try:
            if action == "recycle":
                recycle(f)
            elif action == "move":
                move_to(f, folder)
            elif action == "free":
                free_up_space(f)
            else:
                raise ValueError(action)
            freed = f.disk_size if not (action == "move" and folder and folder.anchor == f.path.anchor) else 0
            result.done += 1
            result.freed += freed
            log.info("Disk space: %s %s (%d bytes)", action, f.path, freed)
            if on_done:
                on_done(f, freed)
        except Exception as exc:
            result.skipped.append(f"{f.path.name}: {exc}")
    return result
