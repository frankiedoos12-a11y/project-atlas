"""Find and remove junk: files and entries that are safe to delete or no longer have a home.

Two kinds of junk, handled differently:

- Things that rebuild themselves (temp files, browser caches, crash dumps) are deleted.
  Anything changed in the last day is left alone, since a program may still be using it.
- Things with no home (startup entries for deleted programs, old installers, app data
  left behind by uninstalled programs) go to the Recycle Bin, or for registry entries,
  are backed up to a .reg file first. Most of these are never pre-selected: you decide.

Scanning only reads. Nothing is removed until clean() is called with the chosen items.
"""

from __future__ import annotations

import csv
import io
import logging
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from atlas.config import FOLDER_DOWNLOADS, known_folder

if sys.platform == "win32":
    import winreg

log = logging.getLogger(__name__)

DAY = 86400
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

HOW_LABELS = {
    "delete": "Delete (rebuilds itself)",
    "contents": "Empty folder (rebuilds itself)",
    "recycle": "Move to Recycle Bin",
    "registry": "Remove entry (backup saved)",
    "empty-bin": "Empty for good (can't be undone)",
}


@dataclass
class JunkItem:
    label: str
    path: Path | None
    size: int = 0
    detail: str = ""
    how: str = "delete"  # a key of HOW_LABELS
    root: Path | None = None  # "delete"/"contents" items must stay inside this folder
    registry: tuple[str, str, str] | None = None  # (hive, key, value name) for how="registry"
    blocked: str | None = None  # why it can't be removed right now
    selected: bool = True


@dataclass
class JunkCategory:
    id: str
    title: str
    description: str
    items: list[JunkItem] = field(default_factory=list)

    @property
    def size(self) -> int:
        return sum(i.size for i in self.items if not i.blocked)

    @property
    def blocked_size(self) -> int:
        """Space that could be freed once whatever is blocking it (e.g. an open browser) is closed."""
        return sum(i.size for i in self.items if i.blocked)


@dataclass
class CleanResult:
    freed: int = 0
    removed: int = 0
    skipped: list[str] = field(default_factory=list)
    backups: list[Path] = field(default_factory=list)


def human_size(n: int) -> str:
    size = float(n)
    for unit in ("bytes", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "bytes" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"


def _date(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d") if ts else "unknown"


def _local() -> Path:
    return Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))


def _roaming() -> Path:
    return Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))


def _is_link(path: Path) -> bool:
    try:
        return path.is_symlink() or path.is_junction()
    except OSError:
        return True


def measure(path: Path) -> tuple[int, float]:
    """Total size and newest modification time of a file or folder. Links are never followed."""
    try:
        st = path.lstat()
    except OSError:
        return 0, 0.0
    if _is_link(path) or not path.is_dir():
        return st.st_size, st.st_mtime
    total, newest = 0, st.st_mtime
    stack = [path]
    while stack:
        try:
            entries = os.scandir(stack.pop())
        except OSError:
            continue
        with entries:
            for e in entries:
                try:
                    if e.is_dir(follow_symlinks=False):
                        if not e.is_junction():
                            stack.append(Path(e.path))
                        continue
                    s = e.stat(follow_symlinks=False)
                    total += s.st_size
                    newest = max(newest, s.st_mtime)
                except OSError:
                    pass
    return total, newest


def running_programs() -> set[str]:
    """Lower-case names of running programs, e.g. {"chrome.exe", ...}."""
    if sys.platform != "win32":
        return set()
    try:
        out = subprocess.run(["tasklist", "/FO", "CSV", "/NH"], capture_output=True, text=True,
                             timeout=30, creationflags=NO_WINDOW).stdout
    except (OSError, subprocess.TimeoutExpired):
        return set()
    return {row[0].lower() for row in csv.reader(io.StringIO(out)) if row}


# --- Finders ----------------------------------------------------------------------

def _age_filtered_children(folder: Path, min_age_days: float, now: float, how: str) -> list[JunkItem]:
    items = []
    try:
        children = list(folder.iterdir())
    except OSError:
        return items
    for child in children:
        size, newest = measure(child)
        if now - newest >= min_age_days * DAY:
            items.append(JunkItem(child.name, child, size, f"last changed {_date(newest)}", how, root=folder))
    return items


def find_temp_files(now: float, min_age_days: float = 1, startup_entries=(),
                    folders: list[Path] | None = None) -> JunkCategory:
    cat = JunkCategory("temp", "Temporary files",
                      "Files programs left in Temp folders. Programs recreate what they need. Anything changed "
                      "in the last day is skipped because a program may still be using it, and so is anything "
                      "a startup item runs from Temp.")
    if folders is None:
        folders = [Path(tempfile.gettempdir())]
        win_temp = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "Temp"
        if os.access(win_temp, os.W_OK):
            folders.append(win_temp)
    for folder in folders:
        cat.items += _age_filtered_children(folder, min_age_days, now, "delete")
    # Some programs (badly) run scheduled tasks from Temp. Deleting those files would break them.
    for item in cat.items:
        for entry in startup_entries:
            if entry.path and _inside(entry.path, item.path):
                item.blocked = f"Used by startup item \"{entry.name}\""
                break
    return cat


def find_crash_dumps(now: float) -> JunkCategory:
    cat = JunkCategory("crash", "Crash dumps and error reports",
                      "Memory dumps and Windows Error Reporting files from programs that crashed. "
                      "Only useful to developers debugging those crashes.")
    for folder in (_local() / "CrashDumps", _local() / "Microsoft/Windows/WER/ReportArchive",
                   _local() / "Microsoft/Windows/WER/ReportQueue"):
        if folder.is_dir():
            cat.items += _age_filtered_children(folder, 0, now, "delete")
    return cat


BROWSERS = [
    ("Chrome", "chrome.exe", lambda: _local() / "Google/Chrome/User Data"),
    ("Edge", "msedge.exe", lambda: _local() / "Microsoft/Edge/User Data"),
    ("Brave", "brave.exe", lambda: _local() / "BraveSoftware/Brave-Browser/User Data"),
    ("Opera", "opera.exe", lambda: _roaming() / "Opera Software/Opera Stable"),
]
CHROMIUM_CACHES = ("Cache", "Code Cache", "GPUCache")


def find_browser_caches(running: set[str]) -> JunkCategory:
    cat = JunkCategory("browser", "Browser caches",
                      "Copies of web pages and images browsers keep to load sites faster. Safe to empty: "
                      "sites just load a little slower the first time. You stay signed in.")
    for name, exe, base in BROWSERS:
        root = base()
        if not root.is_dir():
            continue
        profiles = [root] if (root / "Cache").exists() else \
            [p for p in root.iterdir() if p.is_dir() and (p.name == "Default" or p.name.startswith("Profile "))]
        for profile in profiles:
            for sub in CHROMIUM_CACHES:
                folder = profile / sub
                if folder.is_dir():
                    size, _ = measure(folder)
                    label = f"{name} {'' if profile == root else f'({profile.name}) '}{sub}".replace("  ", " ")
                    blocked = f"Close {name} first" if exe in running else None
                    cat.items.append(JunkItem(label, folder, size, str(folder), "contents", root=root,
                                              blocked=blocked))
    firefox = _local() / "Mozilla/Firefox/Profiles"
    if firefox.is_dir():
        for profile in firefox.iterdir():
            folder = profile / "cache2"
            if folder.is_dir():
                size, _ = measure(folder)
                blocked = "Close Firefox first" if "firefox.exe" in running else None
                cat.items.append(JunkItem(f"Firefox ({profile.name.split('.')[-1]}) cache", folder, size,
                                          str(folder), "contents", root=firefox, blocked=blocked))
    return cat


def _local_low() -> Path:
    return _local().parent / "LocalLow"


# Graphics drivers and DirectX keep compiled shaders so games and apps start faster.
SHADER_CACHES = [
    ("DirectX shader cache", lambda: _local() / "D3DSCache"),
    ("NVIDIA DirectX cache", lambda: _local() / "NVIDIA/DXCache"),
    ("NVIDIA OpenGL cache", lambda: _local() / "NVIDIA/GLCache"),
    ("NVIDIA DirectX cache (LocalLow)", lambda: _local_low() / "NVIDIA/DXCache"),
    ("NVIDIA per-driver cache", lambda: _local_low() / "NVIDIA/PerDriverVersion/DXCache"),
    ("AMD DirectX cache", lambda: _local() / "AMD/DxCache"),
    ("AMD DirectX 12 cache", lambda: _local() / "AMD/DxcCache"),
    ("AMD Vulkan cache", lambda: _local() / "AMD/VkCache"),
    ("AMD OpenGL cache", lambda: _local() / "AMD/GLCache"),
    ("Intel shader cache", lambda: _local() / "Intel/ShaderCache"),
]


def find_shader_caches() -> JunkCategory:
    cat = JunkCategory("shaders", "Graphics shader caches",
                      "Compiled graphics code saved by your graphics driver and DirectX. Old drivers and "
                      "uninstalled games leave a lot behind. Safe to empty: games rebuild what they need, "
                      "so the first launch afterwards may stutter briefly. Files in use are skipped.")
    for label, base in SHADER_CACHES:
        folder = base()
        if folder.is_dir() and not _is_link(folder):
            size, _ = measure(folder)
            if size:
                cat.items.append(JunkItem(label, folder, size, str(folder), "contents", root=folder))
    return cat


def recycle_bin_contents() -> tuple[int, int]:
    """(bytes, items) in the Recycle Bin across all drives."""
    if sys.platform != "win32":
        return 0, 0
    import ctypes

    class SHQUERYRBINFO(ctypes.Structure):
        _fields_ = [("cbSize", ctypes.c_ulong), ("i64Size", ctypes.c_longlong), ("i64NumItems", ctypes.c_longlong)]

    info = SHQUERYRBINFO(ctypes.sizeof(SHQUERYRBINFO), 0, 0)
    if ctypes.windll.shell32.SHQueryRecycleBinW(None, ctypes.byref(info)) != 0:
        return 0, 0
    return info.i64Size, info.i64NumItems


def empty_recycle_bin() -> None:
    import ctypes

    SHERB_NOCONFIRMATION, SHERB_NOPROGRESSUI, SHERB_NOSOUND = 1, 2, 4
    hr = ctypes.windll.shell32.SHEmptyRecycleBinW(None, None,
                                                  SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND)
    if hr not in (0, -2147418113):  # S_OK, or E_UNEXPECTED which Windows returns when already empty
        raise OSError(f"Windows could not empty the Recycle Bin (error {hr & 0xFFFFFFFF:#x})")


def find_recycle_bin() -> JunkCategory:
    cat = JunkCategory("recyclebin", "Recycle Bin",
                      "Files you've already deleted. Emptying it frees the space for good: they can't be "
                      "restored afterwards, so it's never ticked for you.")
    size, count = recycle_bin_contents()
    if count:
        cat.items.append(JunkItem(f"Recycle Bin ({count:,} items)", None, size, "All drives", "empty-bin",
                                  selected=False))
    return cat


def find_leftover_startup(entries=None) -> JunkCategory:
    """Startup entries whose program has been deleted."""
    from atlas.autoruns import enumerate_all

    cat = JunkCategory("startup", "Leftover startup entries",
                      "Startup entries that point to programs that no longer exist, usually left behind by an "
                      "uninstaller. They do nothing but slow sign-in checks slightly. Registry entries are "
                      "backed up to a .reg file before removal.")
    for e in entries if entries is not None else enumerate_all():
        if e.path is None or e.path.exists():
            continue
        detail = f"{e.category} pointing to {e.path} (deleted)"
        if e.category == "Registry Run" and e.location.startswith("HKCU\\"):
            value = "" if e.name == "(Default)" else e.name
            cat.items.append(JunkItem(e.name, None, 0, detail, "registry",
                                      registry=("HKCU", e.location.split("\\", 1)[1], value)))
        elif e.category == "Startup folder":
            shortcut = Path(e.location, e.name)
            cat.items.append(JunkItem(e.name, shortcut, shortcut.stat().st_size if shortcut.exists() else 0,
                                      detail, "recycle"))
        else:
            hint = {"Scheduled task": "remove it in Task Scheduler", "Service": "it needs administrator rights",
                    "Driver": "it needs administrator rights"}.get(e.category, "it needs administrator rights")
            cat.items.append(JunkItem(e.name, None, 0, detail, "registry",
                                      blocked=f"Atlas can't remove this yet: {hint}"))
    return cat


INSTALLER_EXTENSIONS = {".exe", ".msi", ".msix", ".msixbundle", ".appx", ".appxbundle"}


def find_old_installers(now: float, min_age_days: int = 30) -> JunkCategory:
    cat = JunkCategory("installers", "Old installers in Downloads",
                      f"Setup files downloaded more than {min_age_days} days ago. Once a program is installed, "
                      "its installer is usually no longer needed. Not pre-selected: tick the ones you're done with.")
    downloads = known_folder(FOLDER_DOWNLOADS) or Path.home() / "Downloads"
    if downloads.is_dir():
        for f in downloads.iterdir():
            if f.is_file() and f.suffix.lower() in INSTALLER_EXTENSIONS:
                st = f.stat()
                if now - st.st_mtime >= min_age_days * DAY:
                    cat.items.append(JunkItem(f.name, f, st.st_size, f"downloaded {_date(st.st_mtime)}",
                                              "recycle", selected=False))
    return cat


# Folders in AppData that belong to Windows itself or are shared, so never "orphans".
APPDATA_KEEP = {
    "microsoft", "packages", "temp", "programs", "projectatlas", "crashdumps", "d3dscache", "comms",
    "connecteddevicesplatform", "virtualstore", "publishers", "history", "microsoftedge", "fontcache",
    "peerdistrepub", "sun", "identities", "adobe", "nvidia", "nvidiacorporation", "intel", "amd",
    "windowsapps", "pip", "npmcache", "nugetpackages", "inethistory", "inetcache", "inetcookies",
    # Generic names say nothing about which program owns them, so they aren't judged.
    "cache", "caches", "logs", "log", "data", "tmp", "config", "settings", "backup", "backups", "updates",
}


def _norm(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.lower())


def installed_program_names() -> set[str]:
    """Normalised names, publishers and folder names of installed programs."""
    names: set[str] = set()
    if sys.platform == "win32":
        keys = [(winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall")]
        for hive, path in keys:
            try:
                root = winreg.OpenKey(hive, path)
            except OSError:
                continue
            with root:
                i = 0
                while True:
                    try:
                        sub = winreg.EnumKey(root, i)
                    except OSError:
                        break
                    i += 1
                    names.add(_norm(sub))
                    try:
                        with winreg.OpenKey(root, sub) as k:
                            for value in ("DisplayName", "Publisher", "InstallLocation"):
                                try:
                                    v = winreg.QueryValueEx(k, value)[0]
                                except OSError:
                                    continue
                                if isinstance(v, str) and v:
                                    names.add(_norm(v))
                                    if value == "InstallLocation":
                                        names.add(_norm(Path(v.strip('"')).name))
                    except OSError:
                        pass
    for folder in (os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)"), _local() / "Programs"):
        if folder and Path(folder).is_dir():
            names.update(_norm(p.name) for p in Path(folder).iterdir() if p.is_dir())
    names.discard("")
    return names


def has_home(folder_name: str, installed: set[str]) -> bool:
    """True if a folder name matches an installed program (or is too short or odd to judge)."""
    n = _norm(folder_name)
    if len(n) < 3 or folder_name.startswith(("{", ".")) or n in APPDATA_KEEP:
        return True
    return any(n in k or (len(k) >= 4 and k in n) for k in installed)


def find_orphaned_app_data(now: float, installed: set[str] | None = None, min_idle_days: int = 180,
                           roots: list[Path] | None = None) -> JunkCategory:
    cat = JunkCategory("orphans", "App data with no installed program",
                      f"Folders in AppData that don't match any installed program and haven't been used in "
                      f"{min_idle_days}+ days, usually left behind by uninstalled programs. Atlas can't be "
                      "certain, so none are pre-selected and they go to the Recycle Bin. Review each one.")
    installed = installed_program_names() if installed is None else installed
    if roots is None:
        roots = [_roaming(), _local(), _local().parent / "LocalLow"]
    for root in roots:
        if not root.is_dir():
            continue
        for folder in root.iterdir():
            if not folder.is_dir() or _is_link(folder) or has_home(folder.name, installed):
                continue
            size, newest = measure(folder)
            if now - newest >= min_idle_days * DAY:
                cat.items.append(JunkItem(folder.name, folder, size,
                                          f"{folder}  ·  last used {_date(newest)}", "recycle", selected=False))
    return cat


def scan_all(progress: Callable[[str], None] | None = None) -> list[JunkCategory]:
    from atlas.autoruns import enumerate_all

    now = time.time()
    running = running_programs()
    if progress:
        progress("Reading startup items...")
    try:
        startup = enumerate_all()
    except Exception:
        log.exception("Could not read startup items")
        startup = []
    steps = [
        ("Temporary files", lambda: find_temp_files(now, startup_entries=startup)),
        ("Browser caches", lambda: find_browser_caches(running)),
        ("Crash dumps", lambda: find_crash_dumps(now)),
        ("Shader caches", find_shader_caches),
        ("Leftover startup entries", lambda: find_leftover_startup(startup)),
        ("Old installers", lambda: find_old_installers(now)),
        ("App data with no program", lambda: find_orphaned_app_data(now)),
        ("Recycle Bin", find_recycle_bin),
    ]
    categories = []
    for name, finder in steps:
        if progress:
            progress(f"Looking for {name.lower()}...")
        try:
            cat = finder()
        except Exception:
            log.exception("Cleanup scan step failed: %s", name)
            continue
        cat.items.sort(key=lambda i: -i.size)
        categories.append(cat)
    return categories


# --- Cleaning ---------------------------------------------------------------------

def _inside(path: Path, root: Path) -> bool:
    try:
        return path.resolve().is_relative_to(root.resolve())
    except OSError:
        return False


def _retry_writable(func, path, _exc) -> None:
    """Windows won't delete read-only files (e.g. photos Explorer copies to Temp when you open a zip).
    Clear the flag and try once more; files genuinely in use are left alone."""
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except OSError:
        pass


def _delete(path: Path) -> None:
    if _is_link(path):
        path.rmdir() if path.is_dir() else path.unlink()
    elif path.is_dir():
        shutil.rmtree(path, onexc=_retry_writable)
    else:
        try:
            path.unlink()
        except PermissionError:
            os.chmod(path, stat.S_IWRITE)
            path.unlink()


def _recycle(path: Path) -> None:
    from send2trash import send2trash

    send2trash(str(path))


def _remove_registry_value(hive: str, key: str, value: str, backup_dir: Path) -> Path:
    if hive != "HKCU":
        raise PermissionError("Only your own (HKCU) startup entries can be removed")
    backup_dir.mkdir(parents=True, exist_ok=True)
    backup = backup_dir / f"{datetime.now():%Y%m%d-%H%M%S}-{re.sub(r'[^A-Za-z0-9]+', '_', value or 'default')}.reg"
    subprocess.run(["reg", "export", f"HKCU\\{key}", str(backup), "/y"], check=True, capture_output=True,
                   creationflags=NO_WINDOW)
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key, 0, winreg.KEY_SET_VALUE) as k:
        winreg.DeleteValue(k, value)
    return backup


def clean(items: list[JunkItem], backup_dir: Path,
          on_removed: Callable[[JunkItem, int], None] | None = None) -> CleanResult:
    """Remove the given items. Blocked items are skipped. Never raises for a single item."""
    result = CleanResult()
    for item in items:
        if item.blocked:
            result.skipped.append(f"{item.label}: {item.blocked}")
            continue
        try:
            freed = item.size
            if item.how in ("delete", "contents"):
                if item.path is None or item.root is None or not _inside(item.path, item.root):
                    raise PermissionError("outside the folder it was found in; left alone")
                if item.how == "delete":
                    _delete(item.path)
                    left, _ = measure(item.path) if item.path.exists() else (0, 0)
                else:
                    in_use = 0
                    for child in list(item.path.iterdir()):
                        try:
                            _delete(child)
                        except OSError:
                            in_use += 1  # e.g. a cache file a running game holds open
                    left, _ = measure(item.path)
                    if in_use and left >= item.size:
                        raise PermissionError("in use; close the program using it and try again")
                if left:
                    result.skipped.append(f"{item.label}: partly in use, {human_size(left)} left")
                freed = max(0, item.size - left)
            elif item.how == "recycle":
                _recycle(item.path)
            elif item.how == "empty-bin":
                empty_recycle_bin()
                left, _ = recycle_bin_contents()
                freed = max(0, item.size - left)
            elif item.how == "registry":
                result.backups.append(_remove_registry_value(*item.registry, backup_dir))
            else:
                raise ValueError(f"unknown method {item.how}")
            result.freed += freed
            result.removed += 1
            log.info("Cleanup: %s %s (%s)", item.how, item.path or item.registry, human_size(freed))
            if on_removed:
                on_removed(item, freed)
        except Exception as exc:
            result.skipped.append(f"{item.label}: {exc}")
    return result
