"""Running programs check: is anything bad running right now?

Atlas hashes the program file behind every running process and looks it up on VirusTotal.
Optionally it does the same for the DLLs those programs have loaded, skipping Windows' own
folder (which holds thousands, all Microsoft's): malware often hides as a DLL next to a
legitimate program. Hashes are remembered until a file changes, so later checks are quick.

Nothing is stopped or changed unless you press "End program".
"""

from __future__ import annotations

import logging
import os
import sys
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from atlas.local_checks import check_signatures
from atlas.scanner import Scanner, ScanResult, Verdict
from atlas.space import full_hash
from atlas.vt_client import VTError

log = logging.getLogger(__name__)

WORKERS = 6


@dataclass
class RunningFile:
    path: Path
    kind: str  # "program" or "DLL"
    pids: set[int] = field(default_factory=set)
    used_by: set[str] = field(default_factory=set)  # process names
    result: ScanResult | None = None

    @property
    def verdict(self) -> Verdict:
        return self.result.verdict if self.result else Verdict.CLEAN


@dataclass
class RunningReport:
    files: list[RunningFile] = field(default_factory=list)
    unreadable: int = 0  # processes Windows wouldn't let Atlas look into (needs administrator)
    errors: list[str] = field(default_factory=list)

    @property
    def flagged(self) -> list[RunningFile]:
        return [f for f in self.files if f.verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS, Verdict.UNKNOWN)]


def _windows_dir() -> str:
    return os.path.normcase(os.environ.get("WINDIR", r"C:\Windows")) + os.sep


def running_files(include_dlls: bool = False) -> tuple[list[RunningFile], int]:
    """Every distinct program file (and optionally DLL) in use, plus how many processes were off-limits."""
    import psutil

    files: dict[str, RunningFile] = {}
    unreadable = 0
    windows = _windows_dir()

    def add(path: str, kind: str, pid: int, name: str) -> None:
        key = os.path.normcase(path)
        entry = files.setdefault(key, RunningFile(Path(path), kind))
        entry.pids.add(pid)
        entry.used_by.add(name)

    for p in psutil.process_iter(["pid", "name", "exe"]):
        exe, name, pid = p.info["exe"], p.info["name"] or "?", p.info["pid"]
        if exe and not os.path.isabs(exe):
            continue  # Windows internals like "Registry" and "MemCompression": no file behind them
        if not exe:
            if pid not in (0, 4):  # the System Idle Process and System have no file
                unreadable += 1
            continue
        add(exe, "program", pid, name)
        if include_dlls:
            try:
                for m in p.memory_maps():
                    if m.path.lower().endswith(".dll") and not os.path.normcase(m.path).startswith(windows):
                        add(m.path, "DLL", pid, name)
            except (psutil.Error, OSError):
                unreadable += 1
    return list(files.values()), unreadable


def is_atlas_launcher(path: Path) -> bool:
    """atlas.exe / atlas-tray.exe / atlas-gui.exe in Atlas's own environment. pip writes these
    small launchers during install, different on every PC."""
    scripts = Path(sys.prefix) / "Scripts"
    return path.name.lower() in {"atlas.exe", "atlas-tray.exe", "atlas-gui.exe"} and \
        os.path.normcase(str(path.parent)) == os.path.normcase(str(scripts))


def _hash(scanner: Scanner, path: Path) -> str:
    st = path.stat()
    cached = scanner.store.cached_hash(str(path), st.st_size, st.st_mtime)
    if cached:
        return cached
    sha = full_hash(path)  # keeps the file's "last used" date as it was
    scanner.store.cache_hash(str(path), st.st_size, st.st_mtime, sha)
    return sha


def _look_up(scanner: Scanner, item: RunningFile) -> None:
    r = item.result = ScanResult(path=item.path)
    if is_atlas_launcher(item.path):
        r.reasons.append("Project Atlas's own launcher (made on this PC when Atlas was installed, so VirusTotal "
                         "can't know it)")
        return
    try:
        r.sha256 = _hash(scanner, item.path)
    except FileNotFoundError:
        r.raise_to(Verdict.ERROR, "No longer on disk, so it can't be checked. Usually the program updated itself "
                                  "while running; restarting it loads the new version")
        return
    except OSError as exc:
        r.raise_to(Verdict.ERROR, f"Couldn't read the file: {exc.strerror or exc}")
        return
    try:
        r.file_report = scanner.lookup("file", r.sha256)
        scanner.judge_report(r, r.file_report, "This file")
        if r.verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS):
            r.behaviour = scanner.behaviour(r.sha256)
    except VTError as exc:
        r.raise_to(Verdict.ERROR, str(exc))
    except Exception as exc:  # network trouble: report it, keep going
        r.raise_to(Verdict.ERROR, f"Lookup failed: {exc}")


def check_running(scanner: Scanner, include_dlls: bool = False, progress: Callable[[str], None] | None = None,
                  cancel: threading.Event | None = None) -> RunningReport:
    report = RunningReport()
    if scanner.vt is None:
        report.errors.append("No VirusTotal API key configured. Run: atlas set-key")
        return report
    say = progress or (lambda text: None)
    say("Listing running programs...")
    report.files, report.unreadable = running_files(include_dlls)
    done = 0

    def run(item: RunningFile) -> None:
        nonlocal done
        if cancel and cancel.is_set():
            return
        _look_up(scanner, item)
        done += 1
        say(f"Checked {done} of {len(report.files)} files...")

    with ThreadPoolExecutor(WORKERS) as pool:
        list(pool.map(run, report.files))
    report.files = [f for f in report.files if f.result]  # cancelled ones drop out

    # Files VirusTotal has no results for: a valid signature from a known publisher vouches for them.
    unseen = [f for f in report.files if f.result.verdict is Verdict.CLEAN and f.result.file_report
              and not f.result.file_report.analyzed]
    # A lone detection or two on an installed, signed program (VMware, HP, ...) is nearly always a false alarm.
    lone = [f for f in report.files if f.result.verdict is Verdict.SUSPICIOUS and _lone_detection(scanner, f)]
    if unseen or lone:
        say("Checking signatures...")
        signatures = check_signatures([f.path for f in unseen + lone])
        for f in lone:
            sig = f.result.signature = signatures.get(str(f.path))
            if sig and sig.valid:
                rep = f.result.file_report
                f.result.verdict = Verdict.CLEAN
                f.result.behaviour = []
                f.result.reasons = [f"{rep.malicious + rep.suspicious} of {rep.total} engines flagged it, but it is "
                                    f"validly signed by {sig.signer}, and a lone detection on a signed file is "
                                    "usually a false alarm"]
        for f in unseen:
            sig = f.result.signature = signatures.get(str(f.path))
            if sig and sig.valid:
                f.result.reasons.append(f"VirusTotal has never seen it, but it is validly signed by {sig.signer}")
            else:
                f.result.raise_to(Verdict.UNKNOWN, "VirusTotal has never seen this file, and it is not validly "
                                                   "signed. Worth a look if you don't recognise it")
    for f in report.files:
        r = f.result
        if not r.reasons and r.file_report and r.file_report.analyzed:
            r.reasons.append(f"No engines flagged it ({r.file_report.total} checked)")
    report.files.sort(key=lambda f: (-f.verdict.rank, f.kind != "program", f.path.name.lower()))
    return report


def _lone_detection(scanner: Scanner, item: RunningFile) -> bool:
    """Flagged by at most 2 engines (under the malicious threshold) and by no sandbox."""
    rep = item.result.file_report
    return bool(rep and rep.malicious + rep.suspicious <= 2 and rep.malicious < scanner.settings.malicious_threshold
                and not rep.sandbox)


def end_processes(pids: set[int]) -> list[str]:
    """Ask the processes to close, forcing them after a few seconds. Returns problems, if any."""
    import psutil

    problems, procs = [], []
    for pid in pids:
        try:
            p = psutil.Process(pid)
            p.terminate()
            procs.append(p)
        except psutil.NoSuchProcess:
            pass
        except psutil.AccessDenied:
            problems.append(f"Windows wouldn't let Atlas end process {pid} (it may need administrator rights)")
    _, alive = psutil.wait_procs(procs, timeout=5)
    for p in alive:
        try:
            p.kill()
        except psutil.Error as exc:
            problems.append(f"Couldn't end process {p.pid}: {exc}")
    return problems
