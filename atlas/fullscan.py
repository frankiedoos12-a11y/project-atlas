"""Full scan: every program file on the PC's drives, checked with VirusTotal a day's worth at a time.

A free VirusTotal key allows 500 lookups a day and 4 a minute, and a PC has tens of thousands of
program files, so Atlas goes through them in order of risk: files in your user folders, ProgramData
and odd places first, newest first; Program Files later. Answers VirusTotal already gave are reused,
so each run picks up where the last one stopped. The scan runs at low priority, so the PC stays
responsive, and only looks: nothing is moved unless you press Quarantine.

Defender's own full scan and its offline scan (which restarts the PC to scan before Windows starts)
are a button away as well.
"""

from __future__ import annotations

import dataclasses
import logging
import os
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from atlas.processes import RunningFile, _hash, judge_files
from atlas.scanner import Scanner, Verdict
from atlas.space import CLOUD_ONLY

log = logging.getLogger(__name__)

PROGRAM_TYPES = {".exe", ".dll", ".sys", ".scr", ".com", ".pif", ".cpl", ".msi", ".ps1", ".bat", ".cmd", ".vbs",
                 ".vbe", ".js", ".jse", ".wsf", ".hta", ".jar"}
MAX_SIZE = 200 * 1024 * 1024  # VirusTotal's own limit for looking up big files by hash is higher, but such files are
#                               installers and games, not where malware hides
SKIP_DIRS = {"$recycle.bin", "system volume information", "windows.old", "$windows.~bt", "$windows.~ws",
             "$winreagent", "node_modules", ".git", "__pycache__", ".venv", "site-packages"}
FRESH_DAYS = 30
DEFENDER_FULL = "Start-MpScan -ScanType FullScan"
DEFENDER_OFFLINE = "Start-MpWDOScan"


@dataclass
class FullScanReport:
    found: int = 0  # program files on the drives
    checked: int = 0  # looked up this time (from VirusTotal or its saved answers)
    left: int = 0  # not reached this time: the day's lookups ran out, or it was stopped
    files: list[RunningFile] = field(default_factory=list)  # flagged ones, worst first
    errors: list[str] = field(default_factory=list)
    stopped: bool = False

    @property
    def flagged(self) -> list[RunningFile]:
        return [f for f in self.files if f.verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS, Verdict.UNKNOWN)]


def fixed_drives() -> list[Path]:
    import psutil

    drives = []
    for part in psutil.disk_partitions(all=False):
        if "fixed" in part.opts.lower() or part.fstype.upper() in ("NTFS", "REFS"):
            drives.append(Path(part.mountpoint))
    return drives or [Path(os.environ.get("SystemDrive", "C:") + "\\")]


def _risk(path: Path, windows: str, program_files: tuple[str, ...]) -> int:
    """Lower is looked at sooner."""
    p = os.path.normcase(str(path))
    if p.startswith(program_files):
        return 3
    if p.startswith(windows):
        return 4
    if "\\users\\" in p or "\\programdata\\" in p or "\\temp\\" in p:
        return 0 if "\\appdata\\" in p or "\\downloads\\" in p or "\\temp\\" in p or "\\desktop\\" in p else 1
    return 2  # program files somewhere odd, like C:\Intel or D:\stuff


def program_files(roots: list[Path], skip: set[str] | None = None,
                  cancel: threading.Event | None = None) -> list[tuple[Path, int, float]]:
    """(path, size, modified) of every program file under the roots, skipping the Windows folder's component store,
    online-only cloud files and anything in `skip` (Atlas's own quarantine, for one)."""
    skip = {os.path.normcase(s) for s in (skip or set())}
    winsxs = os.path.normcase(os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "WinSxS"))
    found: list[tuple[Path, int, float]] = []
    stack = [str(r) for r in roots]
    while stack:
        if cancel and cancel.is_set():
            break
        folder = stack.pop()
        try:
            entries = list(os.scandir(folder))
        except OSError:
            continue
        for e in entries:
            try:
                if e.is_dir(follow_symlinks=False):
                    norm = os.path.normcase(e.path)
                    if e.name.lower() not in SKIP_DIRS and norm != winsxs and norm not in skip:
                        stack.append(e.path)
                elif e.is_file(follow_symlinks=False) and os.path.splitext(e.name)[1].lower() in PROGRAM_TYPES:
                    st = e.stat()
                    # Online-only OneDrive files would be downloaded just to be read: left alone.
                    if 0 < st.st_size <= MAX_SIZE and not getattr(st, "st_file_attributes", 0) & CLOUD_ONLY:
                        found.append((Path(e.path), st.st_size, st.st_mtime))
            except OSError:
                continue
    return found


def in_order(files: list[tuple[Path, int, float]]) -> list[tuple[Path, int, float]]:
    windows = os.path.normcase(os.environ.get("SystemRoot", r"C:\Windows")) + "\\"
    pf = tuple(os.path.normcase(os.environ.get(v, "")) + "\\" for v in ("ProgramFiles", "ProgramFiles(x86)")
               if os.environ.get(v))
    return sorted(files, key=lambda f: (_risk(f[0], windows, pf or ("\x00",)), -f[2]))


class LowPriority:
    """Below-normal CPU and low disk priority while the scan runs, so the PC stays quick."""

    def __enter__(self):
        import psutil

        self.proc = psutil.Process()
        try:
            self.old = (self.proc.nice(), self.proc.ionice())
            self.proc.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS)
            self.proc.ionice(psutil.IOPRIO_LOW)
        except (psutil.Error, AttributeError, OSError):
            self.old = None
        return self

    def __exit__(self, *exc):
        if self.old:
            try:
                self.proc.nice(self.old[0])
                self.proc.ionice(self.old[1])
            except Exception:
                pass


def full_scan(scanner: Scanner, budget: int, roots: list[Path] | None = None,
              progress: Callable[[str], None] | None = None, cancel: threading.Event | None = None) -> FullScanReport:
    """Look up program files, riskiest first, until `budget` new VirusTotal lookups are spent."""
    say = progress or (lambda text: None)
    report = FullScanReport()
    if scanner.vt is None:
        report.errors.append("A full scan needs a VirusTotal key (Add VirusTotal key... at the top of the window).")
        return report
    with LowPriority():
        say("Listing program files on your drives (a minute or two)...")
        from atlas.quarantine import quarantine_dir

        files = program_files(roots or fixed_drives(), {str(quarantine_dir(scanner.data_dir))}, cancel)
        report.found = len(files)
        chosen: list[RunningFile] = []
        new_lookups = 0
        # An unchanged file needs no fresh verdict for a month, so each run gets further instead of re-asking.
        hours = max(scanner.settings.cache_hours, FRESH_DAYS * 24)
        patient = Scanner(dataclasses.replace(scanner.settings, cache_hours=hours), scanner.store, scanner.vt,
                          scanner.data_dir)
        ordered = in_order(files)
        for i, (path, size, mtime) in enumerate(ordered):
            if cancel and cancel.is_set():
                report.stopped = True
                break
            if i % 200 == 0:
                say(f"Reading files: {i:,} of {len(ordered):,}...")
            spent = new_lookups >= budget
            # Once the budget is spent, only files read before (so possibly answered before) are worth reading.
            if spent and scanner.store.cached_hash(str(path), size, mtime) is None:
                continue
            try:
                sha = _hash(scanner, path)
            except OSError:
                continue
            if scanner.store.cached_report("file", sha, hours) is None:
                if spent:
                    continue
                new_lookups += 1
            chosen.append(RunningFile(path, "program"))
        report.left = len(ordered) - len(chosen)
        say(f"Checking {len(chosen):,} files with VirusTotal ({new_lookups} new lookups; a free key does 4 a "
            "minute)...")
        started = time.monotonic()
        checked = judge_files(patient, chosen, say, cancel)
        report.checked = len(checked)
        report.stopped = report.stopped or bool(cancel and cancel.is_set())
        report.files = [f for f in checked if f.verdict is not Verdict.CLEAN]
        log.info("Full scan: %d files found, %d checked (%d new lookups) in %.0f s, %d not clean", report.found,
                 report.checked, new_lookups, time.monotonic() - started, len(report.files))
    return report


def summary(report: FullScanReport) -> str:
    if report.errors:
        return report.errors[0]
    bad = sum(1 for f in report.files if f.verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS))
    text = (f"Checked {report.checked:,} of {report.found:,} program files. " +
            (f"{bad} flagged: see below." if bad else "Nothing flagged as malicious or suspicious."))
    if report.left:
        text += (f" {report.left:,} are left for another day (the day's VirusTotal lookups are used up, or the scan "
                 "was stopped). Run it again tomorrow: it carries on where it stopped.")
    return text
