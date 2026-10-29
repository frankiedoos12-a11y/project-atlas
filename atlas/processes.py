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
import time
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
REMOTE_QUIET = 30 * 60  # a remote-access tool that keeps restarting gets one pop-up per half hour


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
            scanner.explain(r)
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
    files, report.unreadable = running_files(include_dlls)
    report.files = judge_files(scanner, files, say, cancel)
    return report


def judge_files(scanner: Scanner, files: list[RunningFile], progress: Callable[[str], None] | None = None,
                cancel: threading.Event | None = None) -> list[RunningFile]:
    """Hash and look up each file, then let valid signatures vouch for unknown ones and explain away
    lone detections. Returns the checked files, worst first."""
    say = progress or (lambda text: None)
    done = 0

    def run(item: RunningFile) -> None:
        nonlocal done
        if cancel and cancel.is_set():
            return
        _look_up(scanner, item)
        done += 1
        say(f"Checked {done} of {len(files)} files...")

    with ThreadPoolExecutor(WORKERS) as pool:
        list(pool.map(run, files))
    files = [f for f in files if f.result]  # cancelled ones drop out

    # Files VirusTotal has no results for: a valid signature from a known publisher vouches for them.
    unseen = [f for f in files if f.result.verdict is Verdict.CLEAN and f.result.file_report
              and not f.result.file_report.analyzed]
    # A lone detection or two on an installed, signed program (VMware, HP, ...) is nearly always a false alarm.
    lone = [f for f in files if f.result.verdict is Verdict.SUSPICIOUS and _lone_detection(scanner, f)]
    if unseen or lone:
        say("Checking signatures...")
        signatures = check_signatures([f.path for f in unseen + lone])
        for f in lone:
            sig = f.result.signature = signatures.get(str(f.path))
            if sig and sig.valid:
                rep = f.result.file_report
                f.result.verdict = Verdict.CLEAN
                f.result.behaviour, f.result.gti = [], []
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
    for f in files:
        r = f.result
        if not r.reasons and r.file_report and r.file_report.analyzed:
            r.reasons.append(f"No engines flagged it ({r.file_report.total} checked)")
    files.sort(key=lambda f: (-f.verdict.rank, f.kind != "program", f.path.name.lower()))
    return files


def _lone_detection(scanner: Scanner, item: RunningFile) -> bool:
    """Flagged by at most 2 engines (under the malicious threshold) and by no sandbox."""
    rep = item.result.file_report
    return bool(rep and rep.malicious + rep.suspicious <= 2 and rep.malicious < scanner.settings.malicious_threshold
                and not rep.sandbox)


class NewProgramWatcher:
    """Looks up each program the moment it starts (checked every couple of seconds).

    Speaks up only when a program that just started is malicious or suspicious. Each program
    file is checked once until it changes, so everyday programs cost nothing after the first time.
    Programs that open and close within a second or two can slip past: the hourly check and the
    download guard cover those.
    """

    def __init__(self, scanner: Scanner, on_finding: Callable[[str, str, str | None], None], interval: float = 2.0):
        self.scanner = scanner
        self.on_finding = on_finding
        self.interval = interval
        self.paused = False
        self.checked = 0
        self._known_pids: set[int] = set()
        self._seen_files: dict[str, tuple[int, float]] = {}  # path -> (size, mtime) when last checked
        self._told: set[str] = set()
        self._remote_told: dict[str, float] = {}  # remote-access tool -> when Atlas last spoke up about it
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        import psutil

        self._known_pids = set(psutil.pids())  # already running: the hourly check covers those
        while not self._stop.wait(self.interval):
            try:
                self.tick()
            except Exception:  # never let one odd process end the watcher
                log.exception("New-program check failed")

    def tick(self) -> None:
        import psutil

        pids = set(psutil.pids())
        new, self._known_pids = pids - self._known_pids, pids
        if self.paused or not new:
            return
        try:
            self._check_command_lines(new)
        except Exception:  # the VirusTotal check below must still run
            log.exception("Command-line check failed")
        try:
            self._check_remote_access(new)
        except Exception:
            log.exception("Remote-access check failed")
        if self.scanner.vt is None:
            return
        fresh: dict[str, RunningFile] = {}
        for pid in new:
            try:
                p = psutil.Process(pid)
                exe, name = p.exe(), p.name()
            except (psutil.Error, OSError):
                continue  # already gone, or off-limits
            if not exe or not os.path.isabs(exe):
                continue
            key = os.path.normcase(exe)
            try:
                st = os.stat(exe)
            except OSError:
                continue
            if self._seen_files.get(key) == (st.st_size, st.st_mtime):
                continue
            self._seen_files[key] = (st.st_size, st.st_mtime)
            item = fresh.setdefault(key, RunningFile(Path(exe), "program"))
            item.pids.add(pid)
            item.used_by.add(name)
        if not fresh:
            return
        for f in judge_files(self.scanner, list(fresh.values())):
            self.checked += 1
            r = f.result
            if f.verdict not in (Verdict.MALICIOUS, Verdict.SUSPICIOUS) or r.sha256 in self._told:
                continue
            self._told.add(r.sha256)
            log.warning("Program just started and is %s: %s (%s)", f.verdict.value, f.path, "; ".join(r.reasons))
            link = r.file_report.gui_link if r.file_report and r.file_report.found else None
            self.on_finding(f"Atlas: {f.verdict.value} program just started",
                            f"{f.path.name}\n{r.threat_text or r.reasons[0]}\nSee Running now to end it.", link)


    def _check_remote_access(self, pids: set[int]) -> None:
        """AnyDesk, TeamViewer, Quick Assist and co. the moment they start: the start of most tech-support scams."""
        import psutil

        from atlas import config, remoteaccess

        started = {}
        for pid in pids:
            try:
                tool = remoteaccess.match_file(psutil.Process(pid).name())
            except (psutil.Error, OSError):
                continue
            if tool and time.monotonic() - self._remote_told.get(tool.name, -REMOTE_QUIET) >= REMOTE_QUIET:
                started[tool.name] = tool
        if not started:
            return
        trusted = config.Settings.load().trusted_remote_tools  # read now: "It's mine" takes effect at once
        for name, tool in started.items():
            self._remote_told[name] = time.monotonic()
            if remoteaccess.is_trusted(tool, trusted):
                continue
            log.warning("Remote-access program started: %s", name)
            self.on_finding(*remoteaccess.started_alert(name), None)

    def _check_command_lines(self, pids: set[int]) -> None:
        """Suspicious command lines (encoded PowerShell, Word starting a shell...) the moment they start."""
        from atlas import cmdlines

        procs = [p for p in (cmdlines.process(pid) for pid in pids) if p]
        for f in cmdlines.evaluate(procs):
            if f.level != "warn" or f.key in self._told:
                continue
            self._told.add(f.key)
            log.warning("Suspicious command line: %s", f.title)
            command = next((d for d in f.details if d.startswith("Command line:")), "")
            self.on_finding(f"Atlas: {f.title}", f"{f.details[0]}\n{command[:180]}", None)


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
