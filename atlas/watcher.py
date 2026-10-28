"""Watch download folders and scan each new file once the browser has finished writing it."""

from __future__ import annotations

import logging
import threading
import time
from collections import Counter
from collections.abc import Callable
from pathlib import Path

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from atlas.notify import notify
from atlas.scanner import Scanner, ScanResult, short_url

log = logging.getLogger(__name__)

# In-progress download files written by browsers; the finished file arrives by rename.
TEMP_SUFFIXES = {".crdownload", ".part", ".partial", ".download", ".tmp", ".opdownload"}

SETTLE_SECONDS = 2.0  # a file must stop changing for this long before it is scanned


def is_temp_file(path: Path) -> bool:
    name = path.name
    return path.suffix.lower() in TEMP_SUFFIXES or name.startswith(("~$", ".~")) or name.lower() == "desktop.ini"


class _Handler(FileSystemEventHandler):
    def __init__(self, queue: PendingQueue, ignore_dirs: list[Path]):
        self.queue = queue
        self.ignore_dirs = [d.resolve() for d in ignore_dirs]

    def _consider(self, raw: str) -> None:
        path = Path(raw)
        if is_temp_file(path):
            return
        resolved = path.resolve()
        if any(resolved.is_relative_to(d) for d in self.ignore_dirs):
            return
        self.queue.touch(path)

    def on_created(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._consider(event.src_path)

    def on_modified(self, event: FileSystemEvent) -> None:
        if not event.is_directory and Path(event.src_path) in self.queue:
            self.queue.touch(Path(event.src_path))

    def on_moved(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._consider(event.dest_path)


class PendingQueue:
    """Files waiting to settle, keyed by path, so repeated events become one scan."""

    def __init__(self):
        self._items: dict[Path, tuple[float, int]] = {}  # path -> (last event time, last size)
        self._lock = threading.Lock()

    def __contains__(self, path: Path) -> bool:
        with self._lock:
            return path in self._items

    def touch(self, path: Path) -> None:
        with self._lock:
            self._items[path] = (time.monotonic(), -1)

    def ready(self) -> list[Path]:
        """Return files whose size has not changed for SETTLE_SECONDS and remove them."""
        now = time.monotonic()
        done: list[Path] = []
        with self._lock:
            for path, (stamp, last_size) in list(self._items.items()):
                if now - stamp < SETTLE_SECONDS:
                    continue
                try:
                    size = path.stat().st_size
                except OSError:
                    del self._items[path]  # deleted or renamed away before it settled
                    continue
                if size != last_size:
                    self._items[path] = (now, size)
                    continue
                if size == 0 and now - stamp < 30:
                    continue  # Firefox creates an empty placeholder first; wait for the real file
                del self._items[path]
                if size > 0:
                    done.append(path)
        return done


class DownloadGuard:
    def __init__(self, scanner: Scanner, folders: list[Path], ignore_dirs: list[Path], notifications: bool = True):
        self.scanner = scanner
        self.folders = folders
        self.queue = PendingQueue()
        self.handler = _Handler(self.queue, ignore_dirs)
        self.notifications = notifications
        self.paused = False  # while paused, new files are ignored (not queued for later)
        self.listeners: list[Callable[[ScanResult], None]] = []
        self._stop = threading.Event()

    def run(self) -> None:
        observer = Observer()
        for folder in self.folders:
            if folder.is_dir():
                observer.schedule(self.handler, str(folder), recursive=False)
                log.info("Watching %s", folder)
            else:
                log.warning("Skipping missing folder %s", folder)
        observer.start()
        try:
            while not self._stop.is_set():
                ready = self.queue.ready()
                if not self.paused:
                    for path in ready:
                        self._scan(path)
                self._stop.wait(0.5)
        finally:
            observer.stop()
            observer.join()

    def stop(self) -> None:
        self._stop.set()

    def scan_existing(self) -> Counter:
        """Scan every file already in the watched folders. Returns a count per verdict."""
        counts: Counter = Counter()
        for folder in self.folders:
            if not folder.is_dir():
                continue
            for path in folder.iterdir():
                if path.is_file() and not is_temp_file(path):
                    result = self._scan(path)
                    if result:
                        counts[result.verdict] += 1
        return counts

    def _scan(self, path: Path) -> ScanResult | None:
        try:
            result = self.scanner.scan(path)
        except Exception:
            log.exception("Scan crashed for %s", path)
            return None
        for listener in self.listeners:
            listener(result)
        log.info("%s -> %s %s", path.name, result.verdict.value.upper(), f"[{result.action}]" if result.action else "")
        for reason in result.reasons:
            log.info("    %s", reason)
        if result.signer_text:
            log.info("    %s", result.signer_text)
        if result.motw and result.motw.host_url:
            log.info("    Downloaded from %s", short_url(result.motw.host_url))
            if result.motw.referrer_url:
                log.info("    Link was on page %s", short_url(result.motw.referrer_url))
        if self.notifications:
            notify(result)
        return result
