"""The "Scan with Project Atlas" window, opened from Explorer's right-click menu.

Explorer starts one Atlas process per selected item. The first one opens the window and
the rest hand their paths to it through a small queue file, so a multi-file selection
lands in a single window.

Files are checked exactly like downloads (VirusTotal hash lookup, signature, source, ZIP
contents) but nothing is quarantined automatically: you asked to look, so you decide.
"""

from __future__ import annotations

import logging
import os
import queue
import sys
import threading
import tkinter as tk
import webbrowser
from collections.abc import Callable
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from atlas import config, defender
from atlas.app import build_scanner, setup_logging
from atlas.gui import VERDICT_COLORS, DetailBox, Table, open_in_explorer, style_window
from atlas.quarantine import quarantine_file
from atlas.scanner import ScanResult, Verdict, threat_lines

log = logging.getLogger(__name__)

TITLE = "Project Atlas - Scan"
MUTEX_NAME = "Local\\ProjectAtlasScanWindow"
MAX_FOLDER_FILES = 1000
VT_UPLOAD_LIMIT = 650 * 1024 * 1024


def queue_file() -> Path:
    return config.data_dir() / "scan-queue.txt"


def expand(paths: list[Path], limit: int = MAX_FOLDER_FILES) -> tuple[list[Path], int]:
    """Files to scan: files as given, folders walked (links not followed). Returns (files, skipped)."""
    files: list[Path] = []
    skipped = 0
    for p in paths:
        if p.is_file():
            files.append(p)
        elif p.is_dir():
            for root, dirs, names in os.walk(p):
                dirs[:] = [d for d in dirs if not Path(root, d).is_symlink()]
                for name in names:
                    if len(files) < limit:
                        files.append(Path(root, name))
                    else:
                        skipped += 1
    return files, skipped


def hand_off(paths: list[str]) -> bool:
    """If a scan window is already open, queue these paths for it and return True."""
    if sys.platform != "win32":
        return False
    import ctypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateMutexW.restype = ctypes.c_void_p
    global _window_mutex
    _window_mutex = kernel32.CreateMutexW(None, False, MUTEX_NAME)
    if ctypes.get_last_error() != 183:  # ERROR_ALREADY_EXISTS: someone else has the window
        return False
    queue_file().parent.mkdir(parents=True, exist_ok=True)
    with queue_file().open("a", encoding="utf-8") as fh:
        fh.writelines(f"{p}\n" for p in paths)
    return True


def take_queued() -> list[str]:
    """Paths other Atlas processes queued for this window (and clear the queue)."""
    q = queue_file()
    if not q.exists():
        return []
    taken = q.with_suffix(".taking")
    try:
        q.replace(taken)  # atomic: a process appending right now just starts a new file
    except OSError:
        return []  # being written this instant; try again next tick
    try:
        return [line.strip() for line in taken.read_text(encoding="utf-8").splitlines() if line.strip()]
    finally:
        taken.unlink(missing_ok=True)


class ScanWindow:
    def __init__(self, root: tk.Tk, paths: list[str]):
        self.root = root
        self.settings = config.Settings.load()
        self.scanner, self.store = build_scanner(self.settings)
        self.results: dict[str, ScanResult] = {}
        self.pending: queue.Queue[Path] = queue.Queue()
        self._ui: queue.Queue[Callable[[], None]] = queue.Queue()
        self.total = 0
        self.done = 0
        self.skipped = 0

        self.scale = max(1.0, root.winfo_fpixels("1i") / 96)
        root.title(TITLE)
        root.geometry(f"{min(int(1100 * self.scale), root.winfo_screenwidth() - 80)}x"
                      f"{min(int(620 * self.scale), root.winfo_screenheight() - 120)}")
        root.minsize(int(700 * self.scale), int(400 * self.scale))
        root.configure(background="#ffffff")
        style_window(root, self.scale)
        self._build()
        self.add([Path(p) for p in paths])
        threading.Thread(target=self._worker, daemon=True).start()
        root.protocol("WM_DELETE_WINDOW", self.close)
        root.after(150, self._pump)

    def _build(self) -> None:
        frame = ttk.Frame(self.root, padding=12)
        frame.pack(fill="both", expand=True)
        top = ttk.Frame(frame)
        top.pack(fill="x")
        self.summary = ttk.Label(top, text="", style="Summary.TLabel")
        self.summary.pack(side="left")
        ttk.Button(top, text="Scan more files...", command=self._pick_files).pack(side="right")
        self.progress = ttk.Progressbar(top, mode="determinate", length=int(160 * self.scale))
        self.progress.pack(side="right", padx=8)
        if self.scanner.vt is None:
            ttk.Label(frame, text="No VirusTotal key is set, so only local checks run. Run `atlas set-key` first.",
                      foreground=VERDICT_COLORS["error"]).pack(fill="x", pady=(6, 0))

        panes = ttk.PanedWindow(frame, orient="vertical")
        panes.pack(fill="both", expand=True, pady=(8, 0))
        self.table = Table(panes, [("verdict", "Verdict", 100), ("file", "File", 280), ("signer", "Publisher", 200),
                                   ("details", "Details", 420)], self._show, self.scale)
        panes.add(self.table, weight=3)
        lower = ttk.Frame(panes)
        buttons = ttk.Frame(lower)
        buttons.pack(side="bottom", fill="x", pady=(6, 0))
        self.detail = DetailBox(lower)
        self.detail.pack(fill="both", expand=True)
        panes.add(lower, weight=2)
        self.vt_button = ttk.Button(buttons, text="View on VirusTotal", command=self._open_vt)
        self.open_button = ttk.Button(buttons, text="Open file location", command=self._open_location)
        self.again_button = ttk.Button(buttons, text="Check again", command=self._check_again)
        self.defender_button = ttk.Button(buttons, text="Ask Defender", command=self._ask_defender)
        self.upload_button = ttk.Button(buttons, text="Upload to VirusTotal...", command=self._upload)
        self.quarantine_button = ttk.Button(buttons, text="Move to quarantine...", command=self._quarantine)
        for b in (self.vt_button, self.open_button, self.again_button, self.defender_button):
            b.pack(side="left", padx=(0, 6))
        for b in (self.quarantine_button, self.upload_button):
            b.pack(side="right", padx=(6, 0))
        self._set_buttons(None)
        self.detail.show([("", "Results appear here as each file is checked. Nothing is moved or deleted "
                               "unless you choose to.", None)])

    # --- Scanning -----------------------------------------------------------------

    def add(self, paths: list[Path]) -> None:
        files, skipped = expand(paths)
        self.skipped += skipped
        for f in files:
            self.pending.put(f)
        self.total += len(files)
        self._update_summary()

    def _worker(self) -> None:
        while True:
            path = self.pending.get()
            try:
                result = self.scanner.scan(path, act=False)
            except Exception as exc:  # never let one file stop the rest
                log.exception("Scan failed for %s", path)
                result = ScanResult(path=path, verdict=Verdict.ERROR, reasons=[f"Scan failed: {exc}"])
            self._ui.put(lambda r=result: self._add_result(r))

    def _add_result(self, result: ScanResult) -> None:
        iid = str(len(self.results))
        self.results[iid] = result
        self.done += 1
        self.table.tree.insert("", "end", iid=iid, values=self._row(result), tags=(result.verdict.value,))
        if len(self.results) == 1 or result.verdict.rank >= Verdict.SUSPICIOUS.rank:
            self.table.tree.selection_set(iid)
            self.table.tree.see(iid)
        self._update_summary()

    @staticmethod
    def _row(r: ScanResult) -> tuple:
        signer = r.signature.signer if r.signature and r.signature.valid else (r.signer_text or "-")
        return r.verdict.value.upper(), r.path.name, signer, r.reasons[0] if r.reasons else ""

    def _update_summary(self) -> None:
        flagged = sum(1 for r in self.results.values() if r.verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS))
        unknown = sum(1 for r in self.results.values() if r.verdict is Verdict.UNKNOWN)
        if self.done < self.total:
            text = f"Checking {self.done + 1} of {self.total}..."
        else:
            text = f"{self.total} file{'s' if self.total != 1 else ''} checked: {flagged} flagged, {unknown} unknown"
        if self.skipped:
            text += f"  ({self.skipped} more in those folders weren't checked: limit {MAX_FOLDER_FILES})"
        self.summary.configure(text=text, foreground=VERDICT_COLORS["malicious"] if flagged else "#444444")
        self.progress.configure(maximum=max(1, self.total), value=self.done)
        self.root.title(f"{TITLE} ({self.done}/{self.total})" if self.done < self.total else TITLE)

    def _pump(self) -> None:
        while not self._ui.empty():
            self._ui.get_nowait()()
        queued = take_queued()
        if queued:
            self.add([Path(p) for p in queued])
            self.root.deiconify()
            self.root.lift()
        self.root.after(250, self._pump)

    # --- Details and actions --------------------------------------------------------

    def _selected(self) -> tuple[str, ScanResult] | tuple[None, None]:
        iid = self.table.selection()
        return (iid, self.results[iid]) if iid in self.results else (None, None)

    def _report_link(self, r: ScanResult) -> str | None:
        return r.file_report.gui_link if r.file_report and r.file_report.found else None

    def _set_buttons(self, r: ScanResult | None) -> None:
        exists = bool(r and r.path.exists())
        self.vt_button.configure(state="normal" if r and self._report_link(r) else "disabled")
        self.open_button.configure(state="normal" if exists else "disabled")
        self.again_button.configure(state="normal" if exists else "disabled")
        self.defender_button.configure(state="normal" if exists else "disabled")
        unseen = bool(r and r.file_report is not None and not r.file_report.analyzed)
        self.upload_button.configure(state="normal" if exists and unseen and self.scanner.vt else "disabled")
        self.quarantine_button.configure(state="normal" if exists and not r.action else "disabled")

    def _show(self, iid: str) -> None:
        r = self.results.get(iid)
        if r is None:
            return
        v = r.verdict.value
        lines = [("Verdict", v.upper(), v), ("File", str(r.path), None)]
        if r.signer_text:
            lines.append(("Publisher", r.signer_text, None))
        if r.source_text:
            lines.append(("Downloaded", r.source_text, None))
        lines += [("Why", reason, None) for reason in r.reasons]
        lines += threat_lines(r)
        if r.sha256:
            lines.append(("SHA-256", r.sha256, None))
        if r.action:
            lines.append(("Done", r.action, None))
        self.detail.show(lines)
        self._set_buttons(r)

    def _open_vt(self) -> None:
        _, r = self._selected()
        if r and self._report_link(r):
            webbrowser.open(self._report_link(r))

    def _open_location(self) -> None:
        _, r = self._selected()
        if r:
            open_in_explorer(r.path)

    def _check_again(self) -> None:
        iid, r = self._selected()
        if r is None:
            return
        if r.sha256:
            self.store.forget_report("file", r.sha256)  # ask VirusTotal again, not the 24-hour cache
        self.again_button.configure(state="disabled")
        self.detail.show([("", f"Checking {r.path.name} again...", None)])

        def work():
            fresh = self.scanner.scan(r.path, act=False)

            def done():
                self.results[iid] = fresh
                self.table.tree.item(iid, values=self._row(fresh), tags=(fresh.verdict.value,))
                self.table.tree.selection_set(iid)
                self._show(iid)
                self._update_summary()

            self._ui.put(done)

        threading.Thread(target=work, daemon=True).start()

    def _ask_defender(self) -> None:
        """Second opinion: Defender scans the file now and only reports (it's told not to act)."""
        _, r = self._selected()
        if r is None:
            return
        self.defender_button.configure(state="disabled")
        self.detail.add(("Defender", "Scanning...", None))

        def work():
            scan = defender.scan_file(r.path)
            tag = "malicious" if scan.clean is False else "clean" if scan.clean else None
            self._ui.put(lambda: (self.detail.add(("Defender", scan.message, tag)), self._set_buttons(r)))

        threading.Thread(target=work, daemon=True).start()

    def _upload(self) -> None:
        iid, r = self._selected()
        if r is None:
            return
        size = r.path.stat().st_size
        if size > VT_UPLOAD_LIMIT:
            messagebox.showinfo(TITLE, "VirusTotal only accepts files up to 650 MB.")
            return
        if not messagebox.askyesno(
                TITLE, f"Upload {r.path.name} to VirusTotal?\n\nUploaded files are shared: every VirusTotal "
                       "Intelligence subscriber can download them. Don't upload anything personal or "
                       "confidential.\n\nResults usually take a few minutes; then click Check again."):
            return
        self.upload_button.configure(state="disabled")

        def work():
            try:
                analysis = self.scanner.vt.upload_file(r.path)
                message = (f"{r.path.name} was uploaded (analysis {analysis[:24]}...).\n\n"
                           "Click Check again in a few minutes to see the results.")
                log.info("Uploaded %s to VirusTotal from the scan window (analysis %s)", r.path, analysis)
                self._ui.put(lambda: messagebox.showinfo(TITLE, message))
            except Exception as exc:
                self._ui.put(lambda: messagebox.showerror(TITLE, f"Upload failed:\n{exc}"))
            self._ui.put(lambda: self._set_buttons(r))

        threading.Thread(target=work, daemon=True).start()

    def _quarantine(self) -> None:
        iid, r = self._selected()
        if r is None:
            return
        if not messagebox.askyesno(TITLE, f"Move {r.path.name} to quarantine?\n\nIt can't run from there, and "
                                          "you can restore it later from the Quarantine tab."):
            return
        try:
            qid = quarantine_file(r.path, r.sha256, "; ".join(r.reasons) or "Quarantined by you",
                                  self.store, config.data_dir())
        except OSError as exc:
            messagebox.showerror(TITLE, f"Couldn't quarantine it:\n{exc}")
            return
        r.action = f"quarantined #{qid}"
        log.info("Quarantined %s from the scan window (#%s)", r.path, qid)
        self._show(iid)

    def _pick_files(self) -> None:
        picked = filedialog.askopenfilenames(parent=self.root, title="Choose files to scan")
        if picked:
            self.add([Path(p) for p in picked])

    def close(self) -> None:
        self.store.close()
        self.root.destroy()


def main(paths: list[str]) -> int:
    if hand_off(paths):
        return 0
    setup_logging()
    if sys.platform == "win32":
        import ctypes

        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except (AttributeError, OSError):
            pass
    root = tk.Tk()
    ScanWindow(root, paths)
    root.lift()
    root.attributes("-topmost", True)
    root.after(600, lambda: root.attributes("-topmost", False))
    root.mainloop()
    return 0
