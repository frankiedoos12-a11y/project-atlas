"""The Project Atlas window: startup items, activity and quarantine in readable tables.

Opens from the tray icon (or `atlas gui`). It reads the same local database the tray
writes to, so it shows the latest results instantly; "Check now" re-runs a full check.
"""

from __future__ import annotations

import json
import logging
import queue
import subprocess
import sys
import threading
import tkinter as tk
import webbrowser
from collections import Counter
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from tkinter import messagebox, ttk

from atlas import __version__, browsers, config, space
from atlas.app import build_scanner, guard_running, launch_tray
from atlas.autoruns import MICROSOFT_SIGNERS, assess_all, can_switch, enumerate_all, set_enabled
from atlas.cleanup import HOW_LABELS, clean, human_size, running_programs, scan_all
from atlas.links import check_link
from atlas.quarantine import quarantine_dir, restore_file

WINDOW_TITLE = "Project Atlas"

VERDICT_COLORS = {"malicious": "#c62828", "suspicious": "#d84315", "unknown": "#9a7400",
                  "error": "#6a1b9a", "clean": "#2e7d32"}
VERDICT_ORDER = {"malicious": 0, "suspicious": 1, "unknown": 2, "error": 3, "clean": 4}

FILTERS = {
    "Not Microsoft (recommended)": {"attention", "third-party", "unchecked"},
    "Needs a look": {"attention"},
    "Microsoft": {"microsoft"},
    "Leftovers (deleted files)": {"leftover"},
    "Everything": {"attention", "third-party", "unchecked", "microsoft", "leftover"},
}

log = logging.getLogger(__name__)


def autorun_group(row) -> str:
    """Which bucket a stored startup item belongs in."""
    verdict = row["verdict"]
    if verdict is None or row["reasons"] is None:
        return "unchecked"
    if verdict != "clean":
        return "attention"
    if any("no longer exists" in r for r in json.loads(row["reasons"])):
        return "leftover"
    if row["sig_status"] == "Valid" and row["signer"] in MICROSOFT_SIGNERS:
        return "microsoft"
    return "third-party"


def local_time(iso: str | None) -> str:
    if not iso:
        return "-"
    return datetime.fromisoformat(iso).astimezone().strftime("%Y-%m-%d %H:%M")


def open_in_explorer(path: Path) -> None:
    if path.exists():
        subprocess.Popen(["explorer", "/select,", str(path)])
    elif path.parent.exists():
        subprocess.Popen(["explorer", str(path.parent)])


class Table(ttk.Frame):
    """A Treeview with a scrollbar, clickable sortable headings and verdict colours."""

    def __init__(self, parent, columns: list[tuple[str, str, int]], on_select: Callable[[str], None],
                 scale: float = 1.0):
        super().__init__(parent)
        self.tree = ttk.Treeview(self, columns=[c[0] for c in columns], show="headings", selectmode="browse")
        for cid, title, width in columns:
            self.tree.heading(cid, text=title, command=lambda c=cid: self.sort_by(c))
            self.tree.column(cid, width=int(width * scale), minwidth=int(50 * scale),
                             stretch=cid in ("name", "file", "details", "path", "publisher"))
        for verdict, color in VERDICT_COLORS.items():
            self.tree.tag_configure(verdict, foreground=color)
        self.tree.tag_configure("off", foreground="#888888")
        scroll = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", lambda _: self.selection() and on_select(self.selection()))
        self._sort_desc: dict[str, bool] = {}

    def selection(self) -> str | None:
        sel = self.tree.selection()
        return sel[0] if sel else None

    def replace(self, rows: list[tuple[str, tuple, tuple]]) -> None:
        """rows: (iid, values, tags)."""
        keep = self.selection()
        self.tree.delete(*self.tree.get_children())
        for iid, values, tags in rows:
            self.tree.insert("", "end", iid=iid, values=values, tags=tags)
        if keep and self.tree.exists(keep):
            self.tree.selection_set(keep)
            self.tree.see(keep)

    def sort_by(self, column: str) -> None:
        desc = self._sort_desc[column] = not self._sort_desc.get(column, True)
        items = [(self.tree.set(iid, column).lower(), iid) for iid in self.tree.get_children()]
        if column == "verdict":
            items = [(str(VERDICT_ORDER.get(v, 9)), iid) for v, iid in items]
        for index, (_, iid) in enumerate(sorted(items, reverse=desc)):
            self.tree.move(iid, "", index)


class DetailBox(ttk.Frame):
    """Read-only text panel showing labelled details for the selected row."""

    def __init__(self, parent):
        super().__init__(parent)
        self.text = tk.Text(self, height=7, wrap="word", relief="flat", padx=10, pady=8,
                            font=("Segoe UI", 10), background="#f7f7f9", state="disabled")
        self.text.tag_configure("label", font=("Segoe UI", 10, "bold"))
        for verdict, color in VERDICT_COLORS.items():
            self.text.tag_configure(verdict, foreground=color, font=("Segoe UI", 10, "bold"))
        self.text.pack(fill="both", expand=True)

    def show(self, lines: list[tuple[str, str, str | None]]) -> None:
        """lines: (label, value, optional tag for the value)."""
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        self.text.configure(state="disabled")
        for line in lines:
            self.add(line)

    def add(self, line: tuple[str, str, str | None]) -> None:
        label, value, tag = line
        self.text.configure(state="normal")
        if label:
            self.text.insert("end", f"{label}:  ", "label")
        self.text.insert("end", f"{value}\n", tag or ())
        self.text.configure(state="disabled")


def style_window(root: tk.Tk, scale: float) -> None:
    """The look shared by every Atlas window."""
    try:
        from atlas.contextmenu import icon_path

        root.iconbitmap(default=str(icon_path()))  # the globe, instead of Tk's feather
    except (tk.TclError, OSError):
        pass
    style = ttk.Style(root)
    if "vista" in style.theme_names():
        style.theme_use("vista")
    style.configure(".", font=("Segoe UI", 10))
    style.configure("Treeview", rowheight=int(24 * scale), font=("Segoe UI", 10))
    style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))
    style.configure("Title.TLabel", font=("Segoe UI Semibold", 18), background="#ffffff")
    style.configure("Header.TFrame", background="#ffffff")
    style.configure("On.TLabel", foreground="#2e7d32", background="#ffffff", font=("Segoe UI", 10, "bold"))
    style.configure("Off.TLabel", foreground="#c62828", background="#ffffff", font=("Segoe UI", 10, "bold"))
    style.configure("Muted.TLabel", foreground="#666666", background="#ffffff")
    style.configure("Summary.TLabel", foreground="#444444")


class AtlasWindow:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.settings = config.Settings.load()
        self.scanner, self.store = build_scanner(self.settings)
        self._ui_queue: queue.Queue[Callable[[], None]] = queue.Queue()
        self.startup_rows: dict = {}
        self.activity_rows: dict = {}
        self.quarantine_rows: dict = {}

        root.title(WINDOW_TITLE)
        # Sizes below are in 96-DPI pixels; scale them to match the screen (fonts scale on their own).
        self.scale = max(1.0, root.winfo_fpixels("1i") / 96)
        width = min(int(1200 * self.scale), root.winfo_screenwidth() - 80)
        height = min(int(780 * self.scale), root.winfo_screenheight() - 120)
        root.geometry(f"{width}x{height}")
        root.minsize(int(820 * self.scale), int(520 * self.scale))
        root.configure(background="#ffffff")
        self._style()
        self._build_header()
        self.tabs = ttk.Notebook(root)
        self.tabs.pack(fill="both", expand=True, padx=14, pady=(4, 14))
        self.tabs.add(self._build_startup_tab(), text="  Startup items  ")
        self.tabs.add(self._build_activity_tab(), text="  Activity  ")
        self.tabs.add(self._build_cleanup_tab(), text="  Cleanup  ")
        self.tabs.add(self._build_space_tab(), text="  Disk space  ")
        self.tabs.add(self._build_browsers_tab(), text="  Browsers  ")
        self.tabs.add(self._build_quarantine_tab(), text="  Quarantine  ")
        root.protocol("WM_DELETE_WINDOW", self.close)

        self.refresh_all()
        root.after(150, self._drain_ui_queue)
        root.after(5000, self._tick)
        if not self.startup_rows or any(autorun_group(r) == "unchecked" for r in self.startup_rows.values()):
            root.after(500, self.check_startup)  # never checked with this version: check now

    # --- Plumbing ------------------------------------------------------------

    def _style(self) -> None:
        style_window(self.root, self.scale)

    def in_background(self, work: Callable[[], object], done: Callable[[object], None]) -> None:
        """Run `work` off the UI thread, then `done(result)` back on it."""
        def runner():
            try:
                result = work()
                self._ui_queue.put(lambda: done(result))
            except Exception as exc:
                self._ui_queue.put(lambda: messagebox.showerror(WINDOW_TITLE, f"Something went wrong:\n{exc}"))
                self._ui_queue.put(lambda: done(None))

        threading.Thread(target=runner, daemon=True).start()

    def _drain_ui_queue(self) -> None:
        while not self._ui_queue.empty():
            self._ui_queue.get_nowait()()
        self.root.after(150, self._drain_ui_queue)

    def _tick(self) -> None:
        self._update_header()
        self.root.after(5000, self._tick)

    def close(self) -> None:
        self.store.close()
        self.root.destroy()

    # --- Header --------------------------------------------------------------

    def _build_header(self) -> None:
        header = ttk.Frame(self.root, style="Header.TFrame", padding=(16, 12, 16, 6))
        header.pack(fill="x")
        ttk.Label(header, text="Project Atlas", style="Title.TLabel").pack(side="left")
        ttk.Label(header, text=f"  v{__version__}", style="Muted.TLabel").pack(side="left", pady=(8, 0))
        right = ttk.Frame(header, style="Header.TFrame")
        right.pack(side="right")
        self.protection_label = ttk.Label(right, style="On.TLabel")
        self.protection_label.pack(anchor="e")
        self.key_label = ttk.Label(right, style="Muted.TLabel")
        self.key_label.pack(anchor="e")
        self.start_button = ttk.Button(right, text="Start protection", command=self._start_protection)
        self._update_header()

    def _update_header(self) -> None:
        running = guard_running()
        folders = ", ".join(Path(f).name for f in self.settings.watch_folders)
        if running:
            self.protection_label.configure(text=f"●  Protection ON  ·  watching {folders}", style="On.TLabel")
            self.start_button.pack_forget()
        else:
            self.protection_label.configure(text="●  Protection OFF", style="Off.TLabel")
            self.start_button.pack(anchor="e", pady=(4, 0))
        self.key_label.configure(text="VirusTotal key: connected" if self.scanner.vt
                                 else "VirusTotal key: NOT SET (run atlas set-key)")

    def _start_protection(self) -> None:
        launch_tray()
        self.root.after(2500, self._update_header)

    # --- Startup items -------------------------------------------------------

    def _build_startup_tab(self) -> ttk.Frame:
        tab = ttk.Frame(self.tabs, padding=10)
        bar = ttk.Frame(tab)
        bar.pack(fill="x")
        ttk.Label(bar, text="Show").pack(side="left")
        self.filter_var = tk.StringVar(value=next(iter(FILTERS)))
        box = ttk.Combobox(bar, textvariable=self.filter_var, values=list(FILTERS), state="readonly", width=28)
        box.pack(side="left", padx=(6, 16))
        box.bind("<<ComboboxSelected>>", lambda _: self.fill_startup())
        ttk.Label(bar, text="Search").pack(side="left")
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self.fill_startup())
        ttk.Entry(bar, textvariable=self.search_var, width=32).pack(side="left", padx=6)
        self.check_button = ttk.Button(bar, text="Check now", command=self.check_startup)
        self.check_button.pack(side="right")
        self.progress = ttk.Progressbar(bar, mode="indeterminate", length=140)

        self.startup_summary = ttk.Label(tab, style="Summary.TLabel")
        self.startup_summary.pack(fill="x", pady=(8, 6))

        panes = ttk.PanedWindow(tab, orient="vertical")
        panes.pack(fill="both", expand=True)
        self.startup_table = Table(panes, [("verdict", "Verdict", 100), ("category", "Type", 120),
                                           ("name", "Name", 330), ("publisher", "Publisher", 330),
                                           ("state", "State", 90)], self._show_startup, self.scale)
        panes.add(self.startup_table, weight=3)
        lower = ttk.Frame(panes)
        buttons = ttk.Frame(lower)
        buttons.pack(side="bottom", fill="x", pady=(6, 0))  # packed first so the text can't squeeze it out
        self.startup_detail = DetailBox(lower)
        self.startup_detail.pack(fill="both", expand=True)
        self.startup_open = ttk.Button(buttons, text="Open file location", state="disabled",
                                       command=lambda: self._startup_action("open"))
        self.startup_open.pack(side="left")
        self.startup_vt = ttk.Button(buttons, text="View on VirusTotal", state="disabled",
                                     command=lambda: self._startup_action("vt"))
        self.startup_vt.pack(side="left", padx=6)
        self.startup_switch = ttk.Button(buttons, text="Switch off", state="disabled",
                                         command=lambda: self._startup_action("switch"))
        self.startup_switch.pack(side="right")
        panes.add(lower, weight=1)
        self.startup_detail.show([("", "Select an item to see its details.", None)])
        return tab

    def fill_startup(self) -> None:
        self.startup_rows = {r["key"]: r for r in self.store.autorun_rows()}
        groups = {k: autorun_group(r) for k, r in self.startup_rows.items()}
        wanted = FILTERS[self.filter_var.get()]
        needle = self.search_var.get().strip().lower()
        rows = []
        for key, r in self.startup_rows.items():
            if groups[key] not in wanted:
                continue
            haystack = " ".join(str(r[c] or "") for c in ("name", "category", "signer", "command")).lower()
            if needle and needle not in haystack:
                continue
            verdict = r["verdict"] or "not checked"
            publisher = r["signer"] or ("Not signed" if r["sig_status"] == "NotSigned" else "-")
            state = "On" if r["enabled"] in (None, 1) else "Switched off"
            tags = (verdict,) if r["enabled"] in (None, 1) or verdict != "clean" else ("off",)
            rows.append((VERDICT_ORDER.get(verdict, 5), r["category"], r["name"].lower(),
                         key, (verdict.upper(), r["category"], r["name"], publisher, state), tags))
        rows.sort()
        self.startup_table.replace([(key, values, tags) for *_, key, values, tags in rows])

        counts = Counter(groups.values())
        checked = max((r["checked_at"] or "" for r in self.startup_rows.values()), default="")
        flagged = sum(1 for r in self.startup_rows.values() if r["verdict"] in ("malicious", "suspicious"))
        summary = (f"{len(self.startup_rows)} startup items  ·  {flagged} flagged  ·  "
                   f"{counts['attention'] - flagged} other needing a look  ·  {counts['third-party']} third-party clean"
                   f"  ·  {counts['microsoft']} Microsoft  ·  {counts['leftover']} leftovers")
        if checked:
            summary += f"   (last checked {local_time(checked)})"
        self.startup_summary.configure(text=summary)

    def _show_startup(self, key: str) -> None:
        r = self.startup_rows.get(key)
        if r is None:
            return
        verdict = r["verdict"] or "not checked"
        signer = r["signer"] or ("Not signed" if r["sig_status"] == "NotSigned" else "-")
        if r["sig_status"] and r["sig_status"] not in ("Valid", "NotSigned"):
            signer += f"  (signature problem: {r['sig_status']})"
        lines = [("Verdict", verdict.upper(), verdict if verdict in VERDICT_COLORS else None),
                 ("Name", f"{r['name']}   ({r['category']}"
                          f"{', switched off' if r['enabled'] == 0 else ''})", None),
                 ("Publisher", signer, None),
                 ("Starts", r["command"], None),
                 ("File", r["path"] or "-", None),
                 ("Where", r["location"] or "-", None),
                 ("First seen", local_time(r["first_seen"]), None)]
        for reason in json.loads(r["reasons"] or "[]"):
            lines.append(("Why", reason, None))
        self.startup_detail.show(lines)
        self.startup_open.configure(state="normal" if r["path"] else "disabled")
        self.startup_vt.configure(state="normal" if r["vt_link"] else "disabled")
        is_on = r["enabled"] in (None, 1)
        why_not = can_switch(r["category"], r["location"] or "")
        self.startup_switch.configure(text="Switch off" if is_on else "Switch on",
                                      state="disabled" if why_not else "normal")
        if why_not:
            self.startup_detail.add(("Switch off", why_not, None))

    def _startup_action(self, action: str) -> None:
        r = self.startup_rows.get(self.startup_table.selection() or "")
        if r is None:
            return
        if action == "open" and r["path"]:
            open_in_explorer(Path(r["path"]))
        elif action == "vt" and r["vt_link"]:
            webbrowser.open(r["vt_link"])
        elif action == "switch":
            self._switch_startup(r)

    def _switch_startup(self, r) -> None:
        on = r["enabled"] == 0
        if not on and r["signer"] in MICROSOFT_SIGNERS and not messagebox.askyesno(
                WINDOW_TITLE, f"{r['name']} is part of Windows or a Microsoft program. Switching it off can "
                              "break things.\n\nSwitch it off anyway?"):
            return
        key = r["key"]
        self.startup_switch.configure(state="disabled")

        def work():
            try:
                set_enabled(r["category"], r["location"], r["name"], on)
            except (OSError, ValueError) as exc:
                return str(exc)
            self.store.set_autorun_enabled(key, on)
            log.info("Startup item switched %s: %s", "on" if on else "off", key)
            return None

        def done(error) -> None:
            if error:
                messagebox.showerror(WINDOW_TITLE, f"Couldn't switch {r['name']} {'on' if on else 'off'}.\n\n{error}")
            self.fill_startup()
            if key in self.startup_table.tree.get_children():
                self.startup_table.tree.selection_set(key)
            self._show_startup(key)

        self.in_background(work, done)

    def check_startup(self) -> None:
        self.check_button.configure(state="disabled")
        self.progress.pack(side="right", padx=8)
        self.progress.start(12)
        self.startup_summary.configure(text="Checking startup items: registry, startup folders, scheduled tasks,"
                                            " services. This takes about a minute...")

        def work():
            entries = enumerate_all()
            results = assess_all(entries, self.scanner)
            self.store.sync_autoruns(entries, {e.key: r for e, r in results})

        def done(_):
            self.progress.stop()
            self.progress.pack_forget()
            self.check_button.configure(state="normal")
            self.fill_startup()

        self.in_background(work, done)

    # --- Activity ------------------------------------------------------------

    def _build_activity_tab(self) -> ttk.Frame:
        tab = ttk.Frame(self.tabs, padding=10)
        bar = ttk.Frame(tab)
        bar.pack(fill="x", pady=(0, 8))
        ttk.Label(bar, text="Everything Atlas has checked, newest first.", style="Summary.TLabel").pack(side="left")
        ttk.Button(bar, text="Refresh", command=self.fill_activity).pack(side="right")
        panes = ttk.PanedWindow(tab, orient="vertical")
        panes.pack(fill="both", expand=True)
        self.activity_table = Table(panes, [("time", "When", 140), ("verdict", "Verdict", 100),
                                            ("file", "File", 300), ("details", "Details", 470),
                                            ("action", "Action", 150)], self._show_activity, self.scale)
        panes.add(self.activity_table, weight=3)
        self.activity_detail = DetailBox(panes)
        panes.add(self.activity_detail, weight=1)
        self.activity_detail.show([("", "Select an entry to see its details.", None)])
        return tab

    def fill_activity(self) -> None:
        self.activity_rows = {str(r["id"]): r for r in self.store.recent_scans(1000)}
        rows = []
        for iid, r in self.activity_rows.items():
            reasons = json.loads(r["reasons"])
            rows.append((iid, (local_time(r["scanned_at"]), r["verdict"].upper(), Path(r["path"]).name,
                               reasons[0] if reasons else "", r["action"] or ""), (r["verdict"],)))
        self.activity_table.replace(rows)

    def _show_activity(self, iid: str) -> None:
        r = self.activity_rows.get(iid)
        if r is None:
            return
        lines = [("Verdict", r["verdict"].upper(), r["verdict"]), ("When", local_time(r["scanned_at"]), None),
                 ("File", r["path"], None)]
        if r["source_url"]:
            lines.append(("Downloaded from", r["source_url"], None))
        if r["sha256"]:
            lines.append(("SHA-256", r["sha256"], None))
        for reason in json.loads(r["reasons"]):
            lines.append(("Why", reason, None))
        if r["action"]:
            lines.append(("Action", r["action"], None))
        self.activity_detail.show(lines)

    # --- Cleanup -------------------------------------------------------------

    CHECK = {True: "☑", False: "☐", None: "▣"}  # all / none / some selected

    def _build_cleanup_tab(self) -> ttk.Frame:
        tab = ttk.Frame(self.tabs, padding=10)
        bar = ttk.Frame(tab)
        bar.pack(fill="x")
        ttk.Label(bar, text="Find junk that's safe to remove, and leftovers that no longer have a home.",
                  style="Summary.TLabel").pack(side="left")
        self.clean_button = ttk.Button(bar, text="Clean selected...", state="disabled", command=self._clean)
        self.clean_button.pack(side="right")
        self.junk_scan_button = ttk.Button(bar, text="Scan for junk", command=self.scan_junk)
        self.junk_scan_button.pack(side="right", padx=6)
        self.junk_progress = ttk.Progressbar(bar, mode="indeterminate", length=140)

        self.cleanup_summary = ttk.Label(tab, style="Summary.TLabel",
                                         text="Click Scan for junk to start. Scanning only looks; nothing is "
                                              "removed until you choose Clean selected.")
        self.cleanup_summary.pack(fill="x", pady=(8, 6))

        panes = ttk.PanedWindow(tab, orient="vertical")
        panes.pack(fill="both", expand=True)
        holder = ttk.Frame(panes)
        self.junk_tree = ttk.Treeview(holder, columns=("size", "detail", "how"), show="tree headings",
                                      selectmode="browse")
        self.junk_tree.heading("#0", text="Item  (click a name to tick or untick it)")
        self.junk_tree.heading("size", text="Size")
        self.junk_tree.heading("detail", text="Details")
        self.junk_tree.heading("how", text="What happens")
        s = self.scale
        self.junk_tree.column("#0", width=int(380 * s), minwidth=int(200 * s))
        self.junk_tree.column("size", width=int(90 * s), anchor="e", stretch=False)
        self.junk_tree.column("detail", width=int(420 * s))
        self.junk_tree.column("how", width=int(230 * s), stretch=False)
        self.junk_tree.tag_configure("category", font=("Segoe UI", 10, "bold"))
        self.junk_tree.tag_configure("blocked", foreground="#888888")
        self.junk_tree.tag_configure("review", foreground="#9a7400")
        scroll = ttk.Scrollbar(holder, orient="vertical", command=self.junk_tree.yview)
        self.junk_tree.configure(yscrollcommand=scroll.set)
        self.junk_tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.junk_tree.bind("<Button-1>", self._junk_click)
        self.junk_tree.bind("<space>", lambda _: self._toggle_junk(self.junk_tree.focus()))
        self.junk_tree.bind("<<TreeviewSelect>>", lambda _: self._show_junk())
        panes.add(holder, weight=3)
        self.junk_detail = DetailBox(panes)
        panes.add(self.junk_detail, weight=1)
        removed, freed = self.store.cleanup_totals()
        intro = "Atlas has not cleaned anything yet." if not removed else \
            f"So far Atlas has removed {removed} items and freed {human_size(freed)}."
        self.junk_detail.show([("", intro, None)])
        self.junk_categories: list = []
        return tab

    def scan_junk(self) -> None:
        self.junk_scan_button.configure(state="disabled")
        self.clean_button.configure(state="disabled")
        self.junk_progress.pack(side="right", padx=8)
        self.junk_progress.start(12)

        def progress(text: str) -> None:
            self._ui_queue.put(lambda: self.cleanup_summary.configure(text=text))

        def done(categories) -> None:
            self.junk_progress.stop()
            self.junk_progress.pack_forget()
            self.junk_scan_button.configure(state="normal")
            if categories is not None:
                self.junk_categories = categories
                self._fill_junk()

        self.in_background(lambda: scan_all(progress), done)

    def _junk_item(self, iid: str):
        cat_index, _, item_index = iid.partition("/")
        cat = self.junk_categories[int(cat_index)]
        return cat, (cat.items[int(item_index)] if item_index else None)

    def _category_state(self, cat) -> bool | None:
        usable = [i for i in cat.items if not i.blocked]
        chosen = sum(i.selected for i in usable)
        if not usable or chosen == 0:
            return False
        return True if chosen == len(usable) else None

    def _fill_junk(self) -> None:
        tree = self.junk_tree
        open_rows = {iid for iid in tree.get_children() if tree.item(iid, "open")}
        tree.delete(*tree.get_children())
        for ci, cat in enumerate(self.junk_categories):
            cid = str(ci)
            usable = [i for i in cat.items if not i.blocked]
            count = f"{len(cat.items)} items" if cat.items else "Nothing found"
            if cat.blocked_size:
                count += f"  ·  {human_size(cat.blocked_size)} more locked (see What happens)"
            tree.insert("", "end", iid=cid, open=cid in open_rows, tags=("category",),
                        text=f"{self.CHECK[self._category_state(cat)]}  {cat.title}",
                        values=(human_size(cat.size), count, ""))
            for ii, item in enumerate(cat.items):
                tags = ("blocked",) if item.blocked else ("review",) if item.how in ("recycle", "empty-bin") else ()
                box = "–" if item.blocked else self.CHECK[item.selected]
                tree.insert(cid, "end", iid=f"{ci}/{ii}", text=f"{box}  {item.label}", tags=tags,
                            values=(human_size(item.size) if item.size else "", item.detail,
                                    item.blocked or HOW_LABELS[item.how]))
            if not usable:
                tree.item(cid, text=f"–  {cat.title}")
        self._update_junk_summary()

    def _selected_junk(self) -> list:
        return [(cat, i) for cat in self.junk_categories for i in cat.items if i.selected and not i.blocked]

    def _update_junk_summary(self) -> None:
        total = sum(c.size for c in self.junk_categories)
        chosen = self._selected_junk()
        self.cleanup_summary.configure(
            text=f"Found {human_size(total)} across {sum(len(c.items) for c in self.junk_categories)} items.   "
                 f"Selected: {len(chosen)} items, {human_size(sum(i.size for _, i in chosen))}.")
        self.clean_button.configure(state="normal" if chosen else "disabled")

    def _junk_click(self, event) -> None:
        tree = self.junk_tree
        iid = tree.identify_row(event.y)
        if not iid or tree.identify_column(event.x) != "#0":
            return
        if "indicator" in tree.identify_element(event.x, event.y):
            return  # the expand/collapse arrow
        self._toggle_junk(iid)

    def _toggle_junk(self, iid: str) -> None:
        if not iid or not self.junk_categories:
            return
        cat, item = self._junk_item(iid)
        if item is None:
            new = self._category_state(cat) is not True
            for i in cat.items:
                if not i.blocked:
                    i.selected = new
        elif not item.blocked:
            item.selected = not item.selected
        self._fill_junk()
        self.junk_tree.selection_set(iid)

    def _show_junk(self) -> None:
        iid = self.junk_tree.selection()
        if not iid or not self.junk_categories:
            return
        cat, item = self._junk_item(iid[0])
        if item is None:
            self.junk_detail.show([("", cat.title, "clean"), ("", cat.description, None),
                                   ("Found", f"{len(cat.items)} items, {human_size(cat.size)}", None)])
            return
        lines = [("Item", item.label, None)]
        if item.path:
            lines.append(("Location", str(item.path), None))
        if item.size:
            lines.append(("Size", human_size(item.size), None))
        if item.detail and item.detail != str(item.path):
            lines.append(("Details", item.detail, None))
        lines.append(("What happens", item.blocked or HOW_LABELS[item.how], None))
        if item.how == "recycle" and not item.blocked:
            lines.append(("", "You can restore this from the Recycle Bin if you change your mind.", None))
        self.junk_detail.show(lines)

    def _clean(self) -> None:
        chosen = self._selected_junk()
        if not chosen:
            return
        lines = []
        for cat in self.junk_categories:
            picked = [i for c, i in chosen if c is cat]
            if picked:
                lines.append(f"•  {cat.title}: {len(picked)} items, {human_size(sum(i.size for i in picked))}")
        notes = ["Temp files and caches are deleted (programs rebuild them)."]
        if any(i.how == "recycle" for _, i in chosen):
            notes.append("Installers and app data folders go to the Recycle Bin, so you can restore them.")
        if any(i.how == "registry" for _, i in chosen):
            notes.append("Startup entries are backed up to a .reg file first.")
        if any(i.how == "empty-bin" for _, i in chosen):
            notes.append("The Recycle Bin is emptied for good. Those files can't be restored afterwards.")
        if not messagebox.askyesno(WINDOW_TITLE, "Clean these?\n\n" + "\n".join(lines) + "\n\n" + "\n".join(notes)):
            return
        self.clean_button.configure(state="disabled")
        self.junk_scan_button.configure(state="disabled")
        self.junk_progress.pack(side="right", padx=8)
        self.junk_progress.start(12)
        self.cleanup_summary.configure(text="Cleaning...")
        category_of = {id(i): c for c, i in chosen}
        backups = config.data_dir() / "backups"

        def work():
            return clean([i for _, i in chosen], backups,
                         on_removed=lambda item, freed: self.store.record_cleanup(
                             category_of[id(item)].title, item.label,
                             str(item.path) if item.path else "\\".join(item.registry or ()), item.how, freed))

        def done(result) -> None:
            self.junk_progress.stop()
            self.junk_progress.pack_forget()
            self.junk_scan_button.configure(state="normal")
            if result is not None:
                message = f"Freed {human_size(result.freed)} by removing {result.removed} items."
                if result.backups:
                    message += f"\n\nStartup entry backups saved in:\n{backups}"
                if result.skipped:
                    message += f"\n\n{len(result.skipped)} could not be removed (usually because they're in use):\n"
                    message += "\n".join(f"• {s}" for s in result.skipped[:8])
                    if len(result.skipped) > 8:
                        message += f"\n...and {len(result.skipped) - 8} more"
                messagebox.showinfo(WINDOW_TITLE, message)
            self.scan_junk()

        self.in_background(work, done)

    # --- Disk space ----------------------------------------------------------

    def _build_space_tab(self) -> ttk.Frame:
        tab = ttk.Frame(self.tabs, padding=10)
        bar = ttk.Frame(tab)
        bar.pack(fill="x")
        self.space_mode = tk.StringVar(value="dupes")
        ttk.Radiobutton(bar, text="Duplicate files", value="dupes", variable=self.space_mode,
                        command=self._fill_space).pack(side="left")
        ttk.Radiobutton(bar, text="Big files", value="big", variable=self.space_mode,
                        command=self._fill_space).pack(side="left", padx=14)
        self.space_scan_button = ttk.Button(bar, text="Scan", command=self.scan_space)
        self.space_scan_button.pack(side="right")
        self.space_cancel_button = ttk.Button(bar, text="Stop", command=lambda: self.space_cancel.set())
        self.space_progress = ttk.Progressbar(bar, mode="indeterminate", length=140)
        self.space_cancel = threading.Event()

        folders = ", ".join(self.settings.space_scan_folders)
        self.space_summary = ttk.Label(tab, style="Summary.TLabel", wraplength=int(1100 * self.scale),
                                       text=f"Click Scan to look through {folders}. Scanning only reads; "
                                            "online-only OneDrive files are never downloaded.")
        self.space_summary.pack(fill="x", pady=(8, 6))

        panes = ttk.PanedWindow(tab, orient="vertical")
        panes.pack(fill="both", expand=True)
        holder = ttk.Frame(panes)
        self.space_tree = ttk.Treeview(holder, columns=("size", "where", "date", "notes"), show="tree headings",
                                       selectmode="browse")
        s = self.scale
        for cid, title, width, stretch in (("#0", "File  (click a name to tick or untick it)", 460, True),
                                           ("size", "Size on this PC", 120, False),
                                           ("where", "Location", 170, False), ("date", "Last used", 110, False),
                                           ("notes", "Notes", 330, True)):
            self.space_tree.heading(cid, text=title)
            self.space_tree.column(cid, width=int(width * s), stretch=stretch,
                                   anchor="e" if cid == "size" else "w")
        self.space_tree.tag_configure("group", font=("Segoe UI", 10, "bold"))
        self.space_tree.tag_configure("blocked", foreground="#888888")
        self.space_tree.tag_configure("cloud", foreground="#1565c0")
        scroll = ttk.Scrollbar(holder, orient="vertical", command=self.space_tree.yview)
        self.space_tree.configure(yscrollcommand=scroll.set)
        self.space_tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.space_tree.bind("<Button-1>", self._space_click)
        self.space_tree.bind("<space>", lambda _: self._toggle_space(self.space_tree.focus()))
        self.space_tree.bind("<<TreeviewSelect>>", lambda _: self._show_space())
        panes.add(holder, weight=3)
        lower = ttk.Frame(panes)
        actions = ttk.Frame(lower)
        actions.pack(side="bottom", fill="x", pady=(6, 0))
        self.space_buttons = [
            ttk.Button(actions, text="Move to Recycle Bin...", command=lambda: self._space_action("recycle")),
            ttk.Button(actions, text="Move to folder...", command=lambda: self._space_action("move")),
            ttk.Button(actions, text="Free up space (keep in OneDrive)...",
                       command=lambda: self._space_action("free")),
        ]
        for i, b in enumerate(self.space_buttons):
            b.configure(state="disabled")
            b.pack(side="left", padx=(0 if i == 0 else 6, 0))
        ttk.Button(actions, text="Open file location", command=self._space_open).pack(side="right")
        self.space_detail = DetailBox(lower)
        self.space_detail.pack(fill="both", expand=True)
        panes.add(lower, weight=1)
        self._space_help()
        self.space_files: list = []
        self.space_groups: list = []
        self.space_big: list = []
        return tab

    def _space_help(self) -> None:
        self.space_detail.show([("", "Duplicates are confirmed byte-for-byte before they're listed. At least one "
                                     "copy is always kept, and disks used by your virtual machines are protected.",
                                 None)])

    def scan_space(self) -> None:
        self.space_cancel.clear()
        self.space_scan_button.configure(state="disabled")
        for b in self.space_buttons:
            b.configure(state="disabled")
        self.space_cancel_button.pack(side="right", padx=6)
        self.space_progress.pack(side="right", padx=8)
        self.space_progress.start(12)
        mb = 1024 * 1024
        dup_min, big_min = self.settings.duplicate_min_mb * mb, self.settings.big_file_min_mb * mb

        def progress(text: str) -> None:
            self._ui_queue.put(lambda: self.space_summary.configure(text=text))

        def work():
            files = space.walk([Path(f) for f in self.settings.space_scan_folders], min(dup_min, big_min),
                               self.space_cancel, progress, skip=[config.data_dir()])
            space.mark_vm_disks(files)
            groups = space.find_duplicates([f for f in files if f.size >= dup_min], self.store,
                                           self.space_cancel, progress)
            return files, groups, space.big_files(files, big_min)

        def done(result) -> None:
            self.space_progress.stop()
            self.space_progress.pack_forget()
            self.space_cancel_button.pack_forget()
            self.space_scan_button.configure(state="normal")
            if result is None:
                self.space_summary.configure(text="Scan stopped.")
                return
            self.space_files, self.space_groups, self.space_big = result
            self._fill_space()

        def runner():
            try:
                return work()
            except space.Cancelled:
                return None

        self.in_background(runner, done)

    def _space_file(self, iid: str):
        """The FileInfo behind a row, or None for a duplicate-group heading."""
        if iid.startswith("b"):
            return self.space_big[int(iid[1:])]
        group, _, index = iid[1:].partition("/")
        return self.space_groups[int(group)].files[int(index)] if index else None

    def _ticked_space(self) -> list:
        seen, out = set(), []
        for f in [f for g in self.space_groups for f in g.files] + self.space_big:
            if f.selected and f.path not in seen:
                seen.add(f.path)
                out.append(f)
        return out

    def _fill_space(self) -> None:
        tree = self.space_tree
        open_rows = {iid for iid in tree.get_children() if tree.item(iid, "open")}
        tree.delete(*tree.get_children())
        if self.space_mode.get() == "dupes":
            for gi, g in enumerate(self.space_groups):
                gid = f"g{gi}"
                how = "identical (checked byte-for-byte)" if g.verified else \
                    "same name and size (online-only copy not compared)"
                tree.insert("", "end", iid=gid, open=gid in open_rows or gi < 5, tags=("group",),
                            text=f"{g.files[0].path.name}  ·  {len(g.files)} copies",
                            values=(human_size(g.size), "", "", f"{human_size(g.reclaimable)} can be freed · {how}"))
                for fi, f in enumerate(g.files):
                    self._space_row(gid, f"{gid}/{fi}", f, str(f.path.parent))
            total = sum(g.reclaimable for g in self.space_groups)
            text = f"{len(self.space_groups)} sets of duplicates. Keeping one copy of each would free {human_size(total)}."
        else:
            for bi, f in enumerate(self.space_big):
                self._space_row("", f"b{bi}", f, f.path.name)
            on_pc = sum(f.disk_size for f in self.space_big)
            text = (f"{len(self.space_big)} files over {self.settings.big_file_min_mb} MB, using "
                    f"{human_size(on_pc)} on this PC.")
        ticked = self._ticked_space()
        if ticked:
            text += f"   Ticked: {len(ticked)} files, {human_size(sum(f.disk_size for f in ticked))}."
        self.space_summary.configure(text=text)
        if not tree.selection():
            self._space_help()
        for b in self.space_buttons:
            b.configure(state="normal" if ticked else "disabled")

    def _space_row(self, parent: str, iid: str, f, label: str) -> None:
        box = "–" if f.used_by_vm else self.CHECK[f.selected]
        notes = f.used_by_vm and f"Used by {f.used_by_vm}" or f.kind
        tags = ("blocked",) if f.used_by_vm else ("cloud",) if f.cloud_only else ()
        size = human_size(f.disk_size) if not f.cloud_only else f"0 ({human_size(f.size)} online)"
        self.space_tree.insert(parent, "end", iid=iid, text=f"{box}  {label}", tags=tags,
                               values=(size, f.where, datetime.fromtimestamp(f.last_used).strftime("%Y-%m-%d"),
                                       notes))

    def _space_click(self, event) -> None:
        tree = self.space_tree
        iid = tree.identify_row(event.y)
        if iid and tree.identify_column(event.x) == "#0" and "indicator" not in tree.identify_element(event.x, event.y):
            self._toggle_space(iid)

    def _toggle_space(self, iid: str) -> None:
        f = self._space_file(iid) if iid else None
        if f is None or f.used_by_vm:
            return
        f.selected = not f.selected
        self._fill_space()
        self.space_tree.selection_set(iid)
        self.space_tree.see(iid)

    def _show_space(self) -> None:
        sel = self.space_tree.selection()
        if not sel:
            return
        f = self._space_file(sel[0])
        if f is None:
            g = self.space_groups[int(sel[0][1:])]
            self.space_detail.show([
                ("Duplicate", g.files[0].path.name, None), ("Copies", str(len(g.files)), None),
                ("Each", human_size(g.size), None), ("Can be freed", human_size(g.reclaimable), None),
                ("Compared", "byte-for-byte: identical" if g.verified else
                 "name and size only: an online-only OneDrive copy wasn't downloaded to compare", None),
                ("", "Tick the copies you don't need. Atlas always keeps at least one.", None)])
            return
        lines = [("File", str(f.path), None), ("Size", human_size(f.size), None), ("Location", f.where, None),
                 ("Modified", datetime.fromtimestamp(f.mtime).strftime("%Y-%m-%d %H:%M"), None),
                 ("Type", f.kind, None)]
        if f.used_by_vm:
            lines.append(("Protected", f"This disk belongs to {f.used_by_vm}. Remove the VM in its own app.",
                          "suspicious"))
        if f.in_onedrive and not f.cloud_only:
            lines.append(("OneDrive", "Free up space keeps it in OneDrive and removes only the copy on this PC.",
                          None))
        self.space_detail.show(lines)

    def _space_open(self) -> None:
        sel = self.space_tree.selection()
        f = self._space_file(sel[0]) if sel else None
        if f is not None:
            open_in_explorer(f.path)

    def _space_action(self, action: str) -> None:
        ticked = self._ticked_space()
        if not ticked:
            return
        folder = None
        if action == "move":
            from tkinter import filedialog

            chosen = filedialog.askdirectory(title="Move the ticked files to...", mustexist=True)
            if not chosen:
                return
            folder = Path(chosen)
        total = human_size(sum(f.disk_size for f in ticked))
        verb = {"recycle": "Move to the Recycle Bin", "move": f"Move to {folder}",
                "free": "Free up space (keep in OneDrive)"}[action]
        lines = [f"{verb}: {len(ticked)} files, {total}."]
        onedrive = [f for f in ticked if f.in_onedrive]
        if onedrive and action in ("recycle", "move"):
            lines.append(f"\n{len(onedrive)} of these are in OneDrive. Removing them also removes them from "
                         "OneDrive on all your devices (they go to OneDrive's own recycle bin).")
        if action == "free":
            lines.append("\nThey stay in OneDrive and download again if you open them.")
        if action == "recycle":
            lines.append("\nFiles too big for the Recycle Bin are skipped, so nothing is deleted for good.")
        if not messagebox.askyesno(WINDOW_TITLE, "\n".join(lines) + "\n\nGo ahead?"):
            return
        for b in self.space_buttons:
            b.configure(state="disabled")
        self.space_summary.configure(text="Working...")
        handled = []

        def on_done(f, freed):
            handled.append(f)
            self.store.record_cleanup("Disk space", f.path.name, str(f.path), action, freed)

        def done(result) -> None:
            if result is not None:
                for f in handled:
                    f.selected = False
                    if action == "free":
                        f.cloud_only = True
                if action in ("recycle", "move"):
                    gone = {f.path for f in handled}
                    self.space_big = [f for f in self.space_big if f.path not in gone]
                    for g in self.space_groups:
                        g.files = [f for f in g.files if f.path not in gone]
                    self.space_groups = [g for g in self.space_groups if len(g.files) > 1]
                message = f"Done: {result.done} files, {human_size(result.freed)} freed on this PC."
                if result.skipped:
                    message += f"\n\nSkipped {len(result.skipped)}:\n" + "\n".join(f"• {s}" for s in result.skipped[:8])
                messagebox.showinfo(WINDOW_TITLE, message)
            self._fill_space()

        self.in_background(lambda: space.apply(action, ticked, self.space_groups, folder, on_done), done)

    # --- Quarantine ----------------------------------------------------------

    # --- Browsers: link checker and ad-spam finder -------------------------------------

    def _build_browsers_tab(self) -> ttk.Frame:
        tab = ttk.Frame(self.tabs, padding=10)
        checker = ttk.LabelFrame(tab, text=" Check a link before you open it ", padding=8)
        checker.pack(fill="x")
        row = ttk.Frame(checker)
        row.pack(fill="x")
        self.link_var = tk.StringVar()
        entry = ttk.Entry(row, textvariable=self.link_var)
        entry.pack(side="left", fill="x", expand=True)
        entry.bind("<Return>", lambda _: self.check_link())
        self.link_button = ttk.Button(row, text="Check link", command=self.check_link)
        self.link_button.pack(side="left", padx=(6, 0))
        ttk.Button(row, text="Paste and check", command=self._paste_link).pack(side="left", padx=(6, 0))
        self.link_result = ttk.Label(checker, text="Paste a link from an email, text or ad. Atlas never opens it; "
                                                   "it asks VirusTotal and looks for scam tricks.",
                                     style="Summary.TLabel", wraplength=int(1100 * self.scale))
        self.link_result.pack(fill="x", pady=(6, 0))

        bar = ttk.Frame(tab)
        bar.pack(fill="x", pady=(12, 0))
        self.browser_mode = tk.StringVar(value="sites")
        ttk.Radiobutton(bar, text="Sites allowed to send notifications", value="sites", variable=self.browser_mode,
                        command=self._show_browser_mode).pack(side="left")
        ttk.Radiobutton(bar, text="Extensions", value="extensions", variable=self.browser_mode,
                        command=self._show_browser_mode).pack(side="left", padx=(12, 0))
        self.browser_scan_button = ttk.Button(bar, text="Scan browsers", command=self.scan_browsers)
        self.browser_scan_button.pack(side="right")
        self.browser_progress = ttk.Progressbar(bar, mode="indeterminate", length=140)
        self.browser_summary = ttk.Label(tab, style="Summary.TLabel", wraplength=int(1100 * self.scale),
                                         text="Click Scan browsers to list sites allowed to pop up notifications "
                                              "and the extensions in Chrome, Edge, Brave, Opera and Firefox.")
        self.browser_summary.pack(fill="x", pady=(8, 6))

        panes = ttk.PanedWindow(tab, orient="vertical")
        panes.pack(fill="both", expand=True)
        self.browser_holder = ttk.Frame(panes)
        self.sites_table = Table(self.browser_holder, [("verdict", "Verdict", 100), ("site", "Site", 420),
                                                       ("browser", "Browser", 200), ("details", "Details", 420)],
                                 self._show_browser_row, self.scale)
        self.ext_table = Table(self.browser_holder, [("verdict", "Status", 110), ("name", "Extension", 360),
                                                     ("browser", "Browser", 200), ("state", "State", 70),
                                                     ("details", "Details", 400)],
                               self._show_browser_row, self.scale)
        self.ext_table.tree.tag_configure("look", foreground=VERDICT_COLORS["suspicious"])
        panes.add(self.browser_holder, weight=3)
        lower = ttk.Frame(panes)
        buttons = ttk.Frame(lower)
        buttons.pack(side="bottom", fill="x", pady=(6, 0))
        self.block_button = ttk.Button(buttons, text="Block notifications...", state="disabled",
                                       command=self._block_site)
        self.ext_button = ttk.Button(buttons, text="Open in browser to remove", state="disabled",
                                     command=self._open_extension)
        self.browser_vt = ttk.Button(buttons, text="View on VirusTotal", state="disabled",
                                     command=lambda: self._browser_vt_link and webbrowser.open(self._browser_vt_link))
        self.browser_vt.pack(side="right")
        self.browser_detail = DetailBox(lower)
        self.browser_detail.pack(fill="both", expand=True)
        panes.add(lower, weight=1)
        self.browser_sites: dict = {}
        self.browser_exts: dict = {}
        self._browser_vt_link: str | None = None
        self._show_browser_mode()
        return tab

    def _paste_link(self) -> None:
        try:
            self.link_var.set(self.root.clipboard_get().strip())
        except tk.TclError:
            return
        self.check_link()

    def check_link(self) -> None:
        text = self.link_var.get().strip()
        if not text:
            return
        self.link_button.configure(state="disabled")
        self.link_result.configure(text="Checking...", foreground="#444444")

        def done(check) -> None:
            self.link_button.configure(state="normal")
            verdict = check.verdict.value
            lines = [("Verdict", verdict.upper(), verdict), ("Link", check.url, None)]
            lines += [("Why", r, None) for r in check.reasons]
            report = check.url_report if check.url_report and check.url_report.found else check.domain_report
            self.link_result.configure(text=f"{verdict.upper()}:  {check.reasons[0] if check.reasons else ''}",
                                       foreground=VERDICT_COLORS.get(verdict, "#444444"))
            self._browser_vt_link = report.gui_link if report and report.found else None
            self.browser_vt.configure(state="normal" if self._browser_vt_link else "disabled")
            self.browser_detail.show(lines)

        self.in_background(lambda: check_link(self.scanner, text), done)

    def _show_browser_mode(self) -> None:
        sites = self.browser_mode.get() == "sites"
        (self.ext_table if sites else self.sites_table).pack_forget()
        (self.sites_table if sites else self.ext_table).pack(fill="both", expand=True)
        self.block_button.pack_forget()
        self.ext_button.pack_forget()
        (self.block_button if sites else self.ext_button).pack(side="left")
        self.block_button.configure(state="disabled")
        self.ext_button.configure(state="disabled")
        self.browser_detail.show([("", "Notification spam: sites that tricked you into clicking Allow, then send "
                                       "fake virus alerts and ads. Block any you don't recognise." if sites else
                                       "Adware extensions usually come bundled with another program, from outside "
                                       "the store, and take over your search engine or new tab page.", None)])

    def scan_browsers(self) -> None:
        self.browser_scan_button.configure(state="disabled")
        self.browser_progress.pack(side="right", padx=8)
        self.browser_progress.start(12)
        self.browser_summary.configure(text="Reading browser settings and checking sites with VirusTotal...")

        def work():
            sites = browsers.notification_sites()
            browsers.judge_sites(sites, self.scanner)
            return sites, browsers.extensions()

        def done(result) -> None:
            self.browser_progress.stop()
            self.browser_progress.pack_forget()
            self.browser_scan_button.configure(state="normal")
            if result is not None:
                self._fill_browsers(*result)

        self.in_background(work, done)

    def _fill_browsers(self, sites, exts) -> None:
        self.browser_sites = {str(i): s for i, s in enumerate(sites)}
        self.browser_exts = {str(i): e for i, e in enumerate(exts)}
        self.sites_table.replace([(iid, (s.verdict.upper(), s.site, s.profile.label, s.reasons[0] if s.reasons else ""),
                                   (s.verdict,)) for iid, s in self.browser_sites.items()])
        self.ext_table.replace([(iid, ("NEEDS A LOOK" if e.needs_look else "OK", e.name, e.profile.label,
                                       "On" if e.enabled else "Off", "; ".join(e.concerns + e.notes)),
                                 ("look",) if e.needs_look else ("clean",) if e.enabled else ("off",))
                                for iid, e in self.browser_exts.items()])
        bad_sites = sum(1 for s in sites if s.verdict in ("malicious", "suspicious"))
        look = sum(1 for e in exts if e.needs_look)
        self.browser_summary.configure(
            text=f"{len(sites)} sites can send you notifications ({bad_sites} flagged)  ·  "
                 f"{len(exts)} extensions ({look} need a look)")

    def _show_browser_row(self, iid: str) -> None:
        if self.browser_mode.get() == "sites":
            s = self.browser_sites.get(iid)
            if s is None:
                return
            self.browser_detail.show([("Verdict", s.verdict.upper(), s.verdict if s.verdict in VERDICT_COLORS else None),
                                      ("Site", s.site, None), ("Browser", s.profile.label, None),
                                      ("Allowed to", "Show notifications on your desktop, even when the site "
                                                     "isn't open", None)] + [("Why", r, None) for r in s.reasons])
            self._browser_vt_link = s.vt_link
            self.block_button.configure(state="normal")
        else:
            e = self.browser_exts.get(iid)
            if e is None:
                return
            lines = [("Extension", f"{e.name}  {e.version}".strip(), None), ("Browser", e.profile.label, None),
                     ("State", "On" if e.enabled else "Switched off", None), ("ID", e.id, None)]
            lines += [("Warning", c, "suspicious") for c in e.concerns] + [("Note", n, None) for n in e.notes]
            if e.permissions:
                lines.append(("Permissions", ", ".join(e.permissions[:12]), None))
            self.browser_detail.show(lines)
            self._browser_vt_link = None
            self.ext_button.configure(state="normal")
        self.browser_vt.configure(state="normal" if self._browser_vt_link else "disabled")

    def _block_site(self) -> None:
        s = self.browser_sites.get(self.sites_table.selection() or "")
        if s is None:
            return
        if not messagebox.askyesno(WINDOW_TITLE, f"Block notifications from {s.host} in {s.profile.label}?\n\n"
                                                 f"{s.profile.browser} must be closed. A backup of its settings is "
                                                 "saved first."):
            return
        try:
            backup = browsers.block_notifications(s, config.data_dir() / "backups", running_programs())
        except (OSError, KeyError, ValueError) as exc:
            messagebox.showerror(WINDOW_TITLE, f"Couldn't block {s.host}.\n\n{exc}")
            return
        log.info("Blocked notifications from %s (backup %s)", s.site, backup)
        messagebox.showinfo(WINDOW_TITLE, f"{s.host} can no longer send notifications.\n\nBackup: {backup}")
        self.scan_browsers()

    def _open_extension(self) -> None:
        e = self.browser_exts.get(self.ext_table.selection() or "")
        if e is not None:
            browsers.open_extensions_page(e)

    def _build_quarantine_tab(self) -> ttk.Frame:
        tab = ttk.Frame(self.tabs, padding=10)
        bar = ttk.Frame(tab)
        bar.pack(fill="x", pady=(0, 8))
        ttk.Label(bar, text="Files Atlas moved out of the way. They can't run from here.",
                  style="Summary.TLabel").pack(side="left")
        ttk.Button(bar, text="Open quarantine folder",
                   command=lambda: subprocess.Popen(["explorer", str(quarantine_dir(config.data_dir()))])
                   ).pack(side="right")
        self.restore_button = ttk.Button(bar, text="Restore selected...", state="disabled", command=self._restore)
        self.restore_button.pack(side="right", padx=6)
        panes = ttk.PanedWindow(tab, orient="vertical")
        panes.pack(fill="both", expand=True)
        self.quarantine_table = Table(panes, [("id", "#", 50), ("time", "Quarantined", 140),
                                              ("path", "Original location", 520), ("details", "Reason", 450)],
                                      self._show_quarantine, self.scale)
        panes.add(self.quarantine_table, weight=3)
        self.quarantine_detail = DetailBox(panes)
        panes.add(self.quarantine_detail, weight=1)
        self.quarantine_detail.show([("", "Nothing selected.", None)])
        return tab

    def fill_quarantine(self) -> None:
        self.quarantine_rows = {str(r["id"]): r for r in self.store.quarantined()}
        self.quarantine_table.replace([
            (iid, (r["id"], local_time(r["quarantined_at"]), r["original_path"], r["reason"]), ("malicious",))
            for iid, r in self.quarantine_rows.items()])
        if not self.quarantine_rows:
            self.quarantine_detail.show([("", "Quarantine is empty. Nothing malicious has been caught.", None)])
        self.restore_button.configure(state="disabled")

    def _show_quarantine(self, iid: str) -> None:
        r = self.quarantine_rows.get(iid)
        if r is None:
            return
        self.quarantine_detail.show([("Original location", r["original_path"], None),
                                     ("Quarantined", local_time(r["quarantined_at"]), None),
                                     ("SHA-256", r["sha256"], None), ("Why", r["reason"], None)])
        self.restore_button.configure(state="normal")

    def _restore(self) -> None:
        iid = self.quarantine_table.selection()
        r = self.quarantine_rows.get(iid or "")
        if r is None:
            return
        if not messagebox.askyesno(
                WINDOW_TITLE, f"Restore this file?\n\n{r['original_path']}\n\nAtlas quarantined it because:\n"
                              f"{r['reason']}\n\nOnly restore it if you are sure it is safe.", icon="warning"):
            return
        try:
            dest = restore_file(int(iid), self.store)
            messagebox.showinfo(WINDOW_TITLE, f"Restored to:\n{dest}")
        except Exception as exc:
            messagebox.showerror(WINDOW_TITLE, f"Could not restore:\n{exc}")
        self.fill_quarantine()

    # -------------------------------------------------------------------------

    def refresh_all(self) -> None:
        self.fill_startup()
        self.fill_activity()
        self.fill_quarantine()


def _bring_existing_window_forward() -> bool:
    if sys.platform != "win32":
        return False
    import ctypes

    user32 = ctypes.windll.user32
    hwnd = user32.FindWindowW("TkTopLevel", WINDOW_TITLE)
    if not hwnd:
        return False
    user32.ShowWindow(hwnd, 9)  # SW_RESTORE
    user32.SetForegroundWindow(hwnd)
    return True


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "--scan":  # from Explorer's right-click menu
        from atlas.scanwindow import main as scan_main

        return scan_main(sys.argv[2:])
    if _bring_existing_window_forward():
        return 0
    if sys.platform == "win32":
        import ctypes

        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)  # sharp text on high-DPI screens
        except (AttributeError, OSError):
            pass
    root = tk.Tk()
    AtlasWindow(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
