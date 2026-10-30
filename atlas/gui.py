"""The Project Atlas window: startup items, activity and quarantine in readable tables.

Opens from the tray icon (or `atlas gui`). It reads the same local database the tray
writes to, so it shows the latest results instantly; "Check now" re-runs a full check.
"""

from __future__ import annotations

import json
import logging
import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
import webbrowser
from collections import Counter
from collections.abc import Callable
from datetime import date, datetime
from pathlib import Path
from tkinter import messagebox, simpledialog, ttk

from atlas import (__version__, browsers, config, deepcheck, defender, gti, hunt, installed, network, processes,
                   protection, pwned, score, space, updates)
from atlas.app import build_scanner, guard_running, launch_scan, launch_tray, vt_usage_text
from atlas.autoruns import MICROSOFT_SIGNERS, assess_all, can_switch, enumerate_all, set_enabled
from atlas.cleanup import HOW_LABELS, clean, human_size, running_programs, scan_all
from atlas.links import check_link
from atlas.quarantine import quarantine_dir, quarantine_file, restore_file
from atlas.scanner import Verdict, threat_lines
from atlas.vt_client import VTClient

WINDOW_TITLE = "Project Atlas"

# The sidebar: Home, then the tabs in five groups.
GROUPS = [("home", "Home"), ("protection", "Protection"), ("pc", "My PC"), ("online", "Online safety"),
          ("clean", "Clean up"), ("history", "History")]
SIDEBAR_BG, SIDEBAR_HOVER, SIDEBAR_ON, CARD_BG = "#f3f4f6", "#e5e7eb", "#dbe7fb", "#f7f7f9"
HOME_ROWS = 5  # how many "needs a look" rows Home shows

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


def report_mistake(parent, kind: str, what: str, verdict: str, reasons: list[str]) -> None:
    """Open a filled-in "Wrong warning" report for the user to read and send (GitHub, or email when the
    project has a report address). Atlas sends nothing itself."""
    from atlas import mistakes

    email = mistakes.email_url(kind, what, verdict, reasons)
    if email and not messagebox.askyesno(WINDOW_TITLE, "Report it on GitHub?\n\nChoose No to send it by email "
                                                       "instead (no GitHub account needed).", parent=parent):
        webbrowser.open(email)
        return
    if not messagebox.askokcancel(
            WINDOW_TITLE, f"Atlas opens a report on GitHub in your browser, filled in with: {what}, what Atlas "
                          f"said and why, and the Atlas version.\n\nRead it, add why you think it's wrong, "
                          f"then press Create. Nothing is sent until you do.", parent=parent):
        return
    webbrowser.open(mistakes.issue_url(kind, what, verdict, reasons))


def scam_lines(result) -> list[tuple[str, str, str | None]]:
    """A message or email check for a DetailBox."""
    from atlas import scam

    tag = {scam.SCAM: "malicious", scam.CAREFUL: "suspicious"}.get(result.verdict, "clean")
    lines = [("Verdict", result.verdict.upper(), tag), ("", scam.summary(result), None)]
    lines += [(label, value, None) for label, value in result.about]
    for r in result.reasons:
        lines += [(r.title, r.why, None), ("", f"    \u201c{r.quote}\u201d", None)]
    for link in result.links:
        lines.append(("Link", f"{link.url}: {link.verdict.value}" +
                      (f" ({link.reasons[0]})" if link.reasons else ""), link.verdict.value))
    if result.skipped_links:
        lines.append(("", f"{result.skipped_links} more links weren't checked.", None))
    return lines


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
    style.configure("Update.TLabel", foreground="#1d4ed8", background="#ffffff", font=("Segoe UI", 10, "bold"))
    style.configure("Section.TLabel", background="#ffffff", font=("Segoe UI Semibold", 12))
    style.configure("Heading.TLabel", font=("Segoe UI Semibold", 12))
    style.configure("Hint.TLabel", foreground="#666666")
    style.configure("RowTitle.TLabel", background="#ffffff", font=("Segoe UI Semibold", 10))
    style.configure("OnBody.TLabel", background="#ffffff", foreground="#2e7d32", font=("Segoe UI", 10))
    style.configure("Bang.TLabel", background="#ffffff", foreground=VERDICT_COLORS["suspicious"],
                    font=("Segoe UI", 11, "bold"))


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
        self._build_body()
        root.protocol("WM_DELETE_WINDOW", self.close)

        self.refresh_all()
        root.after(150, self._drain_ui_queue)
        root.after(5000, self._tick)
        if not self.startup_rows or any(autorun_group(r) == "unchecked" for r in self.startup_rows.values()):
            root.after(500, self.check_startup)  # never checked with this version: check now

    # --- Layout: a sidebar of groups, each with its own tabs ------------------------

    def _build_body(self) -> None:
        body = ttk.Frame(self.root, style="Header.TFrame")
        body.pack(fill="both", expand=True, padx=(0, 14), pady=(4, 14))
        self.sidebar = tk.Frame(body, background=SIDEBAR_BG, padx=6, pady=8)
        self.sidebar.pack(side="left", fill="y", padx=(14, 10))
        self.content = ttk.Frame(body, style="Header.TFrame")
        self.content.pack(side="left", fill="both", expand=True)
        self.pages: dict[str, tk.Widget] = {"home": self._build_home(self.content)}
        self.tab_frames: dict[str, tuple[str, ttk.Frame]] = {}  # tab name -> (group, its frame)
        groups = [
            ("protection", [("Checks", self._build_protection_tab), ("Full scan", self._build_fullscan_tab),
                            ("Threat hunt", self._build_hunt_tab)]),
            ("pc", [("Startup items", self._build_startup_tab), ("Running now", self._build_running_tab),
                    ("Installed", self._build_installed_tab)]),
            ("online", [("Message and link check", self._build_scam_tab), ("Browsers", self._build_browsers_tab),
                        ("Passwords", self._build_passwords_tab)]),
            ("clean", [("Cleanup", self._build_cleanup_tab), ("Disk space", self._build_space_tab)]),
            ("history", [("Activity", self._build_activity_tab), ("Quarantine", self._build_quarantine_tab),
                         ("Weekly reports", self._build_reports_tab)]),
        ]
        for group, tabs in groups:
            book = self.pages[group] = ttk.Notebook(self.content)
            for name, build in tabs:
                frame = build(book)
                book.add(frame, text=f"  {name}  ")
                self.tab_frames[name] = (group, frame)
        self.nav: dict[str, tk.Label] = {}
        for group, title in GROUPS:
            item = tk.Label(self.sidebar, text=title, anchor="w", background=SIDEBAR_BG, foreground="#222222",
                            font=("Segoe UI", 11), padx=int(14 * self.scale), pady=int(9 * self.scale),
                            width=14, cursor="hand2")
            item.pack(fill="x", pady=1)
            item.bind("<Button-1>", lambda _, g=group: self.show(g))
            item.bind("<Enter>", lambda _, w=item, g=group: g != self.page and w.configure(background=SIDEBAR_HOVER))
            item.bind("<Leave>", lambda _, w=item, g=group: g != self.page and w.configure(background=SIDEBAR_BG))
            self.nav[group] = item
        self.page = ""
        self.show("home")

    def show(self, group: str, tab: str | None = None) -> None:
        """Switch to a group (and one of its tabs)."""
        if group != self.page:
            if self.page:
                self.pages[self.page].pack_forget()
            self.pages[group].pack(fill="both", expand=True)
            self.page = group
        for g, item in self.nav.items():
            item.configure(background=SIDEBAR_ON if g == group else SIDEBAR_BG,
                           font=("Segoe UI Semibold" if g == group else "Segoe UI", 11))
        if tab:
            self.pages[group].select(self.tab_frames[tab][1])

    def show_tab(self, tab: str) -> None:
        self.show(self.tab_frames[tab][0], tab)

    # --- Home -------------------------------------------------------------------------

    def _build_home(self, parent) -> ttk.Frame:
        page = ttk.Frame(parent, style="Header.TFrame", padding=(8, 4, 0, 0))
        top = ttk.Frame(page, style="Header.TFrame")
        top.pack(fill="x")
        card = tk.Frame(top, background=CARD_BG, padx=int(22 * self.scale), pady=int(14 * self.scale))
        card.pack(side="left", fill="y")
        tk.Label(card, text="Health score", background=CARD_BG, foreground="#555555",
                 font=("Segoe UI", 11)).pack(anchor="w")
        self.home_score = tk.Label(card, text="--", background=CARD_BG, font=("Segoe UI Semibold", 40))
        self.home_score.pack(anchor="w")
        self.home_label = tk.Label(card, text="", background=CARD_BG, font=("Segoe UI Semibold", 12))
        self.home_label.pack(anchor="w")
        self.home_when = tk.Label(card, text="", background=CARD_BG, foreground="#666666", font=("Segoe UI", 9))
        self.home_when.pack(anchor="w", pady=(4, 0))
        self.home_button = ttk.Button(card, text="Check again", command=self.check_home)
        self.home_button.pack(anchor="w", pady=(10, 0))

        actions = ttk.Frame(top, style="Header.TFrame", padding=(int(24 * self.scale), 0, 0, 0))
        actions.pack(side="left", fill="both", expand=True)
        ttk.Label(actions, text="Quick actions", style="Section.TLabel").grid(row=0, column=0, columnspan=3,
                                                                              sticky="w", pady=(0, 6))
        quick = [("Scan a file...", self._scan_files), ("Check a message or link",
                                                         lambda: self.show_tab("Message and link check")),
                 ("Full scan", lambda: self.show_tab("Full scan")),
                 ("Clean up junk", self._home_cleanup), ("Check a password...", self._check_password),
                 ("Weekly report", self._weekly_report)]
        for i, (text, command) in enumerate(quick):
            ttk.Button(actions, text=text, command=command, width=24).grid(row=1 + i // 3, column=i % 3, sticky="ew",
                                                                           padx=(0, 8), pady=4, ipady=4)

        ttk.Label(page, text="Needs a look", style="Section.TLabel").pack(anchor="w", pady=(18, 4))
        self.home_list = ttk.Frame(page, style="Header.TFrame")
        self.home_list.pack(fill="both", expand=True)
        self.home_more = ttk.Label(page, style="Muted.TLabel", cursor="hand2")
        self.home_more.pack(anchor="w", pady=(6, 0))
        self.home_more.bind("<Button-1>", lambda _: self.show_tab("Checks"))
        last = score.recorded(self.store, date.today())
        if last:  # the tray's last check, until this one is done
            self._show_score(last["value"], score.label_for(last["value"]), "From the last check today")
        self.root.after(300, self.check_home)
        return page

    def _show_score(self, value: int, label: str, when: str) -> None:
        color = "#2e7d32" if value >= score.GOOD else "#9a7400" if value >= score.FAIR else "#c62828"
        self.home_score.configure(text=f"{value}", foreground=color)
        self.home_label.configure(text=f"{label}  ·  out of 100", foreground=color)
        self.home_when.configure(text=when)

    def check_home(self) -> None:
        """The Protection checks and the threat hunt, the same as the tray's hourly check."""
        self.home_button.configure(state="disabled")
        self.home_when.configure(text="Checking...")

        def work():
            system = protection.check_system(self.scanner)
            return system, hunt.check_hunt(self.scanner)

        def done(result) -> None:
            self.home_button.configure(state="normal")
            if result is None:
                self.home_when.configure(text="The check didn't finish.")
                return
            system, hunted = result
            self._fill_protection(system)
            self._fill_hunt(hunted)
            health = score.health_score(system + hunted)
            score.record(self.store, health)
            self._show_score(health.value, health.label, f"Checked at {datetime.now():%H:%M}")
            self._fill_home([f for f in system if f.needs_look], [f for f in hunted if f.needs_look],
                            sum(1 for f in system + hunted if f.level == "note"))

        self.in_background(work, done)

    def _fill_home(self, system: list, hunted: list, notes: int) -> None:
        for child in self.home_list.winfo_children():
            child.destroy()
        rows = sorted(system + hunted, key=lambda f: f.area not in score.SERIOUS_AREAS)
        look = len(rows)
        self.nav["protection"].configure(text=f"Protection  ({look})" if look else "Protection")
        if not rows:
            ttk.Label(self.home_list, text="✓  Nothing needs a look. Atlas keeps checking every hour.",
                      style="OnBody.TLabel").pack(anchor="w", pady=4)
        for f in rows[:HOME_ROWS]:
            row = ttk.Frame(self.home_list, style="Header.TFrame")
            row.pack(fill="x", pady=3)
            ttk.Label(row, text="!", style="Bang.TLabel", width=2).pack(side="left", anchor="n")
            text = ttk.Frame(row, style="Header.TFrame")
            text.pack(side="left", fill="x", expand=True)
            ttk.Label(text, text=f.title, style="RowTitle.TLabel").pack(anchor="w")
            why = f"{f.area}  ·  {f.details[0]}" if f.details else f.area
            ttk.Label(text, text=why, style="Muted.TLabel", wraplength=int(700 * self.scale)).pack(anchor="w")
            in_hunt = f in hunted
            ttk.Button(row, text="Details", command=lambda f=f, h=in_hunt: self._home_details(f, h)).pack(
                side="right", padx=(6, 0))
            if f.fix and not in_hunt:
                ttk.Button(row, text=f.fix_label or "Fix...", command=lambda f=f: self._run_fix(f, self.check_home)
                           ).pack(side="right")
        more = []
        if look > HOME_ROWS:
            more.append(f"{look - HOME_ROWS} more need a look")
        if notes:
            more.append(f"{notes} notes")
        self.home_more.configure(text=(" and ".join(more) + ": see Protection >" if more else ""))

    def _home_details(self, f, in_hunt: bool) -> None:
        tab, rows, table = ("Threat hunt", self.hunt_findings, self.hunt_table) if in_hunt else \
            ("Checks", self.protection_findings, self.protection_table)
        self.show_tab(tab)
        iid = next((i for i, x in rows.items() if x is f), None)
        if iid:
            table.tree.selection_set(iid)
            table.tree.see(iid)

    def _home_cleanup(self) -> None:
        self.show_tab("Cleanup")
        if str(self.junk_scan_button["state"]) != "disabled":
            self.scan_junk()

    def _scan_files(self) -> None:
        from tkinter import filedialog

        paths = filedialog.askopenfilenames(parent=self.root, title="Choose files to check")
        if paths:
            launch_scan(list(paths))

    # --- Passwords and weekly reports -------------------------------------------------

    def _build_passwords_tab(self, parent) -> ttk.Frame:
        tab = ttk.Frame(parent, padding=16)
        ttk.Label(tab, text="Has a password appeared in a data leak?", style="Heading.TLabel").pack(anchor="w")
        ttk.Label(tab, style="Summary.TLabel", wraplength=int(800 * self.scale),
                  text="Atlas checks it with Have I Been Pwned. The password never leaves this PC: Atlas sends only "
                       "the first 5 characters of a scrambled (hashed) version, and nothing is saved. If it has "
                       "leaked, change it everywhere you use it, and use a different password for each site (a "
                       "password manager makes that easy).").pack(anchor="w", pady=(6, 12))
        ttk.Button(tab, text="Check a password...", command=self._check_password).pack(anchor="w")
        return tab

    def _build_reports_tab(self, parent) -> ttk.Frame:
        tab = ttk.Frame(parent, padding=10)
        bar = ttk.Frame(tab)
        bar.pack(fill="x")
        ttk.Label(bar, style="Summary.TLabel", text="Once a week the tray writes a report: your health score, what "
                  "changed and what Atlas did. They stay on this PC.").pack(side="left")
        ttk.Button(bar, text="Write one now", command=self._weekly_report).pack(side="right")
        self.reports_table = Table(tab, [("name", "Week ending", 300), ("details", "File", 700)],
                                   lambda iid: None, self.scale)
        self.reports_table.pack(fill="both", expand=True, pady=(8, 6))
        self.reports_table.tree.bind("<Double-1>", lambda _: self._open_report())
        ttk.Button(tab, text="Open", command=self._open_report).pack(anchor="w")
        self.fill_reports()
        return tab

    def fill_reports(self) -> None:
        folder = config.data_dir() / "reports"
        files = sorted(folder.glob("atlas-week-*.html"), reverse=True) if folder.is_dir() else []
        self.reports_table.replace([(str(f), (f.stem.removeprefix("atlas-week-"), f.name), ()) for f in files])

    def _open_report(self) -> None:
        iid = self.reports_table.selection()
        if iid:
            os.startfile(iid)

    def _weekly_report(self) -> None:
        from atlas import report

        def work():
            findings = protection.check_system(self.scanner) + hunt.check_hunt(self.scanner)
            weekly = report.build(self.store, score.health_score(findings))
            return report.save(weekly, config.data_dir() / "reports")

        def done(path) -> None:
            if path:
                self.fill_reports()
                os.startfile(path)

        self.in_background(work, done)


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
        self.key_button = ttk.Button(right, text="Add VirusTotal key...", command=self.ask_for_key)
        self.update_row = ttk.Frame(right, style="Header.TFrame")
        self.update_label = ttk.Label(self.update_row, style="Update.TLabel")
        self.update_label.pack(side="left")
        self.update_button = ttk.Button(self.update_row, text="Update now", command=self._update_now)
        self.start_button = ttk.Button(right, text="Start protection", command=self._start_protection)
        self._update_header()
        if self.settings.check_for_updates:
            self.in_background(updates.latest_version, self._show_update)

    def _show_update(self, latest) -> None:
        if not latest or not updates.is_newer(latest):
            return
        self.update_label.configure(text=updates.update_hint(latest) + "  ")
        if updates.can_update_itself():
            self.update_button.pack(side="left")
        self.update_row.pack(anchor="e", pady=(4, 0))

    def _update_now(self) -> None:
        if not messagebox.askyesno(WINDOW_TITLE, "Update Project Atlas now?\n\nThe installer closes Atlas, updates it "
                                                 "and starts the tray again. "
                                                 "Your settings, history and key are kept."):
            return
        try:
            updates.start_update()
        except (OSError, RuntimeError) as exc:
            messagebox.showerror(WINDOW_TITLE, str(exc))
            return
        self.close()

    def _update_header(self) -> None:
        running = guard_running()
        folders = ", ".join(Path(f).name for f in self.settings.watch_folders)
        if running:
            self.protection_label.configure(text=f"●  Protection ON  ·  watching {folders}", style="On.TLabel")
            self.start_button.pack_forget()
        else:
            self.protection_label.configure(text="●  Protection OFF", style="Off.TLabel")
            self.start_button.pack(anchor="e", pady=(4, 0))
        self.key_label.configure(text=f"VirusTotal key: connected  ·  {vt_usage_text(self.store)}" if self.scanner.vt
                                 else "VirusTotal key: not set, so only Atlas's own checks run")
        if self.scanner.vt:
            self.key_button.pack_forget()
        else:
            self.key_button.pack(anchor="e", pady=(4, 0))

    def ask_for_key(self) -> None:
        """Store a VirusTotal key from the window, for people who never open a terminal."""
        if not messagebox.askyesno(WINDOW_TITLE, "Atlas checks files and links with VirusTotal, using your own free "
                                                 "VirusTotal key.\n\nDo you already have one?"):
            messagebox.showinfo(WINDOW_TITLE, "VirusTotal's sign-up page opens now. After signing up, click your "
                                              "name (top right), choose API key and copy it, then come back here.")
            webbrowser.open("https://www.virustotal.com/gui/join-us")
        key = simpledialog.askstring(WINDOW_TITLE, "Paste your VirusTotal API key\n(kept in Windows Credential Manager):",
                                     parent=self.root, show="*")
        if not key or not key.strip():
            return
        key = key.strip()

        def check():
            try:
                # The EICAR test file: a harmless file every antivirus detects on purpose.
                VTClient(key).file_report("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
            except Exception as exc:
                return str(exc)
            return None

        def done(problem):
            if problem:
                messagebox.showerror(WINDOW_TITLE, f"VirusTotal didn't accept that key, so it wasn't saved.\n\n{problem}")
                return
            config.set_api_key(key)
            self.scanner.vt = VTClient(key)
            self.scanner.vt.on_request = self.store.count_vt_request
            self._update_header()
            messagebox.showinfo(WINDOW_TITLE, "VirusTotal key saved. Atlas now checks files and links with it.")

        self.in_background(check, done)

    def _start_protection(self) -> None:
        launch_tray()
        self.root.after(2500, self._update_header)

    # --- Startup items -------------------------------------------------------

    def _build_startup_tab(self, parent) -> ttk.Frame:
        tab = ttk.Frame(parent, padding=10)
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

    def _build_activity_tab(self, parent) -> ttk.Frame:
        tab = ttk.Frame(parent, padding=10)
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

    def _build_cleanup_tab(self, parent) -> ttk.Frame:
        tab = ttk.Frame(parent, padding=10)
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
        if any(i.how == "files" for _, i in chosen):
            notes.append("History, cookies and the recent files list are deleted for good. Clearing cookies signs "
                         "you out of websites.")
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

    def _build_space_tab(self, parent) -> ttk.Frame:
        tab = ttk.Frame(parent, padding=10)
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

    def _build_browsers_tab(self, parent) -> ttk.Frame:
        tab = ttk.Frame(parent, padding=10)
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
        actions = ttk.Frame(checker)
        actions.pack(fill="x", pady=(6, 0))
        self.trust_button = ttk.Button(actions, text="Always trust this site...", state="disabled",
                                       command=self._trust_link_site)
        self.trust_button.pack(side="left")
        self.link_mistake = ttk.Button(actions, text="Report a mistake...", state="disabled",
                                       command=self._link_mistake)
        self.link_mistake.pack(side="left", padx=6)
        ttk.Button(actions, text="Trusted sites...", command=self._trusted_sites).pack(side="right")
        self._link_check = None

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
            self._link_check = check
            flagged = verdict in ("malicious", "suspicious", "unknown")
            self.trust_button.configure(state="normal" if flagged and check.host else "disabled")
            self.link_mistake.configure(state="normal" if flagged and check.host else "disabled")

        self.in_background(lambda: check_link(self.scanner, text), done)

    def _link_mistake(self) -> None:
        check = self._link_check
        if check is not None:
            report_mistake(self.root, "Site", check.host, check.verdict.value, check.reasons)

    def _trust_link_site(self) -> None:
        from atlas import allowlist

        check = self._link_check
        if check is None:
            return
        site = allowlist.site_of(check.host)
        if not messagebox.askyesno(WINDOW_TITLE, f"Always trust {site}?\n\nAtlas stops using its own guesses about "
                                                 "it (look-alike names, brand-new domains), on this PC. It still "
                                                 "warns if VirusTotal's engines flag it. Remove it again with "
                                                 "Trusted sites..."):
            return
        try:
            allowlist.trust_site(check.host)
        except ValueError as exc:
            messagebox.showerror(WINDOW_TITLE, str(exc))
            return
        self.settings.trusted_sites = config.Settings.load().trusted_sites
        self.check_link()

    def _trusted_sites(self) -> None:
        """Your trusted sites, with Remove."""
        from atlas import allowlist

        box = tk.Toplevel(self.root)
        box.title("Trusted sites")
        box.transient(self.root)
        frame = ttk.Frame(box, padding=12)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, style="Summary.TLabel", wraplength=int(420 * self.scale),
                  text="Atlas skips its own guesses about these sites, but still warns if VirusTotal's engines "
                       "flag them. Sites on Project Atlas's shared allow-list aren't listed here.").pack(anchor="w")
        sites = tk.Listbox(frame, height=10, font=("Segoe UI", 10), activestyle="none")
        sites.pack(fill="both", expand=True, pady=8)

        def fill() -> None:
            sites.delete(0, "end")
            for site in config.Settings.load().trusted_sites:
                sites.insert("end", site)

        def remove() -> None:
            chosen = sites.curselection()
            if chosen:
                allowlist.untrust_site(sites.get(chosen[0]))
                self.settings.trusted_sites = config.Settings.load().trusted_sites
                fill()

        buttons = ttk.Frame(frame)
        buttons.pack(fill="x")
        ttk.Button(buttons, text="Remove", command=remove).pack(side="left")
        ttk.Button(buttons, text="Close", command=box.destroy).pack(side="right")
        fill()

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

    # --- Running now: programs and network ------------------------------------

    def _build_running_tab(self, parent) -> ttk.Frame:
        tab = ttk.Frame(parent, padding=10)
        bar = ttk.Frame(tab)
        bar.pack(fill="x")
        self.running_mode = tk.StringVar(value="programs")
        ttk.Radiobutton(bar, text="Programs", value="programs", variable=self.running_mode,
                        command=self._show_running_mode).pack(side="left")
        ttk.Radiobutton(bar, text="Network connections", value="network", variable=self.running_mode,
                        command=self._show_running_mode).pack(side="left", padx=(12, 0))
        self.running_button = ttk.Button(bar, text="Check now", command=self.check_running)
        self.running_button.pack(side="right")
        self.include_dlls = tk.BooleanVar(value=False)
        self.dll_check = ttk.Checkbutton(bar, text="Include DLLs (slower the first time)", variable=self.include_dlls)
        self.dll_check.pack(side="right", padx=(0, 12))
        self.running_summary = ttk.Label(tab, style="Summary.TLabel", wraplength=int(1100 * self.scale))
        self.running_summary.pack(fill="x", pady=(8, 6))

        panes = ttk.PanedWindow(tab, orient="vertical")
        panes.pack(fill="both", expand=True)
        self.running_holder = ttk.Frame(panes)
        self.programs_table = Table(self.running_holder, [("verdict", "Verdict", 100), ("name", "File", 260),
                                                          ("kind", "Type", 80), ("used", "Used by", 220),
                                                          ("details", "Details", 480)],
                                    self._show_running_row, self.scale)
        self.network_table = Table(self.running_holder, [("verdict", "Verdict", 100), ("address", "Address", 260),
                                                         ("what", "Seen as", 120), ("programs", "Programs", 220),
                                                         ("details", "Details", 440)],
                                   self._show_running_row, self.scale)
        panes.add(self.running_holder, weight=3)
        lower = ttk.Frame(panes)
        buttons = ttk.Frame(lower)
        buttons.pack(side="bottom", fill="x", pady=(6, 0))
        self.running_location = ttk.Button(buttons, text="Open file location", state="disabled",
                                           command=self._open_running_location)
        self.running_location.pack(side="left")
        self.running_end = ttk.Button(buttons, text="End program...", state="disabled", command=self._end_program)
        self.running_end.pack(side="left", padx=(6, 0))
        self.running_defender = ttk.Button(buttons, text="Ask Defender", state="disabled",
                                           command=lambda: self._ask_defender(self._running_path()))
        self.running_defender.pack(side="left", padx=(6, 0))
        self.running_vt = ttk.Button(buttons, text="View on VirusTotal", state="disabled",
                                     command=lambda: self._running_link and webbrowser.open(self._running_link))
        self.running_vt.pack(side="right")
        self.running_detail = DetailBox(lower)
        self.running_detail.pack(fill="both", expand=True)
        panes.add(lower, weight=1)
        self.running_files: dict = {}
        self.network_checks: dict = {}
        self._running_link: str | None = None
        self._show_running_mode()
        return tab

    def _show_running_mode(self) -> None:
        programs = self.running_mode.get() == "programs"
        (self.network_table if programs else self.programs_table).pack_forget()
        (self.programs_table if programs else self.network_table).pack(fill="both", expand=True)
        for button in (self.running_location, self.running_end, self.running_vt, self.running_defender):
            button.configure(state="disabled")
        if programs:
            self.dll_check.pack(side="right", padx=(0, 12))
            self.running_summary.configure(text=self._programs_summary or
                                           "Click Check now to look up every running program with VirusTotal.")
            self.running_detail.show([("", "Is anything bad running right now? Atlas looks up the file behind every "
                                           "running program, and optionally the DLLs they've loaded from outside "
                                           "the Windows folder. Nothing is stopped unless you press End program.",
                                       None)])
        else:
            self.dll_check.pack_forget()
            self.running_summary.configure(text=self._network_summary or
                                           "Click Check now to see which programs are talking to the internet.")
            self.running_detail.show([("", "Which programs are connected to the internet right now, and is any of "
                                           "them talking to a server VirusTotal knows is bad? Atlas only looks; "
                                           "nothing is blocked.", None)])

    _programs_summary = ""
    _network_summary = ""

    def check_running(self) -> None:
        programs = self.running_mode.get() == "programs"
        dlls = self.include_dlls.get()
        self.running_button.configure(state="disabled")

        def progress(text: str) -> None:
            self._ui_queue.put(lambda: self.running_summary.configure(text=text))

        def work():
            if programs:
                return processes.check_running(self.scanner, include_dlls=dlls, progress=progress)
            return network.check_network(self.scanner, progress=progress)

        def done(result) -> None:
            self.running_button.configure(state="normal")
            if result is None:
                return
            if programs:
                self._fill_programs(result)
            else:
                self._fill_network(result)

        progress("Starting...")
        self.in_background(work, done)

    def _fill_programs(self, report) -> None:
        self.running_files = {str(i): f for i, f in enumerate(report.files)}
        self.programs_table.replace([
            (iid, (f.verdict.value.upper(), f.path.name, f.kind, ", ".join(sorted(f.used_by))[:80],
                   f.result.reasons[0] if f.result.reasons else ""), (f.verdict.value,))
            for iid, f in self.running_files.items()])
        counts = Counter(f.verdict for f in report.files)
        programs = sum(1 for f in report.files if f.kind == "program")
        text = (f"{programs} programs" + (f" and {len(report.files) - programs} DLLs" if programs < len(report.files)
                                          else "") + f" checked: {counts[Verdict.MALICIOUS]} malicious, "
                f"{counts[Verdict.SUSPICIOUS]} suspicious, {counts[Verdict.UNKNOWN]} unknown")
        if report.unreadable:
            text += f"  ·  {report.unreadable} process(es) need administrator rights to look into"
        self._programs_summary = "; ".join(report.errors) or text
        self.running_summary.configure(text=self._programs_summary)

    def _fill_network(self, report) -> None:
        checks = report.addresses + report.sites
        self.network_checks = {str(i): c for i, c in enumerate(checks)}
        self.network_table.replace([
            (iid, (c.verdict.value.upper(), c.target, "Connection" if c.kind == "ip" else "Looked up",
                   ", ".join(c.programs) or "-", c.reasons[0] if c.reasons else ""), (c.verdict.value,))
            for iid, c in self.network_checks.items()])
        text = (f"{len(report.addresses)} internet addresses in use, {len(report.flagged)} flagged")
        if report.sites:
            text += f"  ·  {len(report.sites)} recently looked-up sites checked"
        elif not report.dns_available:
            text += ("  ·  Recently looked-up sites: Windows only shows that list to administrators on this PC, "
                     "so only live connections were checked")
        self._network_summary = "; ".join(report.errors) or text
        self.running_summary.configure(text=self._network_summary)

    def _running_selected(self):
        if self.running_mode.get() == "programs":
            return self.running_files.get(self.programs_table.selection() or "")
        return self.network_checks.get(self.network_table.selection() or "")

    def _show_running_row(self, iid: str) -> None:
        item = self._running_selected()
        if item is None:
            return
        if isinstance(item, processes.RunningFile):
            r = item.result
            v = r.verdict.value
            lines = [("Verdict", v.upper(), v), ("File", str(item.path), None), ("Type", item.kind, None),
                     ("Used by", ", ".join(sorted(item.used_by)), None)]
            if r.signer_text:
                lines.append(("Publisher", r.signer_text, None))
            lines += [("Why", reason, None) for reason in r.reasons] + threat_lines(r)
            if r.sha256:
                lines.append(("SHA-256", r.sha256, None))
            self._running_link = r.file_report.gui_link if r.file_report and r.file_report.found else None
            self.running_location.configure(state="normal")
            self.running_end.configure(state="normal")
        else:
            v = item.verdict.value
            lines = [("Verdict", v.upper(), v), ("Address" if item.kind == "ip" else "Site", item.target, None)]
            if item.hostnames:
                lines.append(("Names", ", ".join(item.hostnames[:5]), None))
            for c in item.connections:
                lines.append(("Program", f"{c.program} (process {c.pid}), port {c.port}" +
                              (f": {c.path}" if c.path else ""), None))
            lines += [("Why", reason, None) for reason in item.reasons]
            self._running_link = item.report.gui_link if item.report and item.report.found else None
            has_program = network.program_path(item) is not None
            self.running_location.configure(state="normal" if has_program else "disabled")
            self.running_end.configure(state="normal" if item.connections else "disabled")
        self.running_detail.show(lines)
        self.running_vt.configure(state="normal" if self._running_link else "disabled")
        self.running_defender.configure(state="normal" if self._running_path() else "disabled")

    def _running_path(self) -> Path | None:
        item = self._running_selected()
        return item.path if isinstance(item, processes.RunningFile) else network.program_path(item) if item else None

    def _open_running_location(self) -> None:
        path = self._running_path()
        if path:
            open_in_explorer(path)

    def _ask_defender(self, path: Path | None) -> None:
        """Second opinion: Defender scans the file now and only reports (it's told not to act)."""
        if not path:
            return
        self.root.configure(cursor="watch")

        def done(scan) -> None:
            self.root.configure(cursor="")
            if scan is None:
                return
            if scan.clean is False:
                messagebox.showwarning(WINDOW_TITLE, f"{path.name}\n\n{scan.message}.\n\nDefender was told only to "
                                                     "report, not to act. Open Windows Security to remove it, or use "
                                                     "Atlas's quarantine.")
            else:
                messagebox.showinfo(WINDOW_TITLE, f"{path.name}\n\n{scan.message}.")

        self.in_background(lambda: defender.scan_file(path), done)

    def _end_program(self) -> None:
        item = self._running_selected()
        if item is None:
            return
        if isinstance(item, processes.RunningFile):
            pids, names = item.pids, sorted(item.used_by)
        else:
            pids, names = {c.pid for c in item.connections}, item.programs
        if not messagebox.askyesno(WINDOW_TITLE, f"End {', '.join(names)} ({len(pids)} process(es))?\n\n"
                                                 "Unsaved work in it will be lost. It may start again later if it's "
                                                 "set to start automatically (see Startup items).", icon="warning"):
            return
        problems = processes.end_processes(pids)
        log.info("Ended %s (pids %s) from the Running now tab", names, sorted(pids))
        if problems:
            messagebox.showwarning(WINDOW_TITLE, "\n".join(problems))
        self.check_running()

    # --- Installed programs -------------------------------------------------------

    def _build_installed_tab(self, parent) -> ttk.Frame:
        tab = ttk.Frame(parent, padding=10)
        bar = ttk.Frame(tab)
        bar.pack(fill="x")
        self.installed_summary = ttk.Label(bar, style="Summary.TLabel", wraplength=int(950 * self.scale),
                                           text="Click Check now to look up every installed program with VirusTotal "
                                                "and spot adware and other potentially unwanted programs.")
        self.installed_summary.pack(side="left", fill="x", expand=True)
        self.installed_button = ttk.Button(bar, text="Check now", command=self.check_installed)
        self.installed_button.pack(side="right")
        panes = ttk.PanedWindow(tab, orient="vertical")
        panes.pack(fill="both", expand=True, pady=(8, 0))
        self.installed_table = Table(panes, [("verdict", "Status", 110), ("name", "Program", 330),
                                             ("publisher", "Publisher", 200), ("date", "Installed", 100),
                                             ("size", "Size", 80), ("details", "Details", 420)],
                                     self._show_installed_row, self.scale)
        self.installed_table.tree.tag_configure("unwanted", foreground=VERDICT_COLORS["suspicious"])
        panes.add(self.installed_table, weight=3)
        lower = ttk.Frame(panes)
        buttons = ttk.Frame(lower)
        buttons.pack(side="bottom", fill="x", pady=(6, 0))
        self.installed_uninstall = ttk.Button(buttons, text="Uninstall...", state="disabled",
                                              command=self._uninstall)
        self.installed_uninstall.pack(side="left")
        self.installed_location = ttk.Button(buttons, text="Open file location", state="disabled",
                                             command=lambda: self._installed_file() and
                                             open_in_explorer(self._installed_file()))
        self.installed_location.pack(side="left", padx=(6, 0))
        self.installed_defender = ttk.Button(buttons, text="Ask Defender", state="disabled",
                                             command=lambda: self._ask_defender(self._installed_file()))
        self.installed_defender.pack(side="left", padx=(6, 0))
        self.installed_vt = ttk.Button(buttons, text="View on VirusTotal", state="disabled",
                                       command=lambda: self._installed_link and webbrowser.open(self._installed_link))
        self.installed_vt.pack(side="right")
        self.installed_detail = DetailBox(lower)
        self.installed_detail.pack(fill="both", expand=True)
        panes.add(lower, weight=1)
        self.installed_programs: dict = {}
        self._installed_link: str | None = None
        return tab

    def check_installed(self) -> None:
        self.installed_button.configure(state="disabled")

        def progress(text: str) -> None:
            self._ui_queue.put(lambda: self.installed_summary.configure(text=text))

        def done(programs) -> None:
            self.installed_button.configure(state="normal")
            if programs is None:
                return
            self.installed_programs = {str(i): p for i, p in enumerate(programs)}
            self.installed_table.replace([
                (iid, (p.status, p.name, p.publisher or "-", p.installed_on or "-",
                       f"{p.size_mb:,.0f} MB" if p.size_mb else "-", p.reasons[0] if p.reasons else ""),
                 ("unwanted",) if p.status == "UNWANTED" else (p.verdict.value,))
                for iid, p in self.installed_programs.items()])
            look = sum(1 for p in programs if p.verdict is not Verdict.CLEAN)
            checked = sum(1 for p in programs if p.file and p.file.result)
            self.installed_summary.configure(
                text=f"{len(programs)} programs installed, {checked} looked up on VirusTotal: {look} need a look"
                     + ("" if self.scanner.vt else "  ·  No VirusTotal key, so only names were checked"))

        progress("Starting...")
        self.in_background(lambda: installed.check_installed(self.scanner, progress), done)

    def _selected_program(self):
        return self.installed_programs.get(self.installed_table.selection() or "")

    def _installed_file(self) -> Path | None:
        p = self._selected_program()
        return p.file.path if p and p.file else None

    def _show_installed_row(self, iid: str) -> None:
        p = self._selected_program()
        if p is None:
            return
        v = p.verdict.value
        lines = [("Status", p.status, v), ("Program", f"{p.name}  {p.version}".strip(), None),
                 ("Publisher", p.publisher or "(none given)", None), ("For", p.scope, None)]
        if p.installed_on:
            lines.append(("Installed", f"{p.installed_on} (or last updated)", None))
        if p.file:
            lines.append(("Program file", str(p.file.path), None))
            if p.file.result and p.file.result.signer_text:
                lines.append(("Publisher", p.file.result.signer_text, None))
        lines += [("Why", r, None) for r in p.reasons]
        if p.file and p.file.result:
            lines += threat_lines(p.file.result)
        self.installed_detail.show(lines)
        report = p.file.result.file_report if p.file and p.file.result else None
        self._installed_link = report.gui_link if report and report.found else None
        self.installed_vt.configure(state="normal" if self._installed_link else "disabled")
        self.installed_uninstall.configure(state="normal" if p.uninstall else "disabled")
        for button in (self.installed_location, self.installed_defender):
            button.configure(state="normal" if p.file else "disabled")

    def _uninstall(self) -> None:
        p = self._selected_program()
        if p is None:
            return
        if not messagebox.askyesno(WINDOW_TITLE, f"Uninstall {p.name}?\n\nAtlas starts the program's own uninstaller. "
                                                 "Windows may ask for permission. Watch its screens: some adware "
                                                 "uninstallers try to talk you out of it or offer \"deals\".",
                                   icon="warning"):
            return
        try:
            installed.run_uninstaller(p)
        except OSError as exc:
            messagebox.showerror(WINDOW_TITLE, str(exc))
            return
        messagebox.showinfo(WINDOW_TITLE, "The uninstaller has started. When it's finished, click Check now to "
                                          "refresh the list.")

    # --- Protection: Defender and hijacks ------------------------------------------------

    def _build_protection_tab(self, parent) -> ttk.Frame:
        tab = ttk.Frame(parent, padding=10)
        bar = ttk.Frame(tab)
        bar.pack(fill="x")
        self.protection_summary = ttk.Label(bar, style="Summary.TLabel", wraplength=int(950 * self.scale),
                                            text="Is Defender on and untouched, are your programs and Windows up "
                                                 "to date, are your drives healthy, is a remote-access program "
                                                 "running, and has anything changed your browser, proxy, hosts file "
                                                 "or DNS? Click Check now.")
        self.protection_summary.pack(side="left", fill="x", expand=True)
        self.protection_button = ttk.Button(bar, text="Check now", command=self.check_protection)
        self.protection_button.pack(side="right")
        panes = ttk.PanedWindow(tab, orient="vertical")
        panes.pack(fill="both", expand=True, pady=(8, 0))
        self.protection_table = Table(panes, [("verdict", "Status", 120), ("area", "Area", 200),
                                              ("details", "Finding", 760)], self._show_protection_row, self.scale)
        self.protection_table.tree.tag_configure("warn", foreground=VERDICT_COLORS["suspicious"])
        self.protection_table.tree.tag_configure("note", foreground="#444444")
        self.protection_table.tree.tag_configure("ok", foreground=VERDICT_COLORS["clean"])
        panes.add(self.protection_table, weight=3)
        lower = ttk.Frame(panes)
        buttons = ttk.Frame(lower)
        buttons.pack(side="bottom", fill="x", pady=(6, 0))
        self.protection_fix = ttk.Button(buttons, text="Fix...", state="disabled", command=self._fix_finding)
        self.protection_fix.pack(side="left")
        self.protection_vt = ttk.Button(buttons, text="View on VirusTotal", state="disabled",
                                        command=lambda: self._protection_link and webbrowser.open(self._protection_link))
        self.protection_vt.pack(side="right")
        self.protection_detail = DetailBox(lower)
        self.protection_detail.pack(fill="both", expand=True)
        panes.add(lower, weight=1)
        self.protection_findings: dict = {}
        self._protection_link: str | None = None
        return tab

    def check_protection(self) -> None:
        self.protection_button.configure(state="disabled")
        self.protection_summary.configure(text="Checking Defender, updates, drives, browsers, proxy, hosts file "
                                               "and DNS...")

        def done(findings) -> None:
            self.protection_button.configure(state="normal")
            if findings is not None:
                self._fill_protection(findings)

        self.in_background(lambda: protection.check_system(self.scanner), done)

    def _fill_protection(self, findings) -> None:
        self.protection_findings = {str(i): f for i, f in enumerate(findings)}
        label = {"warn": "NEEDS A LOOK", "note": "NOTE", "ok": "OK"}
        self.protection_table.replace([(iid, (label.get(f.level, f.level), f.area, f.title), (f.level,))
                                       for iid, f in self.protection_findings.items()])
        look = sum(1 for f in findings if f.needs_look)
        self.protection_summary.configure(text=f"{len(findings)} checks: " +
                                          (f"{look} need a look" if look else "nothing needs a look"))
        self.store.new_findings([f.key for f in findings if f.needs_look and f.key])  # tray won't repeat these

    def _show_protection_row(self, iid: str) -> None:
        f = self.protection_findings.get(iid)
        if f is None:
            return
        tag = {"warn": "suspicious", "ok": "clean"}.get(f.level)
        lines = [("Status", {"warn": "Needs a look", "note": "Note", "ok": "OK"}.get(f.level, f.level), tag),
                 ("Area", f.area, None), ("Finding", f.title, None)] + [("Why", d, None) for d in f.details]
        self.protection_detail.show(lines)
        self._protection_link = f.vt_link
        self.protection_vt.configure(state="normal" if f.vt_link else "disabled",
                                     text="View on CISA" if f.vt_link and "cisa.gov" in f.vt_link
                                     else "View on VirusTotal")
        self.protection_fix.configure(text=f.fix_label or "Fix...", state="normal" if f.fix else "disabled")

    def _fix_finding(self) -> None:
        f = self.protection_findings.get(self.protection_table.selection() or "")
        if f is not None and f.fix:
            self._run_fix(f, self.check_protection)

    def _run_fix(self, f, then: Callable[[], None]) -> None:
        question = protection.describe_fix(f)
        if question and not messagebox.askyesno(WINDOW_TITLE, question):
            return
        try:
            message = protection.apply_fix(f)
        except (OSError, ValueError) as exc:
            messagebox.showerror(WINDOW_TITLE, f"That didn't work:\n\n{exc}")
            return
        if message:
            messagebox.showinfo(WINDOW_TITLE, message)
            then()

    def _check_password(self) -> None:
        password = simpledialog.askstring(
            WINDOW_TITLE, "Type a password to see whether it has appeared in a data leak.\n\nIt never leaves this "
                          "PC: Atlas sends only the first 5 characters of a scrambled (hashed) version to Have I Been "
                          "Pwned, and nothing is saved.", show="*", parent=self.root)
        if not password:
            return

        def done(count) -> None:
            if count is not None:
                (messagebox.showwarning if count else messagebox.showinfo)(WINDOW_TITLE, pwned.verdict(count))

        self.in_background(lambda: pwned.times_leaked(password), done)

    # --- Full scan ---------------------------------------------------------------

    def _build_fullscan_tab(self, parent) -> ttk.Frame:
        tab = ttk.Frame(parent, padding=10)
        bar = ttk.Frame(tab)
        bar.pack(fill="x")
        self.fullscan_summary = ttk.Label(
            bar, style="Summary.TLabel", wraplength=int(760 * self.scale),
            text="Checks every program file on your drives with VirusTotal, riskiest places first, at low priority so "
                 f"the PC stays quick. It uses up to {self.settings.full_scan_lookups} new lookups a run (a free key "
                 "does 4 a minute, so this takes a while) and carries on where it stopped next time. Only looks.")
        self.fullscan_summary.pack(side="left", fill="x", expand=True)
        self.fullscan_button = ttk.Button(bar, text="Start full scan", command=self.start_fullscan)
        self.fullscan_button.pack(side="right")
        ttk.Button(bar, text="Defender offline scan...", command=lambda: self._defender_scan(offline=True)
                   ).pack(side="right", padx=(0, 6))
        ttk.Button(bar, text="Defender full scan...", command=lambda: self._defender_scan(offline=False)
                   ).pack(side="right", padx=(0, 6))
        panes = ttk.PanedWindow(tab, orient="vertical")
        panes.pack(fill="both", expand=True, pady=(8, 0))
        self.fullscan_table = Table(panes, [("verdict", "Verdict", 100), ("name", "File", 240),
                                            ("path", "Folder", 520), ("details", "Details", 360)],
                                    self._show_fullscan_row, self.scale)
        panes.add(self.fullscan_table, weight=3)
        lower = ttk.Frame(panes)
        buttons = ttk.Frame(lower)
        buttons.pack(side="bottom", fill="x", pady=(6, 0))
        self.fullscan_location = ttk.Button(buttons, text="Open file location", state="disabled",
                                            command=lambda: self._fullscan_path() and
                                            open_in_explorer(self._fullscan_path()))
        self.fullscan_location.pack(side="left")
        self.fullscan_quarantine = ttk.Button(buttons, text="Quarantine...", state="disabled",
                                              command=self._quarantine_fullscan)
        self.fullscan_quarantine.pack(side="left", padx=(6, 0))
        self.fullscan_defender = ttk.Button(buttons, text="Ask Defender", state="disabled",
                                            command=lambda: self._ask_defender(self._fullscan_path()))
        self.fullscan_defender.pack(side="left", padx=(6, 0))
        self.fullscan_vt = ttk.Button(buttons, text="View on VirusTotal", state="disabled",
                                      command=lambda: self._fullscan_link and webbrowser.open(self._fullscan_link))
        self.fullscan_vt.pack(side="right")
        self.fullscan_detail = DetailBox(lower)
        self.fullscan_detail.pack(fill="both", expand=True)
        panes.add(lower, weight=1)
        self.fullscan_detail.show([("", "Files Atlas flags appear here. Unknown means VirusTotal has never seen it and "
                                        "it isn't validly signed: often harmless (your own tools, games), but worth a "
                                        "look if you don't recognise it.", None)])
        self.fullscan_files: dict = {}
        self._fullscan_link: str | None = None
        self._fullscan_cancel: threading.Event | None = None
        return tab

    def start_fullscan(self) -> None:
        if self._fullscan_cancel is not None:  # running: this is the Stop button
            self._fullscan_cancel.set()
            self.fullscan_button.configure(state="disabled", text="Stopping...")
            return
        from atlas import fullscan

        cancel = self._fullscan_cancel = threading.Event()
        self.fullscan_button.configure(text="Stop")

        def progress(text: str) -> None:
            self._ui_queue.put(lambda: self.fullscan_summary.configure(text=text))

        def done(report) -> None:
            self._fullscan_cancel = None
            self.fullscan_button.configure(state="normal", text="Start full scan")
            if report is None:
                return
            self.fullscan_files = {str(i): f for i, f in enumerate(report.files)}
            self.fullscan_table.replace([(iid, (f.verdict.value.upper(), f.path.name, str(f.path.parent),
                                                f.result.reasons[0] if f.result.reasons else ""), (f.verdict.value,))
                                         for iid, f in self.fullscan_files.items()])
            self.fullscan_summary.configure(text=fullscan.summary(report))

        self.in_background(lambda: fullscan.full_scan(self.scanner, self.settings.full_scan_lookups, progress=progress,
                                                      cancel=cancel), done)

    def _fullscan_selected(self):
        return self.fullscan_files.get(self.fullscan_table.selection() or "")

    def _fullscan_path(self) -> Path | None:
        item = self._fullscan_selected()
        return item.path if item else None

    def _show_fullscan_row(self, iid: str) -> None:
        item = self._fullscan_selected()
        if item is None:
            return
        r = item.result
        v = r.verdict.value
        lines = [("Verdict", v.upper(), v), ("File", str(item.path), None)]
        if r.signer_text:
            lines.append(("Publisher", r.signer_text, None))
        lines += [("Why", reason, None) for reason in r.reasons] + threat_lines(r)
        if r.sha256:
            lines.append(("SHA-256", r.sha256, None))
        self.fullscan_detail.show(lines)
        self._fullscan_link = r.file_report.gui_link if r.file_report and r.file_report.found else None
        for button in (self.fullscan_location, self.fullscan_quarantine, self.fullscan_defender):
            button.configure(state="normal")
        self.fullscan_vt.configure(state="normal" if self._fullscan_link else "disabled")

    def _quarantine_fullscan(self) -> None:
        item = self._fullscan_selected()
        if item is None or not item.result.sha256:
            return
        if not messagebox.askyesno(WINDOW_TITLE, f"Move {item.path.name} to quarantine?\n\n{item.path}\n\nIt's "
                                                 "moved somewhere it can't run. You can put it back from the "
                                                 "Quarantine tab. If a program needs it, that program may stop "
                                                 "working until you do.", icon="warning"):
            return
        try:
            quarantine_file(item.path, item.result.sha256, f"Full scan: {item.verdict.value}", self.store,
                            config.data_dir())
        except OSError as exc:
            messagebox.showerror(WINDOW_TITLE, f"Couldn't move it (is it running? End it first):\n\n{exc}")
            return
        iid = self.fullscan_table.selection()
        self.fullscan_files.pop(iid, None)
        self.fullscan_table.tree.delete(iid)
        messagebox.showinfo(WINDOW_TITLE, f"{item.path.name} is in quarantine.")

    def _defender_scan(self, offline: bool) -> None:
        if offline:
            question = ("Start Microsoft Defender's offline scan?\n\nWindows asks for administrator permission, then "
                        "RESTARTS the PC within a minute and scans for about 15 minutes before Windows starts, where "
                        "hidden malware can't fight back. Save your work and close programs first.")
        else:
            question = ("Start Microsoft Defender's full scan?\n\nWindows asks for administrator permission. Defender "
                        "then scans the whole PC in the background (often an hour or more) and shows what it finds "
                        "in Windows Security.")
        if not messagebox.askyesno(WINDOW_TITLE, question, icon="warning" if offline else "question"):
            return
        try:
            protection.start_defender_scan(offline)
        except OSError as exc:
            messagebox.showerror(WINDOW_TITLE, str(exc))

    # --- Scam check ----------------------------------------------------------------

    def _build_scam_tab(self, parent) -> ttk.Frame:
        tab = ttk.Frame(parent, padding=10)
        self._fit(ttk.Label(tab, style="Summary.TLabel",
                  text="Got an email, text or pop-up you're not sure about? Paste the text or a screenshot "
                       "(Win+Shift+S), or open the email itself: it shows Atlas the real links, sender and "
                       "attachments. Atlas looks for the usual scam tricks and checks links with VirusTotal. "
                       "Nothing else leaves this PC."))
        bar = ttk.Frame(tab)
        bar.pack(fill="x", pady=(8, 0))
        ttk.Button(bar, text="Open email or screenshot...", command=self._open_message_file).pack(side="left")
        ttk.Button(bar, text="Paste", command=self._paste_scam).pack(side="left", padx=(6, 0))
        ttk.Button(bar, text="Clear", command=self._clear_scam).pack(side="left", padx=(6, 0))
        ttk.Button(bar, text="Check", command=self.check_scam).pack(side="right")
        self._fit(ttk.Label(tab, style="Hint.TLabel",
                  text="Getting an email file: in Outlook on the PC, drag the email to the desktop. In Gmail: "
                       "\u22ee > Download message. In Outlook on the web: \u22ef > Save > Save as. Then drop the file "
                       "on the box below, or click Open."), pady=(6, 0))
        from atlas import unelevate

        if unelevate.is_elevated():  # Windows blocks dragging from Explorer into an administrator window
            self._fit(ttk.Label(tab, style="Hint.TLabel",
                      text="Atlas is running as administrator, so Windows won't let you drag files in: click "
                           "Open instead, or restart Atlas from the Start menu."), pady=(4, 0))
        panes = ttk.PanedWindow(tab, orient="vertical")
        panes.pack(fill="both", expand=True, pady=(8, 0))
        self.scam_text = tk.Text(panes, height=8, wrap="word", font=("Segoe UI", 10), padx=10, pady=8, undo=True)
        panes.add(self.scam_text, weight=1)
        self.scam_detail = DetailBox(panes)
        panes.add(self.scam_detail, weight=2)
        from atlas import dropfiles

        self.root.after(200, lambda: dropfiles.accept_files(self.scam_text, self._message_files))
        return tab

    @staticmethod
    def _fit(label: ttk.Label, pady=0) -> None:
        """Pack a label that wraps to the width it's given, whatever the window size."""
        label.pack(fill="x", anchor="w", pady=pady)
        label.bind("<Configure>", lambda e: label.configure(wraplength=max(100, e.width - 4)))

    def _clear_scam(self) -> None:
        self.scam_text.delete("1.0", "end")
        self.scam_detail.show([])

    def _paste_scam(self) -> None:
        """Text, or a screenshot on the clipboard (read with Windows' text recognition)."""
        from atlas import ocr

        try:
            image = ocr.clipboard_image()
        except Exception:  # an odd clipboard format: fall back to text
            image = None
        if image is not None:
            self._read_screenshot(lambda: ocr.read_image(image))
            return
        try:
            text = self.root.clipboard_get()
        except tk.TclError:
            return
        self.scam_text.delete("1.0", "end")
        self.scam_text.insert("1.0", text)
        self.check_scam()

    def _read_screenshot(self, read: Callable[[], str]) -> None:
        from atlas import ocr

        self.show_tab("Message and link check")
        self.scam_detail.show([("", "Reading the screenshot...", None)])

        def work():
            try:
                return read()
            except (ocr.OcrError, OSError) as exc:
                return exc

        def done(text) -> None:
            if isinstance(text, Exception) or not text:
                self.scam_detail.show([("", f"Couldn't read any words in that picture. {text or ''}", None)])
                return
            self.scam_text.delete("1.0", "end")
            self.scam_text.insert("1.0", text)
            self.check_scam()

        self.in_background(work, done)

    def _open_message_file(self) -> None:
        from tkinter import filedialog

        path = filedialog.askopenfilename(parent=self.root, title="Open an email or a screenshot", filetypes=[
            ("Emails and screenshots", "*.eml *.msg *.png *.jpg *.jpeg *.bmp *.gif"), ("Emails", "*.eml *.msg"),
            ("Pictures", "*.png *.jpg *.jpeg *.bmp *.gif"), ("All files", "*.*")])
        if path:
            self._message_files([path])

    def _message_files(self, paths: list[str]) -> None:
        """An email file or a picture, opened or dropped on the message box."""
        from atlas import emailcheck, ocr

        path = Path(paths[0])
        suffix = path.suffix.lower()
        if suffix in ocr.IMAGE_TYPES:
            self._read_screenshot(lambda: ocr.read_file(path))
        elif suffix in emailcheck.EMAIL_TYPES:
            self.check_email(path)
        else:
            messagebox.showinfo(WINDOW_TITLE, "Drop an email file (.eml or .msg) or a screenshot here. To check "
                                              "a program or document, right-click it > Scan with Project Atlas.")

    def check_email(self, path: Path) -> None:
        from atlas import emailcheck

        self.show_tab("Message and link check")
        self.scam_text.delete("1.0", "end")
        self.scam_text.insert("1.0", f"Email file: {path}")
        self.scam_detail.show([("", f"Checking {path.name}...", None)])

        def work():
            try:
                return emailcheck.check_email(path, self.scanner)
            except (OSError, ValueError) as exc:
                return exc

        def done(result) -> None:
            if isinstance(result, Exception):
                self.scam_detail.show([("", f"Couldn't read that email: {result}", None)])
            elif result is not None:
                self.scam_detail.show(scam_lines(result))

        self.in_background(work, done)

    def check_scam(self) -> None:
        from atlas import scam

        text = self.scam_text.get("1.0", "end").strip()
        if not text:
            return
        if text.startswith("Email file: ") and "\n" not in text:
            self.check_email(Path(text.removeprefix("Email file: ")))
            return
        self.scam_detail.show([("", "Checking...", None)])
        self.in_background(lambda: scam.check_message(text, self.scanner),
                           lambda result: result is not None and self.scam_detail.show(scam_lines(result)))

    def _build_hunt_tab(self, parent) -> ttk.Frame:
        tab = ttk.Frame(parent, padding=10)
        bar = ttk.Frame(tab)
        bar.pack(fill="x")
        self.hunt_summary = ttk.Label(bar, style="Summary.TLabel", wraplength=int(800 * self.scale),
                                      text="What a hash lookup can't see: suspicious command lines, rogue root "
                                           "certificates, vulnerable drivers, programs accepting connections, "
                                           "unsigned programs in user folders and threat-intel matches. Click Check now.")
        self.hunt_summary.pack(side="left", fill="x", expand=True)
        self.hunt_deep = ttk.Button(bar, text="Deep check (administrator)...", command=lambda: self.check_hunt(True))
        self.hunt_deep.pack(side="right", padx=(6, 0))
        self.hunt_button = ttk.Button(bar, text="Check now", command=self.check_hunt)
        self.hunt_button.pack(side="right")
        self.hunt_intel = ttk.Label(tab, style="Muted.TLabel", text=self._intel_text())
        self.hunt_intel.pack(anchor="w", pady=(4, 0))
        panes = ttk.PanedWindow(tab, orient="vertical")
        panes.pack(fill="both", expand=True, pady=(6, 0))
        self.hunt_table = Table(panes, [("verdict", "Status", 120), ("area", "Area", 160),
                                        ("details", "Finding", 800)], self._show_hunt_row, self.scale)
        self.hunt_table.tree.tag_configure("warn", foreground=VERDICT_COLORS["suspicious"])
        self.hunt_table.tree.tag_configure("note", foreground="#444444")
        self.hunt_table.tree.tag_configure("ok", foreground=VERDICT_COLORS["clean"])
        panes.add(self.hunt_table, weight=3)
        lower = ttk.Frame(panes)
        buttons = ttk.Frame(lower)
        buttons.pack(side="bottom", fill="x", pady=(6, 0))
        self.hunt_fix = ttk.Button(buttons, text="Open...", state="disabled", command=self._hunt_fix)
        self.hunt_fix.pack(side="left")
        self.hunt_location = ttk.Button(buttons, text="Open file location", state="disabled",
                                        command=lambda: self._hunt_path() and open_in_explorer(self._hunt_path()))
        self.hunt_location.pack(side="left", padx=6)
        self.hunt_defender = ttk.Button(buttons, text="Ask Defender", state="disabled",
                                        command=lambda: self._ask_defender(self._hunt_path()))
        self.hunt_defender.pack(side="left")
        self.hunt_regedit = ttk.Button(buttons, text="Open in Registry Editor", state="disabled",
                                       command=self._hunt_regedit)
        self.hunt_regedit.pack(side="left", padx=6)
        self.hunt_link = ttk.Button(buttons, text="Open report", state="disabled",
                                    command=lambda: self._hunt_url and webbrowser.open(self._hunt_url))
        self.hunt_link.pack(side="right")
        self.hunt_mistake = ttk.Button(buttons, text="Report a mistake...", state="disabled",
                                       command=self._hunt_mistake)
        self.hunt_mistake.pack(side="right", padx=6)
        self.hunt_detail = DetailBox(lower)
        self.hunt_detail.pack(fill="both", expand=True)
        panes.add(lower, weight=1)
        self.hunt_findings: dict = {}
        self._hunt_url: str | None = None
        return tab

    def _intel_text(self) -> str:
        reports, iocs = self.store.gti_stats()
        last = gti.last_sync(self.store)
        if not reports and last is None:
            return "Google Threat Intelligence: used automatically with a VirusTotal Enterprise / GTI key."
        when = last.astimezone().strftime("%Y-%m-%d %H:%M") if last else "never"
        return (f"Google Threat Intelligence: {iocs:,} indicators from {reports} Windows threat reports of the last "
                f"{self.scanner.settings.gti_days} days (updated {when}).")

    def check_hunt(self, deep: bool = False) -> None:
        if deep and not messagebox.askyesno(
                WINDOW_TITLE, "The deep check reads what Windows only shows administrators: Defender's exclusions, "
                              "the DNS cache, failed sign-ins and new accounts, every process's command line and WMI "
                              "subscriptions.\n\nWindows will ask for permission. It only reads; nothing is changed. "
                              "Continue?"):
            return
        self.hunt_button.configure(state="disabled")
        self.hunt_deep.configure(state="disabled")
        self.hunt_summary.configure(text="Waiting for Windows' permission..." if deep else "Starting...")

        def progress(text: str) -> None:
            self._ui_queue.put(lambda: self.hunt_summary.configure(text=text))

        def work():
            data = deepcheck.run_elevated() if deep else None
            return hunt.check_hunt(self.scanner, progress, deep=data)

        def done(findings) -> None:
            self.hunt_button.configure(state="normal")
            self.hunt_deep.configure(state="normal")
            if findings is None:
                self.hunt_summary.configure(text="The check didn't finish.")
                return
            self._fill_hunt(findings, deep)

        self.in_background(work, done)

    def _fill_hunt(self, findings, deep: bool = False) -> None:
        self.hunt_intel.configure(text=self._intel_text())
        self.hunt_findings = {str(i): f for i, f in enumerate(findings)}
        label = {"warn": "NEEDS A LOOK", "note": "NOTE", "ok": "OK"}
        self.hunt_table.replace([(iid, (label.get(f.level, f.level), f.area, f.title), (f.level,))
                                 for iid, f in self.hunt_findings.items()])
        look = sum(1 for f in findings if f.needs_look)
        self.hunt_summary.configure(text=(f"{look} thing(s) need a look" if look else "Nothing needs a look")
                                    + f" ({len(findings)} findings" + (", with the deep check)" if deep else ")"))
        self.store.new_findings([f.key for f in findings if f.needs_look and f.key])  # tray won't repeat these

    def _hunt_selected(self):
        return self.hunt_findings.get(self.hunt_table.selection() or "")

    def _hunt_path(self) -> Path | None:
        f = self._hunt_selected()
        path = ((f.data or {}).get("path") or (f.data or {}).get("exe")) if f else None
        return Path(path) if path else None

    def _show_hunt_row(self, iid: str) -> None:
        f = self.hunt_findings.get(iid)
        if f is None:
            return
        tag = {"warn": "suspicious", "ok": "clean"}.get(f.level)
        lines = [("Status", {"warn": "Needs a look", "note": "Note", "ok": "OK"}.get(f.level, f.level), tag),
                 ("Area", f.area, None), ("Finding", f.title, None)] + [("Why", d, None) for d in f.details]
        self.hunt_detail.show(lines)
        self._hunt_url = f.vt_link
        url = f.vt_link or ""
        self.hunt_link.configure(state="normal" if url else "disabled",
                                 text="Open GTI report" if "/collection/" in url else "View on VirusTotal"
                                 if "virustotal.com" in url else "MITRE ATT&CK" if "attack.mitre" in url
                                 else "Open LOLDrivers" if "loldrivers" in url else "Open report")
        self.hunt_fix.configure(text=f.fix_label or "Open...", state="normal" if f.fix else "disabled")
        path = self._hunt_path()
        exists = bool(path and path.exists())
        self.hunt_location.configure(state="normal" if exists else "disabled")
        self.hunt_defender.configure(state="normal" if exists and path.is_file() else "disabled")
        self.hunt_regedit.configure(state="normal" if (f.data or {}).get("registry") else "disabled")
        self.hunt_mistake.configure(state="normal" if f.level in ("warn", "note") else "disabled")

    def _hunt_mistake(self) -> None:
        f = self._hunt_selected()
        if f is not None:
            report_mistake(self.root, "Finding", f"{f.area}: {f.title}", f.level, f.details)

    def _hunt_regedit(self) -> None:
        from atlas import registry

        f = self._hunt_selected()
        location = (f.data or {}).get("registry") if f else None
        if not location:
            return
        import psutil

        if any((p.info["name"] or "").lower() == "regedit.exe" for p in psutil.process_iter(["name"])):
            messagebox.showinfo(WINDOW_TITLE, "Registry Editor is already open, and it only jumps to a key when it "
                                              "starts. Close it, then click Open in Registry Editor again.")
            return
        try:
            registry.open_in_regedit(location)
        except OSError as exc:
            messagebox.showerror(WINDOW_TITLE, f"Couldn't open Registry Editor:\n\n{exc}")

    def _hunt_fix(self) -> None:
        f = self._hunt_selected()
        if f is None or not f.fix:
            return
        try:
            protection.apply_fix(f)
        except (OSError, ValueError) as exc:
            messagebox.showerror(WINDOW_TITLE, f"That didn't work:\n\n{exc}")

    def _build_quarantine_tab(self, parent) -> ttk.Frame:
        tab = ttk.Frame(parent, padding=10)
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
    scan = len(sys.argv) > 1 and sys.argv[1] == "--scan"  # from Explorer's right-click menu
    from atlas import unelevate
    from atlas.app import gui_command, scan_command

    if unelevate.restart_unelevated(scan_command(sys.argv[2:]) if scan else gui_command()):  # never as administrator
        return 0
    if scan:
        from atlas.emailcheck import EMAIL_TYPES

        paths = sys.argv[2:]
        if paths and all(Path(p).suffix.lower() in EMAIL_TYPES for p in paths):  # emails: is it a scam?
            from atlas.messagewindow import main as message_main

            return message_main(paths)
        from atlas.scanwindow import main as scan_main

        return scan_main(paths)
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
