"""System tray app: runs the download guard and the startup-item monitor in the background.

The icon is a small globe: blue while protecting, grey while paused, red after an alert
(until you choose "Clear alert").
"""

from __future__ import annotations

import logging
import os
import threading
import time
from collections.abc import Callable

import pystray
from PIL import Image, ImageDraw

from atlas import __version__, autostart, config, contextmenu, unelevate
from atlas.app import (build_scanner, claim_single_instance, launch_gui, log_file, setup_logging, tray_command,
                       watch_folders)
from atlas.autoruns import Autorun, AutorunMonitor
from atlas.links import check_link, read_clipboard
from atlas.notify import notify_autorun, toast
from atlas.processes import NewProgramWatcher
from atlas.quarantine import quarantine_dir
from atlas.scanner import ScanResult, Verdict
from atlas.watcher import DownloadGuard

log = logging.getLogger(__name__)


class RunningMonitor:
    """Checks running programs and network connections every so often.

    Speaks up only about programs or addresses flagged as malicious or suspicious, once each
    per session. Unknown programs are listed in the window's Running now tab instead.
    """

    def __init__(self, scanner, minutes: int, on_finding: Callable[[str, str, str | None], None]):
        self.scanner = scanner
        self.interval = minutes * 60
        self.on_finding = on_finding
        self.paused = False
        self.last_check: str | None = None
        self._told: set[str] = set()
        self._wake = threading.Event()
        self._stop = threading.Event()

    def run(self) -> None:
        delay = 120  # let sign-in settle before the first check
        while True:
            asked = self._wake.wait(delay if self.interval else None)  # interval 0: only when asked
            self._wake.clear()
            if self._stop.is_set():
                return
            if asked or not self.paused:
                self.check()
            delay = self.interval

    def check_now(self) -> None:
        self._wake.set()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()

    def check(self) -> None:
        from atlas.network import check_network
        from atlas.processes import check_running

        try:
            running = check_running(self.scanner)
            net = check_network(self.scanner)
        except Exception:  # never let a bad check end the monitor
            log.exception("Running programs / network check failed")
            return
        self.last_check = time.strftime("%H:%M")
        bad = (Verdict.MALICIOUS, Verdict.SUSPICIOUS)
        for f in running.files:
            key = f"file:{f.result.sha256}"
            if f.verdict in bad and key not in self._told:
                self._told.add(key)
                link = f.result.vt_link
                what = f.result.threat_text or f.result.reasons[0]
                log.warning("Running %s %s is %s: %s", f.kind, f.path, f.verdict.value, "; ".join(f.result.reasons))
                self.on_finding(f"Atlas: {f.verdict.value} program running", f"{f.path.name}\n{what}", link)
        for c in net.flagged:
            key = f"{c.kind}:{c.target}"
            if key not in self._told:
                self._told.add(key)
                link = c.report.gui_link if c.report and c.report.found else None
                who = ", ".join(c.programs) or "This PC"
                log.warning("%s talking to %s: %s", who, c.target, "; ".join(c.reasons))
                self.on_finding(f"Atlas: {c.verdict.value} connection", f"{who} is talking to {c.target}\n"
                                f"{c.reasons[0] if c.reasons else ''}", link)


class SystemMonitor:
    """Re-runs the Protection checks (Defender, browser hijacks, proxy, hosts file, DNS) and the threat hunt
    (command lines, certificates, drivers, open ports, user folders, GTI matches) every so often.

    Alerts when a problem appears that wasn't there before. The very first run only records what's
    already there (it's listed on the Protection page and the tray menu, without a pop-up for each).
    """

    def __init__(self, scanner, store, minutes: int, on_finding: Callable[[str, str, str | None], None]):
        self.scanner, self.store = scanner, store
        self.interval = minutes * 60
        self.on_finding = on_finding
        self.paused = False
        self.needs_look = 0
        self.score = None
        self._wake = threading.Event()
        self._stop = threading.Event()

    def run(self) -> None:
        delay = 180
        while True:
            asked = self._wake.wait(delay if self.interval else None)
            self._wake.clear()
            if self._stop.is_set():
                return
            if asked or not self.paused:
                self.check()
            delay = self.interval

    def check_now(self) -> None:
        self._wake.set()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()

    def _score_and_report(self, findings) -> None:
        from atlas import report, score

        self.score = score.health_score(findings)
        score.record(self.store, self.score)
        if not self.scanner.settings.weekly_report or not report.due(self.store):
            return
        weekly = report.build(self.store, self.score)
        path = report.save(weekly, config.data_dir() / "reports")
        report.mark_sent(self.store)
        log.info("Weekly report: %s (%s)", weekly.summary, path)
        if self.scanner.settings.notifications:
            toast("Your weekly Atlas report", weekly.summary, link=path.as_uri(), link_label="Open the report")

    def check(self) -> None:
        from atlas.hunt import check_hunt
        from atlas.protection import check_system

        try:
            findings = check_system(self.scanner)
        except Exception:
            log.exception("System check failed")
            return
        try:
            findings += check_hunt(self.scanner)  # also downloads new GTI reports once a day
        except Exception:
            log.exception("Threat hunt failed")
        warnings = [f for f in findings if f.needs_look and f.key]
        self.needs_look = len(warnings)
        try:
            self._score_and_report(findings)
        except Exception:
            log.exception("Health score or weekly report failed")
        first_run = not self.store.has_seen_findings()
        fresh = set(self.store.new_findings(["system:checked"] + [f.key for f in warnings]))
        if first_run:
            log.info("First system check: %d thing(s) need a look", len(warnings))
            return
        for f in warnings:
            if f.key in fresh:
                log.warning("New system finding: [%s] %s", f.area, f.title)
                self.on_finding(f"Atlas: {f.area}", f"{f.title}\n{f.details[0] if f.details else ''}", f.vt_link)


STATE_COLORS = {"ok": (37, 99, 235), "paused": (120, 120, 120), "alert": (220, 38, 38)}


def make_icon(state: str) -> Image.Image:
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    white = (255, 255, 255, 255)
    d.ellipse((2, 2, 62, 62), fill=STATE_COLORS[state])
    d.ellipse((20, 4, 44, 60), outline=white, width=3)  # meridian
    d.line((4, 32, 60, 32), fill=white, width=3)  # equator
    d.line((10, 17, 54, 17), fill=white, width=2)
    d.line((10, 47, 54, 47), fill=white, width=2)
    return img


class AtlasTray:
    def __init__(self):
        self.settings = config.Settings.load()
        self.scanner, self.store = build_scanner(self.settings)
        self.guard = DownloadGuard(self.scanner, watch_folders(self.settings),
                                   ignore_dirs=[quarantine_dir(config.data_dir())],
                                   notifications=self.settings.notifications)
        self.guard.listeners.append(self._on_download)
        self.monitor = None
        if self.settings.monitor_autoruns:
            self.monitor = AutorunMonitor(self.scanner, self.store, self.settings.autorun_check_minutes,
                                          self._on_autorun)
        self.running = RunningMonitor(self.scanner, self.settings.running_check_minutes, self._on_running_finding)
        self.system = SystemMonitor(self.scanner, self.store, self.settings.system_check_minutes,
                                    self._on_running_finding)
        self.new_programs = NewProgramWatcher(self.scanner, self._on_running_finding) \
            if self.settings.watch_new_programs else None
        self.update_available: str | None = None
        self._update_stop = threading.Event()
        self.alert: str | None = None
        self.busy: str | None = None
        self.icon = pystray.Icon("ProjectAtlas", make_icon("ok"), "Project Atlas", menu=self._menu())

    # --- Menu ----------------------------------------------------------------

    def _menu(self) -> pystray.Menu:
        item = pystray.MenuItem
        return pystray.Menu(
            item("Open Project Atlas", lambda: launch_gui(), default=True),  # also a left-click on the icon
            pystray.Menu.SEPARATOR,
            item(lambda _: self._status(), None, enabled=False),
            item(lambda _: f"Alert: {self.alert}", None, enabled=False, visible=lambda _: self.alert is not None),
            item("Clear alert", self._clear_alert, visible=lambda _: self.alert is not None),
            item(lambda _: f"Health score: {self.system.score.text}", lambda: launch_gui(),
                 visible=lambda _: self.system.score is not None),
            item(lambda _: f"Protection and threat hunt: {self.system.needs_look} thing(s) need a look", lambda: launch_gui(),
                 visible=lambda _: self.system.needs_look > 0),
            item(lambda _: f"Update to Project Atlas {self.update_available}", self._update,
                 visible=lambda _: self.update_available is not None),
            pystray.Menu.SEPARATOR,
            item("Pause protection", self._toggle_pause, checked=lambda _: self.guard.paused),
            item("Check startup items now", self._check_autoruns, enabled=lambda _: self.monitor is not None),
            item("Check running programs and network now", self._check_running),
            item("Check Defender, browsers, network settings and threat hunt now", self._check_system),
            item("Scan watched folders now", self._scan_folders, enabled=lambda _: self.busy is None),
            item("Check link on clipboard", self._check_clipboard_link),
            pystray.Menu.SEPARATOR,
            item("Open activity log", lambda: os.startfile(log_file())),
            item("Open quarantine folder", lambda: os.startfile(quarantine_dir(config.data_dir()))),
            item("Open settings file", lambda: os.startfile(config.config_dir() / "config.json")),
            pystray.Menu.SEPARATOR,
            item("Start with Windows", self._toggle_autostart, checked=lambda _: autostart.is_enabled()),
            item('"Scan with Project Atlas" in right-click menu', self._toggle_context_menu,
                 checked=lambda _: contextmenu.is_enabled()),
            item("Quit Project Atlas", self._quit),
        )

    def _status(self) -> str:
        if self.busy:
            return self.busy
        if self.guard.paused:
            return "Protection paused"
        if self.scanner.vt is None:
            return f"Protecting {len(self.guard.folders)} folders · VirusTotal not connected"
        text = f"Protecting {len(self.guard.folders)} folders"
        if self.monitor and self.monitor.last_check:
            text += f" · startup checked {self.monitor.last_check}"
        return text

    def _refresh(self) -> None:
        state = "alert" if self.alert else "paused" if self.guard.paused else "ok"
        self.icon.icon = make_icon(state)
        self.icon.title = f"Project Atlas: {self._status()}"
        self.icon.update_menu()

    # --- Events --------------------------------------------------------------

    def _on_download(self, result: ScanResult) -> None:
        if result.verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS):
            self.alert = f"{result.verdict.value} file {result.path.name}"
            self._refresh()

    def _on_autorun(self, entry: Autorun, result: ScanResult, is_new: bool) -> None:
        log.info("Startup item %s: %s -> %s (%s)", "added" if is_new else "changed", entry.name,
                 result.verdict.value.upper(), "; ".join(result.reasons))
        if self.settings.notifications:
            notify_autorun(entry, result, is_new)
        if result.verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS):
            self.alert = f"{result.verdict.value} startup item {entry.name}"
            self._refresh()

    def _on_running_finding(self, title: str, body: str, link: str | None) -> None:
        if self.settings.notifications:
            toast(title, body, link=link, loud=True)
        self.alert = title.removeprefix("Atlas: ")
        self._refresh()

    # --- Actions -------------------------------------------------------------

    def _check_system(self, icon, item) -> None:
        self.system.check_now()
        toast("Atlas: checking Defender, browsers, network settings and threat hunt",
              "You'll hear back if something new needs a look. The Protection and Threat hunt tabs show everything.")

    def _watch_for_updates(self) -> None:
        from atlas import updates

        delay = 300  # not during sign-in
        while not self._update_stop.wait(delay):
            delay = 24 * 3600
            latest = updates.latest_version()
            if latest and updates.is_newer(latest) and latest != self.update_available:
                self.update_available = latest
                log.info("Update available: %s", latest)
                toast("Atlas: update available", updates.update_hint(latest) +
                      (" Right-click the globe to update." if updates.can_update_itself() else ""))
                self._refresh()

    def _update(self, icon, item) -> None:
        from atlas import updates

        try:
            updates.start_update()  # its window stops this tray, updates and starts the new one
        except (OSError, RuntimeError) as exc:
            toast("Atlas: couldn't update", str(exc))

    def _check_running(self, icon, item) -> None:
        self.running.check_now()
        toast("Atlas: checking running programs and connections",
              "You'll only hear back if something needs attention. See Running now in the window for everything.")

    def _clear_alert(self, icon, item) -> None:
        self.alert = None
        self._refresh()

    def _toggle_pause(self, icon, item) -> None:
        self.guard.paused = not self.guard.paused
        if self.monitor:
            self.monitor.paused = self.guard.paused
        self.running.paused = self.guard.paused
        self.system.paused = self.guard.paused
        if self.new_programs:
            self.new_programs.paused = self.guard.paused
        log.info("Protection %s", "paused" if self.guard.paused else "resumed")
        self._refresh()

    def _check_autoruns(self, icon, item) -> None:
        if self.monitor:
            self.monitor.check_now()
            toast("Atlas: checking startup items", "You'll only hear back if something needs attention.")

    def _scan_folders(self, icon, item) -> None:
        def work():
            self.busy = "Scanning watched folders..."
            self._refresh()
            try:
                counts = self.guard.scan_existing()
                total = sum(counts.values())
                flagged = counts[Verdict.MALICIOUS] + counts[Verdict.SUSPICIOUS]
                body = f"{total} files checked: {flagged} flagged, {counts[Verdict.UNKNOWN]} unknown."
                toast("Atlas: folder scan finished", body, loud=flagged > 0)
            finally:
                self.busy = None
                self._refresh()

        threading.Thread(target=work, daemon=True).start()

    def _check_clipboard_link(self, icon, item) -> None:
        def work():
            text = read_clipboard().strip()
            if not text or len(text) > 2000 or " " in text or "." not in text:
                toast("Atlas: no link on the clipboard", "Copy a link first (right-click it, Copy link), then try again.")
                return
            check = check_link(self.scanner, text)
            verdict = check.verdict.value
            title = f"Atlas: link {verdict.upper()}" if verdict != "clean" else "Atlas: link looks clean"
            report = check.url_report if check.url_report and check.url_report.found else check.domain_report
            body = f"{check.host}\n" + ("\n".join(check.reasons[:2]) or "")
            toast(title, body, link=report.gui_link if report and report.found else None,
                  loud=check.verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS))

        threading.Thread(target=work, daemon=True).start()

    def _toggle_autostart(self, icon, item) -> None:
        if autostart.is_enabled():
            autostart.disable()
        else:
            autostart.enable()
        self._refresh()

    def _toggle_context_menu(self, icon, item) -> None:
        if contextmenu.is_enabled():
            contextmenu.disable()
        else:
            contextmenu.enable()
            toast("Atlas: added to the right-click menu", 'Right-click any file or folder, choose "Show more '
                  'options", then "Scan with Project Atlas".')
        self._refresh()

    def _quit(self, icon, item) -> None:
        log.info("Project Atlas tray stopped")
        self.guard.stop()
        if self.monitor:
            self.monitor.stop()
        self.running.stop()
        self.system.stop()
        if self.new_programs:
            self.new_programs.stop()
        self._update_stop.set()
        icon.stop()

    # --- Running -------------------------------------------------------------

    def _setup(self, icon) -> None:
        icon.visible = True
        threading.Thread(target=self.guard.run, name="download-guard", daemon=True).start()
        if self.monitor:
            threading.Thread(target=self.monitor.run, name="autorun-monitor", daemon=True).start()
        threading.Thread(target=self.running.run, name="running-monitor", daemon=True).start()
        threading.Thread(target=self.system.run, name="system-monitor", daemon=True).start()
        if self.new_programs:
            threading.Thread(target=self.new_programs.run, name="new-programs", daemon=True).start()
        if self.settings.check_for_updates:
            threading.Thread(target=self._watch_for_updates, name="updates", daemon=True).start()
        log.info("Project Atlas %s tray started", __version__)
        self._refresh()

    def run(self) -> None:
        self.icon.run(setup=self._setup)
        self.store.close()


def main() -> int:
    setup_logging()
    if unelevate.restart_unelevated(tray_command()):  # never as administrator
        return 0
    if not claim_single_instance():
        toast("Project Atlas is already running", "Look for the globe icon by the clock (it may be under ^).")
        return 1
    AtlasTray().run()
    return 0
