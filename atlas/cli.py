"""Command line for Project Atlas.

    atlas tray                 run in the system tray (the normal way to use Atlas)
    atlas gui                  open the Project Atlas window
    atlas guard                same protection, in this console window
    atlas set-key              store your VirusTotal API key in Windows Credential Manager
    atlas scan FILE...         scan files right now
    atlas autoruns             check everything set to start automatically
    atlas running / network    check running programs / internet connections
    atlas protection           check Defender, browser start/search pages, proxy, hosts file, DNS
    atlas installed            check installed programs for adware and unwanted software
    atlas second-opinion FILE  ask Microsoft Defender to scan a file too
    atlas hunt [--admin]       command lines, certificates, drivers, open ports, user folders, threat intel
    atlas gti [sync]           Google Threat Intelligence reports on this PC
    atlas quota                VirusTotal lookups used today and this month
    atlas update [--now]       check GitHub for a newer version
    atlas history              show recent scans
    atlas quarantine           list quarantined files
    atlas restore ID           put a quarantined file back
    atlas config               show where settings live and what they are
    atlas autostart on|off     start Atlas (in the tray) when you sign in
    atlas context-menu on|off  add "Scan with Project Atlas" to Explorer's right-click menu
    atlas browser-extension on|off  connect the browser link-checker extension to Atlas
"""

from __future__ import annotations

import argparse
import getpass
import json
import logging
import sys
import threading
from dataclasses import asdict
from pathlib import Path

from atlas import __version__, autostart, config
from atlas.app import build_scanner, claim_single_instance, setup_logging, watch_folders
from atlas.db import Store
from atlas.quarantine import quarantine_dir, restore_file
from atlas.scanner import ScanResult, Verdict, short_url, threat_lines
from atlas.vt_client import VTClient

COLORS = {
    Verdict.CLEAN: "\033[32m", Verdict.UNKNOWN: "\033[33m", Verdict.SUSPICIOUS: "\033[33m",
    Verdict.MALICIOUS: "\033[31m", Verdict.ERROR: "\033[35m",
}
RESET = "\033[0m"


def _verdict_label(verdict: Verdict) -> str:
    color = COLORS[verdict] if sys.stdout.isatty() else ""
    return f"{color}{verdict.value.upper():<10}{RESET if color else ''}"


def _print_result(result: ScanResult) -> None:
    print(f"{_verdict_label(result.verdict)} {result.path}")
    if result.sha256:
        print(f"           sha256: {result.sha256}")
    if result.motw and result.motw.host_url:
        print(f"           from:   {short_url(result.motw.host_url)}")
        if result.motw.referrer_url:
            print(f"           page:   {short_url(result.motw.referrer_url)}")
    if result.signature:
        signer = f" ({result.signature.signer})" if result.signature.signer else ""
        print(f"           signed: {result.signature.status}{signer}")
    for reason in result.reasons:
        print(f"           - {reason}")
    for label, text, _ in threat_lines(result):
        print(f"           {label + ':':<10} {text}")
    if result.file_report and result.file_report.found:
        print(f"           {result.file_report.gui_link}")
    if result.action:
        print(f"           >> {result.action}")


def cmd_set_key(args) -> int:
    key = getpass.getpass("VirusTotal API key (input hidden): ").strip()
    if not key:
        print("No key entered; nothing changed.")
        return 1
    config.set_api_key(key)
    print("Saved to Windows Credential Manager. Checking it with VirusTotal...")
    try:
        # The EICAR test file: a harmless file every antivirus detects on purpose.
        report = VTClient(key).file_report("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
        print(f"Key works. (EICAR test file: {report.malicious}/{report.total} engines.)")
    except Exception as exc:
        print(f"Key saved, but the test lookup failed: {exc}")
        return 1
    return 0


def cmd_scan(args) -> int:
    settings = config.Settings.load()
    scanner, store = build_scanner(settings)
    if scanner.vt is None:
        print("Note: no API key set, so only local checks will run. Run `atlas set-key` first.\n")
    worst = Verdict.CLEAN
    for raw in args.files:
        path = Path(raw)
        targets = [p for p in path.iterdir() if p.is_file()] if path.is_dir() else [path]
        for target in targets:
            if not target.exists():
                print(f"Not found: {target}")
                continue
            result = scanner.scan(target, act=args.quarantine)
            _print_result(result)
            worst = max(worst, result.verdict, key=lambda v: v.rank)
    store.close()
    return {Verdict.MALICIOUS: 3, Verdict.SUSPICIOUS: 2, Verdict.UNKNOWN: 1}.get(worst, 0)


def cmd_guard(args) -> int:
    from atlas.autoruns import AutorunMonitor
    from atlas.notify import notify_autorun
    from atlas.watcher import DownloadGuard

    setup_logging(args.verbose)
    log = logging.getLogger("atlas")
    if not claim_single_instance():
        log.error("Project Atlas is already running (check the tray by the clock). Quit it first.")
        return 1
    settings = config.Settings.load()
    scanner, store = build_scanner(settings)
    if scanner.vt is None:
        log.warning("No VirusTotal API key set; only local checks will run. Run `atlas set-key`.")
    guard = DownloadGuard(scanner, watch_folders(settings), ignore_dirs=[quarantine_dir(config.data_dir())],
                          notifications=settings.notifications)
    monitor = None
    if settings.monitor_autoruns:
        def on_autorun(entry, result, is_new):
            log.info("Startup item %s: %s -> %s", "added" if is_new else "changed", entry.name,
                     result.verdict.value.upper())
            for reason in result.reasons:
                log.info("    %s", reason)
            log.info("    %s", result.path)
            if settings.notifications:
                notify_autorun(entry, result, is_new)

        monitor = AutorunMonitor(scanner, store, settings.autorun_check_minutes, on_autorun)
        threading.Thread(target=monitor.run, name="autorun-monitor", daemon=True).start()
        log.info("Checking startup items every %d minutes", settings.autorun_check_minutes)
    log.info("Project Atlas %s guard started", __version__)
    try:
        guard.run()
    except KeyboardInterrupt:
        log.info("Stopped")
    finally:
        if monitor:
            monitor.stop()
        store.close()
    return 0


def cmd_gui(args) -> int:
    from atlas.gui import main as gui_main

    return gui_main()


def cmd_tray(args) -> int:
    from atlas.tray import main as tray_main

    return tray_main()


def cmd_autoruns(args) -> int:
    from atlas.autoruns import assess_all, enumerate_all, is_microsoft

    settings = config.Settings.load()
    scanner, store = build_scanner(settings)
    print("Reading startup items (registry, startup folders, scheduled tasks, services)...")
    entries = enumerate_all()
    print(f"Found {len(entries)}. Checking signatures{'' if args.no_vt else ' and VirusTotal'}"
          " (this can take a minute)...\n")
    results = assess_all(entries, None if args.no_vt else scanner)
    store.sync_autoruns(entries, {e.key: r for e, r in results})
    first_seen = store.autorun_first_seen()

    microsoft = [er for er in results if is_microsoft(er[1].signature) and er[1].verdict is Verdict.CLEAN]
    leftovers = [er for er in results if er[0].path and not er[0].path.exists() and er[1].verdict is Verdict.CLEAN]
    attention = [er for er in results if er[1].verdict is not Verdict.CLEAN]
    third_party = [er for er in results if er not in microsoft and er not in leftovers and er not in attention]
    by_name = lambda er: (er[0].category, er[0].name.lower())  # noqa: E731

    if attention:
        print("NEEDS A LOOK")
        for entry, result in sorted(attention, key=lambda er: (-er[1].verdict.rank, *by_name(er))):
            state = "" if entry.enabled else " (switched off)"
            print(f"{_verdict_label(result.verdict)} {entry.category}: {entry.name}{state}")
            print(f"           runs:   {entry.command}")
            if result.signer_text:
                print(f"           {result.signer_text}")
            for reason in result.reasons:
                if reason != result.signer_text:
                    print(f"           - {reason}")
            if result.file_report and result.file_report.found:
                print(f"           {result.file_report.gui_link}")
            print(f"           where:  {entry.location}  (first seen {first_seen.get(entry.key, '?')[:10]})")
        print()

    groups = [("THIRD-PARTY, CLEAN", third_party, True)]
    if args.all:
        groups += [("MICROSOFT", microsoft, True), ("LEFTOVERS (point to deleted files)", leftovers, True)]
    for title, rows, _ in groups:
        if not rows:
            continue
        print(title)
        for entry, result in sorted(rows, key=by_name):
            signer = result.signature.signer if result.signature and result.signature.signer else "-"
            off = "  (switched off)" if not entry.enabled else ""
            print(f"  {entry.category:<15} {entry.name[:45]:<45} {signer}{off}")
        print()

    flagged = sum(1 for _, r in attention if r.verdict in (Verdict.SUSPICIOUS, Verdict.MALICIOUS))
    print(f"{len(results)} startup items checked: {flagged} flagged, {len(attention) - flagged} other"
          f" needing a look, {len(third_party)} third-party clean, {len(microsoft)} Microsoft,"
          f" {len(leftovers)} leftovers.")
    if not args.all:
        print("Microsoft items and leftovers are hidden. Use --all to show everything.")
    store.close()
    return 2 if flagged else 0


def cmd_cleanup(args) -> int:
    """Report junk. Read-only: cleaning is done from the Atlas window, where you pick what goes."""
    from atlas.cleanup import HOW_LABELS, human_size, scan_all

    categories = scan_all(lambda text: print(text))
    print()
    for cat in categories:
        locked = f" (+{human_size(cat.blocked_size)} locked, reasons below)" if cat.blocked_size else ""
        print(f"{cat.title}: {human_size(cat.size)} in {len(cat.items)} items{locked}")
        for item in cat.items[: args.top]:
            what = item.blocked or HOW_LABELS[item.how]
            size = human_size(item.size) if item.size else ""
            print(f"    {size:>10}  {item.label[:50]:<50}  {what}")
        if len(cat.items) > args.top:
            print(f"    ...and {len(cat.items) - args.top} more")
    total = sum(c.size for c in categories)
    print(f"\nTotal: {human_size(total)}. To clean, open the Atlas window (atlas gui) and use the Cleanup tab.")
    return 0


def cmd_space(args) -> int:
    """Report duplicates and big files. Read-only: act on them from the Atlas window."""
    from atlas import space
    from atlas.cleanup import human_size

    settings = config.Settings.load()
    store = Store(config.data_dir() / "atlas.db")
    mb = 1024 * 1024
    dup_min, big_min = settings.duplicate_min_mb * mb, settings.big_file_min_mb * mb
    last = [""]

    def progress(text: str) -> None:
        if text.split("...")[0] != last[0]:
            print(text)
        last[0] = text.split("...")[0]

    files = space.walk([Path(f) for f in settings.space_scan_folders], min(dup_min, big_min),
                       progress=progress, skip=[config.data_dir()])
    space.mark_vm_disks(files)
    groups = space.find_duplicates([f for f in files if f.size >= dup_min], store, progress=progress)
    big = space.big_files(files, big_min)

    print(f"\nDUPLICATES: {len(groups)} sets, {human_size(sum(g.reclaimable for g in groups))} could be freed")
    for g in groups[: args.top]:
        how = "identical" if g.verified else "same name+size, online copy not compared"
        print(f"  {human_size(g.reclaimable):>10} freeable  {g.files[0].path.name}  ({len(g.files)} copies, {how})")
        for f in g.files:
            vm = f"  [{f.used_by_vm}]" if f.used_by_vm else ""
            print(f"  {'':>10}            - {f.where:<22} {f.path}{vm}")
    print(f"\nBIG FILES (over {settings.big_file_min_mb} MB): {len(big)} files, "
          f"{human_size(sum(f.disk_size for f in big))} on this PC")
    for f in big[: args.top]:
        vm = f"  [{f.used_by_vm}]" if f.used_by_vm else ""
        print(f"  {human_size(f.size):>10}  {f.kind:<10} {f.where:<22} {f.path}{vm}")
    print("\nTo act on these, open the Atlas window (atlas gui) and use the Disk space tab.")
    store.close()
    return 0


def cmd_check_url(args) -> int:
    """Check a link without opening it."""
    from atlas.links import check_link

    scanner, store = build_scanner(config.Settings.load())
    check = check_link(scanner, args.url)
    print(f"{check.verdict.value.upper():<11} {check.url}")
    for reason in check.reasons:
        print(f"            - {reason}")
    report = check.url_report if check.url_report and check.url_report.found else check.domain_report
    if report and report.found:
        print(f"            {report.gui_link}")
    store.close()
    return {Verdict.MALICIOUS: 3, Verdict.SUSPICIOUS: 2, Verdict.UNKNOWN: 1}.get(check.verdict, 0)


def cmd_browsers(args) -> int:
    """List sites allowed to send notifications and browser extensions. Read-only."""
    from atlas import browsers

    scanner, store = build_scanner(config.Settings.load())
    sites = browsers.notification_sites()
    if not args.no_vt:
        browsers.judge_sites(sites, scanner)
    print(f"SITES ALLOWED TO SEND NOTIFICATIONS: {len(sites)}")
    for s in sites:
        print(f"  {s.verdict.upper():<11} {s.site:<45} {s.profile.label}")
        for reason in s.reasons if s.verdict not in ("clean", "not checked") else []:
            print(f"  {'':<11} - {reason}")
    exts = browsers.extensions()
    print(f"\nEXTENSIONS: {len(exts)} ({sum(e.needs_look for e in exts)} need a look)")
    for e in exts:
        status = "LOOK" if e.needs_look else "ok"
        print(f"  {status:<5} {'on ' if e.enabled else 'off'}  {e.name[:45]:<45} {e.profile.label}")
        for concern in e.concerns:
            print(f"  {'':<10} ! {concern}")
    print("\nTo block a site or remove an extension, use the Browsers tab in the Atlas window (atlas gui).")
    store.close()
    return 0


def cmd_running(args) -> int:
    """Look up every running program (and optionally loaded DLLs). Read-only."""
    from atlas.processes import check_running

    scanner, store = build_scanner(config.Settings.load())
    live = sys.stdout.isatty()  # a progress line only makes sense in a terminal, not in a saved log
    report = check_running(scanner, include_dlls=args.dlls,
                           progress=(lambda t: print(f"\r{t:<60}", end="", flush=True)) if live else None)
    if live:
        print("\r" + " " * 60 + "\r", end="")
    for error in report.errors:
        print(error)
    shown = report.files if args.all else report.flagged + [f for f in report.files if f.verdict is Verdict.ERROR]
    for f in shown:
        print(f"{_verdict_label(f.verdict)} {f.path}  ({f.kind}, used by {', '.join(sorted(f.used_by))})")
        for reason in f.result.reasons:
            print(f"           - {reason}")
        for label, text, _ in threat_lines(f.result):
            print(f"           {label + ':':<10} {text}")
    clean = sum(1 for f in report.files if f.verdict is Verdict.CLEAN)
    print(f"\n{len(report.files)} files checked: {len(report.flagged)} need a look, {clean} clean."
          + (f" {report.unreadable} process(es) need administrator rights to look into." if report.unreadable else "")
          + ("" if args.all else " Add --all to list everything."))
    store.close()
    return 2 if report.flagged else 0


def cmd_network(args) -> int:
    """Check the internet addresses programs are connected to right now. Read-only."""
    from atlas.network import check_network

    scanner, store = build_scanner(config.Settings.load())
    report = check_network(scanner)
    for error in report.errors:
        print(error)
    for c in report.addresses + report.sites:
        if not args.all and c.verdict is Verdict.CLEAN:
            continue
        what = ", ".join(c.programs) if c.kind == "ip" else "looked up"
        print(f"{_verdict_label(c.verdict)} {c.target}  ({what})")
        for reason in c.reasons:
            print(f"           - {reason}")
    print(f"\n{len(report.addresses)} internet addresses in use, {len(report.flagged)} flagged."
          + (f" {len(report.sites)} recently looked-up sites checked." if report.sites else
             " Recently looked-up sites: Windows shows that list only to administrators here." if not
             report.dns_available else "")
          + ("" if args.all else " Add --all to list everything."))
    store.close()
    return 2 if report.flagged else 0


def cmd_protection(args) -> int:
    """Defender settings and history, program and Windows updates, disk health, browser start/search pages,
    proxy, hosts file and DNS. Read-only."""
    from atlas.protection import check_system

    scanner, store = build_scanner(config.Settings.load())
    findings = check_system(scanner)
    labels = {"warn": "[LOOK]   ", "note": "[NOTE]   ", "ok": "[OK]     "}
    for f in findings:
        if not args.all and f.level == "ok":
            continue
        print(f"{labels.get(f.level, '')} {f.area}: {f.title}")
        for line in f.details:
            print(f"           - {line}")
        if f.fix_label:
            print(f"           Fix in the Protection tab: {f.fix_label}")
    flagged = [f for f in findings if f.needs_look]
    print(f"\n{len(findings)} checks: {len(flagged)} need a look."
          + ("" if args.all else " Add --all to list everything."))
    store.close()
    return 2 if flagged else 0


def cmd_password_check(args) -> int:
    """Has a password appeared in a data leak? Only 5 characters of its hash leave the PC."""
    import getpass

    from atlas import pwned

    password = getpass.getpass("Password to check (not shown, never saved): ")
    if not password:
        return 1
    try:
        count = pwned.times_leaked(password)
    except Exception as exc:
        print(f"Couldn't reach Have I Been Pwned: {exc}")
        return 1
    print(pwned.verdict(count))
    return 2 if count else 0


def cmd_installed(args) -> int:
    """Look up installed programs' main files and point out known unwanted software. Read-only."""
    from atlas.installed import check_installed

    scanner, store = build_scanner(config.Settings.load())
    live = sys.stdout.isatty()
    programs = check_installed(scanner,
                               progress=(lambda t: print(f"\r{t[:60]:<60}", end="", flush=True)) if live else None)
    if live:
        print("\r" + " " * 60 + "\r", end="")
    flagged = [p for p in programs if p.verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS) or p.concerns]
    for p in programs if args.all else flagged:
        print(f"[{p.status:<10}] {p.name}" + (f"  ({p.publisher})" if p.publisher else ""))
        for reason in p.reasons:
            print(f"           - {reason}")
    print(f"\n{len(programs)} programs installed: {len(flagged)} need a look."
          + (" Uninstall them from the Installed tab or Windows Settings." if flagged else "")
          + ("" if args.all else " Add --all to list everything."))
    store.close()
    return 2 if flagged else 0


def cmd_second_opinion(args) -> int:
    """Ask Microsoft Defender to scan a file (it reports only; nothing is removed)."""
    from atlas.defender import scan_file

    worst = 0
    for name in args.paths:
        scan = scan_file(Path(name))
        label = "[CLEAN]    " if scan.clean else "[THREAT]   " if scan.clean is False else "[ERROR]    "
        print(f"{label} {name}: {scan.message}")
        worst = max(worst, 2 if scan.clean is False else 1 if scan.clean is None else 0)
    return worst


def cmd_hunt(args) -> int:
    """Command lines, certificates, drivers, open ports, user-folder programs and threat intel. Read-only."""
    from atlas import deepcheck
    from atlas.hunt import check_hunt

    scanner, store = build_scanner(config.Settings.load())
    deep = None
    if args.admin:
        print("Windows will ask for administrator permission...")
        try:
            deep = deepcheck.run_elevated()
        except OSError as exc:
            print(f"Deep check skipped: {exc}")
    live = sys.stdout.isatty()
    findings = check_hunt(scanner, deep=deep,
                          progress=(lambda t: print(f"\r{t[:70]:<70}", end="", flush=True)) if live else None)
    if live:
        print("\r" + " " * 70 + "\r", end="")
    labels = {"warn": "[LOOK]   ", "note": "[NOTE]   ", "ok": "[OK]     "}
    for f in findings:
        if not args.all and f.level == "ok":
            continue
        print(f"{labels.get(f.level, '')} {f.area}: {f.title}")
        for line in f.details:
            print(f"           - {line}")
        if f.vt_link:
            print(f"           {f.vt_link}")
    flagged = [f for f in findings if f.needs_look]
    print(f"\n{len(findings)} findings: {len(flagged)} need a look."
          + ("" if args.all else " Add --all to list what's fine too.")
          + ("" if args.admin else " Add --admin for the administrator-only checks."))
    store.close()
    return 2 if flagged else 0


def cmd_deep_check(args) -> int:
    """The administrator-only collector (Atlas starts this itself with Windows' permission prompt)."""
    from atlas import deepcheck

    data = deepcheck.collect()
    out = Path(args.out) if args.out else deepcheck.output_file()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, default=str), encoding="utf-8")
    print(f"Wrote {out}")
    return 0


def cmd_gti(args) -> int:
    """Google Threat Intelligence: download new reports, or show what's on this PC."""
    from atlas import gti
    from atlas.hunt import gti_on, sync_gti

    scanner, store = build_scanner(config.Settings.load())
    try:
        if not gti_on(scanner):
            print("This VirusTotal key doesn't reach Google Threat Intelligence (or gti_enabled is off).")
            return 1
        if args.action == "sync":
            live = sys.stdout.isatty()
            new, _ = sync_gti(scanner, force=True,
                              progress=(lambda t: print(f"\r{t[:70]:<70}", end="", flush=True)) if live else None)
            if live:
                print("\r" + " " * 70 + "\r", end="")
            print(f"{new} new report(s) downloaded.")
        reports, iocs = store.gti_stats()
        last = gti.last_sync(store)
        print(f"{reports} GTI reports about Windows from the last {scanner.settings.gti_days} days, {iocs:,} indicators."
              f" Last updated: {last.astimezone():%Y-%m-%d %H:%M}" if last else " Never updated.")
        return 0
    finally:
        store.close()


def cmd_quota(args) -> int:
    """Atlas's own VirusTotal requests today and this month."""
    from atlas.app import vt_usage

    store = Store(config.data_dir() / "atlas.db")
    u = vt_usage(store)
    store.close()
    print(f"VirusTotal lookups today: {u['today']:,}   this month: {u['month']:,}")
    if u["throttled_today"]:
        print(f"Slowed down by VirusTotal's rate limit today: {u['throttled_today']}")
    for kind, n in u["today_by_kind"].items():
        print(f"  {kind}: {n:,}")
    print("Cached answers don't count. A free VirusTotal key allows 500 lookups a day and 4 a minute.")
    return 0


def cmd_update(args) -> int:
    """Tell whether a newer Atlas is on GitHub, and with --now start updating."""
    from atlas import updates

    latest = updates.latest_version()
    if latest is None:
        print("Couldn't reach GitHub to check for updates.")
        return 1
    if not updates.is_newer(latest):
        print(f"Project Atlas {__version__} is the newest version.")
        return 0
    print(updates.update_hint(latest))
    if args.now:
        updates.start_update()
        print("Updating in a new window.")
    elif updates.install_kind() == "installer":
        print("Run `atlas update --now` to update.")
    return 0


def cmd_history(args) -> int:
    store = Store(config.data_dir() / "atlas.db")
    for row in reversed(store.recent_scans(args.limit)):
        reasons = json.loads(row["reasons"])
        action = f" [{row['action']}]" if row["action"] else ""
        print(f"{row['scanned_at'][:19]}  {row['verdict'].upper():<10} {Path(row['path']).name}{action}")
        if reasons and row["verdict"] != "clean":
            print(f"{'':31}{reasons[0]}")
    store.close()
    return 0


def cmd_quarantine(args) -> int:
    store = Store(config.data_dir() / "atlas.db")
    rows = store.quarantined(include_restored=args.all)
    if not rows:
        print("Quarantine is empty.")
    for row in rows:
        state = f" (restored {row['restored_at'][:19]})" if row["restored_at"] else ""
        print(f"#{row['id']:<4} {row['quarantined_at'][:19]}  {row['original_path']}{state}")
        print(f"      {row['reason']}")
    store.close()
    return 0


def cmd_restore(args) -> int:
    store = Store(config.data_dir() / "atlas.db")
    row = store.get_quarantine(args.id)
    if row is None:
        print(f"No quarantine entry #{args.id}")
        return 1
    print(f"#{args.id}: {row['original_path']}\nReason: {row['reason']}")
    if not args.yes and input("Restore this file? Type 'yes' to confirm: ").strip().lower() != "yes":
        print("Cancelled.")
        return 1
    dest = restore_file(args.id, store)
    print(f"Restored to {dest}")
    store.close()
    return 0


def cmd_config(args) -> int:
    settings = config.Settings.load()
    print(f"Settings file: {config.config_dir() / 'config.json'}")
    print(f"Data folder:   {config.data_dir()}")
    print(f"API key:       {'set' if config.get_api_key() else 'NOT SET (run atlas set-key)'}")
    print(f"Autostart:     {'on' if autostart.is_enabled() else 'off'}")
    from atlas import contextmenu

    print(f"Right-click:   {'on' if contextmenu.is_enabled() else 'off'}")
    print(json.dumps(asdict(settings), indent=2))
    return 0


def cmd_autostart(args) -> int:
    if args.state == "off":
        autostart.disable()
        print("Project Atlas will no longer start at sign-in.")
    else:
        print(f"Project Atlas will start in the tray at sign-in (shortcut: {autostart.enable()}).")
    return 0


def cmd_browser_extension(args) -> int:
    from atlas import browserext

    if args.state == "off":
        browserext.disable()
        print("The browser extension is disconnected from Atlas. Remove it from each browser's extensions page.")
        return 0
    manifest = browserext.enable()
    print(f"Atlas's link-check helper is registered for Chrome, Edge and Brave ({manifest}).\n")
    print("Now add the extension to each browser you use (once):")
    print("  1. Open chrome://extensions  (Edge: edge://extensions, Brave: brave://extensions)")
    print("  2. Switch on 'Developer mode'")
    print("  3. Click 'Load unpacked' and choose this folder:")
    print(f"       {browserext.extension_dir()}")
    print("  4. Pin the globe icon; it shows Atlas's verdict for the page you're on.")
    return 0


def cmd_context_menu(args) -> int:
    from atlas import contextmenu

    if args.state == "off":
        contextmenu.disable()
        print('"Scan with Project Atlas" removed from the right-click menu.')
    else:
        contextmenu.enable()
        print('"Scan with Project Atlas" added to the right-click menu for files and folders.\n'
              'On Windows 11 it is under "Show more options" (or hold Shift while right-clicking).')
    return 0


def main(argv: list[str] | None = None) -> int:
    # Names like "μTorrent" mustn't crash the output when it goes to a file or another program.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    parser = argparse.ArgumentParser(prog="atlas", description="Project Atlas: VirusTotal-powered protection")
    parser.add_argument("--version", action="version", version=f"Project Atlas {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("tray", help="run in the system tray").set_defaults(func=cmd_tray)
    sub.add_parser("gui", help="open the Project Atlas window").set_defaults(func=cmd_gui)

    p = sub.add_parser("guard", help="run protection in this console window")
    p.add_argument("-v", "--verbose", action="store_true")
    p.set_defaults(func=cmd_guard)

    sub.add_parser("set-key", help="store your VirusTotal API key").set_defaults(func=cmd_set_key)

    p = sub.add_parser("scan", help="scan files or folders now")
    p.add_argument("files", nargs="+")
    p.add_argument("--quarantine", action="store_true", help="quarantine files found malicious")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("autoruns", help="check everything set to start automatically")
    p.add_argument("--all", action="store_true", help="also show clean Microsoft items and dead entries")
    p.add_argument("--no-vt", action="store_true", help="skip VirusTotal (signatures and local checks only)")
    p.set_defaults(func=cmd_autoruns)

    p = sub.add_parser("cleanup", help="report junk that can be removed (read-only)")
    p.add_argument("--top", type=int, default=5, help="items to show per category")
    p.set_defaults(func=cmd_cleanup)

    p = sub.add_parser("space", help="report duplicate and big files (read-only)")
    p.add_argument("--top", type=int, default=10, help="how many to list of each")
    p.set_defaults(func=cmd_space)

    p = sub.add_parser("check-url", aliases=["link"], help="check a link without opening it")
    p.add_argument("url")
    p.set_defaults(func=cmd_check_url)

    p = sub.add_parser("browsers", help="list notification sites and extensions (read-only)")
    p.add_argument("--no-vt", action="store_true", help="don't look sites up on VirusTotal")
    p.set_defaults(func=cmd_browsers)

    p = sub.add_parser("running", aliases=["processes"], help="check running programs with VirusTotal (read-only)")
    p.add_argument("--dlls", action="store_true", help="also check DLLs loaded from outside the Windows folder")
    p.add_argument("--all", action="store_true", help="list clean files too")
    p.set_defaults(func=cmd_running)

    p = sub.add_parser("network", help="check what programs are connected to (read-only)")
    p.add_argument("--all", action="store_true", help="list clean addresses too")
    p.set_defaults(func=cmd_network)

    p = sub.add_parser("protection", aliases=["system"],
                       help="check Defender, updates, disk health, browser start/search pages, proxy, hosts file "
                            "and DNS (read-only)")
    p.add_argument("--all", action="store_true", help="also list what's fine")
    p.set_defaults(func=cmd_protection)

    sub.add_parser("password-check", help="check whether a password has appeared in a data leak"
                   ).set_defaults(func=cmd_password_check)

    p = sub.add_parser("installed", aliases=["programs"], help="check installed programs (read-only)")
    p.add_argument("--all", action="store_true", help="list every program, not only the ones to look at")
    p.set_defaults(func=cmd_installed)

    p = sub.add_parser("second-opinion", aliases=["defender"], help="ask Microsoft Defender to scan files")
    p.add_argument("paths", nargs="+")
    p.set_defaults(func=cmd_second_opinion)

    p = sub.add_parser("hunt", help="command lines, certificates, drivers, open ports, user-folder programs and "
                                    "threat intel (read-only)")
    p.add_argument("--all", action="store_true", help="also list what's fine")
    p.add_argument("--admin", action="store_true", help="include the administrator-only checks (asks permission)")
    p.set_defaults(func=cmd_hunt)

    p = sub.add_parser("deep-check", help=argparse.SUPPRESS)
    p.add_argument("--collect", action="store_true")
    p.add_argument("--out")
    p.set_defaults(func=cmd_deep_check)

    p = sub.add_parser("gti", help="Google Threat Intelligence reports: sync or status")
    p.add_argument("action", nargs="?", choices=["sync", "status"], default="status")
    p.set_defaults(func=cmd_gti)

    sub.add_parser("quota", aliases=["usage"], help="VirusTotal lookups used today and this month"
                   ).set_defaults(func=cmd_quota)

    p = sub.add_parser("update", help="check GitHub for a newer version")
    p.add_argument("--now", action="store_true", help="update right away (installed copies)")
    p.set_defaults(func=cmd_update)

    p = sub.add_parser("history", help="show recent scans")
    p.add_argument("-n", "--limit", type=int, default=20)
    p.set_defaults(func=cmd_history)

    p = sub.add_parser("quarantine", help="list quarantined files")
    p.add_argument("--all", action="store_true", help="include restored files")
    p.set_defaults(func=cmd_quarantine)

    p = sub.add_parser("restore", help="restore a quarantined file")
    p.add_argument("id", type=int)
    p.add_argument("-y", "--yes", action="store_true", help="skip confirmation")
    p.set_defaults(func=cmd_restore)

    sub.add_parser("config", help="show settings").set_defaults(func=cmd_config)

    p = sub.add_parser("autostart", aliases=["startup"], help="start Atlas in the tray at sign-in")
    p.add_argument("state", choices=["on", "off"])
    p.set_defaults(func=cmd_autostart)

    p = sub.add_parser("browser-extension", aliases=["extension"],
                       help="connect the Project Atlas browser extension to this PC")
    p.add_argument("state", choices=["on", "off"])
    p.set_defaults(func=cmd_browser_extension)

    p = sub.add_parser("context-menu", aliases=["menu"],
                       help='add "Scan with Project Atlas" to the right-click menu')
    p.add_argument("state", choices=["on", "off"])
    p.set_defaults(func=cmd_context_menu)

    args = parser.parse_args(argv)
    return args.func(args)
