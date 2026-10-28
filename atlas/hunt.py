"""Threat hunt: the checks a hash lookup alone can't do, in one place.

- Suspicious command lines (atlas.cmdlines)
- Root certificates (atlas.certs)
- Drivers and new services (atlas.drivers)
- Programs listening for connections, and the firewall (atlas.listening)
- Registry hiding places, password and security settings, and changes to them (atlas.registry)
- Programs running from user folders, and programs hidden in other files (atlas.userpaths)
- Google Threat Intelligence matches (atlas.gti), with a GTI key
- Administrator-only checks, when a deep check has been run (atlas.deepcheck)

Programs these checks turn up are looked up on VirusTotal like everything else.
Read-only throughout.
"""

from __future__ import annotations

import logging
import os
import threading
from collections.abc import Callable
from pathlib import Path

from atlas import certs, cmdlines, deepcheck, drivers, gti, history, listening, registry, userpaths
from atlas.findings import NOTE, OK, WARN, Finding
from atlas.local_checks import check_signatures
from atlas.processes import RunningFile, _hash, judge_files
from atlas.scanner import Scanner, Verdict, threat_lines

log = logging.getLogger(__name__)

ORDER = {WARN: 0, NOTE: 1, OK: 2}


def _part(found: list[Finding], name: str, fn) -> None:
    try:
        found += fn()
    except Exception as exc:  # one broken check mustn't hide the others
        log.exception("Threat hunt: %s failed", name)
        found.append(Finding("Atlas", f"A check failed: {name}", NOTE, [str(exc)], key=f"hunt:failed:{name}"))


def gti_on(scanner: Scanner) -> bool:
    try:
        return scanner.settings.gti_enabled and gti.available(scanner.vt, scanner.store)
    except Exception:
        log.exception("Couldn't tell whether GTI is available")
        return False


def sync_gti(scanner: Scanner, progress: Callable[[str], None] | None = None,
             cancel: threading.Event | None = None, force: bool = False) -> tuple[int, int] | None:
    """Download new GTI reports when a day has passed (or when forced). None without GTI."""
    if not gti_on(scanner) or not (force or gti.due(scanner.store)):
        return None
    return gti.sync(scanner.vt, scanner.store, scanner.settings.gti_days, progress, cancel)


def _flagged_file(f: RunningFile, area: str, why: str) -> Finding:
    r = f.result
    details = [why, *r.reasons] + [f"{label}: {text}" for label, text, _ in threat_lines(r)]
    link = r.file_report.gui_link if r.file_report and r.file_report.found else None
    unknown = r.verdict is Verdict.UNKNOWN
    return Finding(area, f"VirusTotal has never seen {f.path.name}" if unknown else f"VirusTotal flags {f.path.name}",
                   NOTE if unknown else WARN,
                   details, key=f"hunt:vt:{(r.sha256 or str(f.path)).lower()}", vt_link=link,
                   data={"path": str(f.path)})


def check_hunt(scanner: Scanner, progress: Callable[[str], None] | None = None,
               cancel: threading.Event | None = None, deep: dict | None = None) -> list[Finding]:
    say = progress or (lambda text: None)
    found: list[Finding] = []
    intel = gti_on(scanner)
    context = (lambda t: gti.technique_context(scanner.store, t)) if intel else None
    if intel:
        try:
            sync_gti(scanner, say, cancel)
        except Exception:
            log.exception("GTI sync failed")
            found.append(Finding("Threat intel", "Couldn't update the GTI threat reports", NOTE,
                                 ["Matching uses the reports already on this PC."], key="gti:sync-failed"))

    say("Reading command lines...")
    procs, hidden = cmdlines.processes()
    deep_found, deep_extra = deepcheck.analyze(deep, context) if deep else ([], {})
    _part(found, "command lines", lambda: [] if deep else cmdlines.evaluate(procs, context))
    if hidden and not deep:
        found.append(Finding("Command lines", f"{hidden} system process(es) need administrator rights to check", NOTE,
                             ["Windows hides the command lines of programs running as SYSTEM or as administrator. "
                              "Run the deep check to include them."], key="cmdline:hidden"))
    found += deep_found

    say("Checking root certificates...")
    _part(found, "certificates", certs.check_certificates)

    say("Checking drivers...")
    loaded = drivers.loaded_drivers()
    hashes: dict[str, str] = {}
    for _, path in loaded:
        try:
            hashes[str(path)] = _hash(scanner, path)
        except OSError:
            pass
    _part(found, "drivers", lambda: drivers.driver_findings(loaded, hashes, drivers.loldrivers())
          + drivers.protection_status())
    services = drivers.new_services()
    _part(found, "services", lambda: drivers.service_findings(services))

    say("Checking programs that accept connections...")
    open_doors = listening.listeners()
    _part(found, "listening programs", lambda: listening.listener_findings(open_doors))
    firewall: list[Finding] = []
    _part(firewall, "firewall", listening.firewall_findings)
    found += firewall

    say("Checking the registry...")
    reg_found: list[Finding] = []

    def registry_part() -> list[Finding]:
        findings, spots = registry.check_registry()
        return findings + registry.watch_changes(scanner.store, spots)

    _part(reg_found, "registry", registry_part)
    found += reg_found

    say("Checking programs in user folders...")
    user_programs = userpaths.running_from_user_folders()
    signatures = check_signatures([p.path for p in user_programs if not p.hidden_stream])

    # VirusTotal: the programs these checks turned up. Drivers too with an Enterprise/GTI key (a free key's
    # 4 lookups a minute would take the best part of an hour for the ~200 drivers on a typical PC).
    files: dict[str, tuple[RunningFile, str, str]] = {}

    def want(path: str | None, kind: str, area: str, why: str) -> None:
        if path and os.path.isabs(path) and Path(path).is_file():
            files.setdefault(os.path.normcase(path), (RunningFile(Path(path), kind), area, why))

    for item in open_doors:
        if not listening.is_windows_program(item.path, item.program):
            want(item.path, "program", "Listening", f"It accepts network connections ({item.program})")
    for f in firewall:
        want(f.data.get("path"), "program", "Firewall", "The firewall lets it accept connections")
    for p in user_programs:
        if not (signatures.get(str(p.path)) and signatures[str(p.path)].valid):
            want(str(p.path), "program", "User folders", "It runs from a user folder without a valid signature")
    for f in reg_found:
        want(f.data.get("path"), "program", f.area, f"The registry points to it: {f.title}")
    for r in services:
        want(drivers.image_path(r.get("path") or ""), "program", "Services", f"Installed as the service {r.get('name')}")
    if intel:
        for name, path in loaded:
            want(str(path), "driver", "Drivers", f"Loaded driver: {name}")
    verdicts: dict[str, str] = {}
    if scanner.vt is not None and files:
        say(f"Looking up {len(files)} program(s) on VirusTotal...")
        for f in judge_files(scanner, [v[0] for v in files.values()], say, cancel):
            verdicts[str(f.path)] = f.verdict.value
            _, area, why = files[os.path.normcase(str(f.path))]
            if f.verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS) or (
                    f.verdict is Verdict.UNKNOWN and area not in ("User folders",)):
                found.append(_flagged_file(f, area, why))
    _part(found, "user folders", lambda: userpaths.judge(user_programs, signatures, verdicts))
    _part(found, "hidden programs", userpaths.hidden_programs)

    if deep and isinstance(deep.get("dns"), list) and scanner.vt is not None:
        say("Checking sites from the DNS cache...")
        from atlas.network import check_network

        pairs = [(str(r.get("name") or "").lower().rstrip("."), str(r.get("data") or "").lower())
                 for r in deep["dns"] if r.get("name")]
        report = check_network(scanner, cancel=cancel, dns_pairs=pairs)
        for c in report.sites:
            if c.verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS):
                found.append(Finding("Deep check", f"This PC recently looked up a flagged site: {c.target}", WARN,
                                     c.reasons, key=f"deep:dns:{c.target}",
                                     vt_link=c.report.gui_link if c.report and c.report.found else None))

    if intel:
        say("Matching against Google Threat Intelligence...")

        def matches() -> list[Finding]:
            urls = history.visited()
            hosts = history.hosts(urls)
            hosts.update(history.hosts({u: "downloaded from" for u in scanner.store.download_urls()}))
            hosts.update(deep_extra.get("hosts") or {})
            from atlas.network import connections

            ips = {c.ip: f"{c.program} is connected to it" for c in connections()}
            return gti.match(scanner.store, hosts=hosts, urls=urls, ips=ips)

        _part(found, "threat intel", matches)
        reports, indicators = scanner.store.gti_stats()
        found.append(Finding("Threat intel", f"Checked against {indicators:,} indicators from {reports} recent GTI "
                             "reports about Windows", OK, ["Files Atlas has hashed, sites in your browser history and "
                                                           "downloads, and live connections."], key="gti:ok"))
    return sorted(found, key=lambda f: (ORDER.get(f.level, 3), f.area))
