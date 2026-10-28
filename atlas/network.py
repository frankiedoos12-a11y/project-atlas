"""Network watch: which programs are talking to the internet right now, and to whom.

Atlas lists every open connection to an internet address (not your home network), asks
VirusTotal about each address, and names the program behind it. When Windows allows it,
it also checks the sites this PC looked up recently (the DNS cache). Recent Windows builds
only show that list to administrators, and Atlas doesn't run as one, so it may be missing.

Nothing is blocked or changed: this only reports.
"""

from __future__ import annotations

import ipaddress
import logging
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from atlas.local_checks import run_powershell_json
from atlas.scanner import Scanner, Verdict
from atlas.sites import registered_domain
from atlas.vt_client import Report, VTError

log = logging.getLogger(__name__)

LIVE_STATES = {"ESTABLISHED", "SYN_SENT", "SYN_RECV", "CLOSE_WAIT", "FIN_WAIT1", "FIN_WAIT2"}
MAX_SITES = 300  # DNS-cache names looked up per check
WORKERS = 6


@dataclass
class Connection:
    pid: int
    program: str  # e.g. "chrome.exe"
    path: str | None  # the program file, when Windows says
    ip: str
    port: int


@dataclass
class RemoteCheck:
    """One internet address (or looked-up site) and what VirusTotal says about it."""

    target: str  # IP address, or host name for DNS-cache entries
    kind: str  # "ip" or "domain"
    connections: list[Connection] = field(default_factory=list)
    hostnames: list[str] = field(default_factory=list)  # names that pointed at this address
    verdict: Verdict = Verdict.CLEAN
    reasons: list[str] = field(default_factory=list)
    report: Report | None = None

    @property
    def programs(self) -> list[str]:
        return sorted({c.program for c in self.connections})

    def raise_to(self, verdict: Verdict, reason: str) -> None:
        self.reasons.append(reason)
        if verdict.rank > self.verdict.rank:
            self.verdict = verdict


@dataclass
class NetworkReport:
    addresses: list[RemoteCheck] = field(default_factory=list)  # live connections, one per address
    sites: list[RemoteCheck] = field(default_factory=list)  # recently looked-up sites
    dns_available: bool = True
    errors: list[str] = field(default_factory=list)

    @property
    def flagged(self) -> list[RemoteCheck]:
        return [c for c in self.addresses + self.sites if c.verdict in (Verdict.MALICIOUS, Verdict.SUSPICIOUS)]


def is_internet(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip.split("%")[0]).is_global
    except ValueError:
        return False


def connections() -> list[Connection]:
    """Open connections to internet addresses, one per program and address."""
    import psutil

    names: dict[int, tuple[str, str | None]] = {}
    found: dict[tuple[int, str], Connection] = {}
    for c in psutil.net_connections("inet"):
        if not c.raddr or c.status not in LIVE_STATES or not is_internet(c.raddr.ip):
            continue
        pid = c.pid or 0
        if pid not in names:
            try:
                p = psutil.Process(pid)
                names[pid] = (p.name(), p.exe() or None)
            except (psutil.Error, OSError):
                names[pid] = ("System" if pid in (0, 4) else f"process {pid}", None)
        program, path = names[pid]
        found.setdefault((pid, c.raddr.ip), Connection(pid, program, path, c.raddr.ip, c.raddr.port))
    return list(found.values())


_DNS_SCRIPT = ("ConvertTo-Json -Compress -InputObject @(Get-DnsClientCache -ErrorAction SilentlyContinue |"
               " Where-Object { $_.Type -in 1, 28, 5 } | Select-Object Entry, Data)")


def dns_cache() -> list[tuple[str, str]] | None:
    """(name, address or alias) pairs Windows remembers, or None if Windows won't show them."""
    try:
        rows = run_powershell_json(_DNS_SCRIPT, timeout=60)
    except Exception:  # PowerShell missing or broken: treat like "not available"
        log.exception("Couldn't read the DNS cache")
        return None
    pairs = [(str(r.get("Entry") or "").lower().rstrip("."), str(r.get("Data") or "").lower().rstrip("."))
             for r in rows if r.get("Entry")]
    return pairs or None  # empty means "administrators only" on recent Windows


def _worth_checking(name: str) -> bool:
    return "." in name and not name.endswith((".local", ".lan", ".home", ".arpa", ".internal")) and \
        not _is_any_ip(name)


def _is_any_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def _judge_address(scanner: Scanner, check: RemoteCheck) -> None:
    """IP addresses are shared (cloud hosts, CDNs), so like websites they need several engines to count."""
    report = check.report = scanner.lookup("ip", check.target)
    if not report.found:
        return
    owner = f" ({report.owner})" if report.owner else ""
    detail = f"{report.malicious} malicious / {report.suspicious} suspicious of {report.total} engines"
    if report.malicious >= scanner.settings.malicious_threshold:
        check.raise_to(Verdict.SUSPICIOUS, f"This address{owner} is flagged by VirusTotal: {detail}")
    elif report.malicious:
        check.reasons.append(f"{report.malicious} engine(s) flagged this address{owner}, which is common for "
                             "shared hosting and usually not a concern on its own")
    elif report.owner:
        check.reasons.append(f"Belongs to {report.owner}")


def _judge_site(scanner: Scanner, check: RemoteCheck) -> None:
    report = check.report = scanner.lookup("domain", check.target)
    scanner.judge_report(check, report, f"The site {check.target}", site=True)
    scanner.judge_site_record(check, check.target, report)


def check_network(scanner: Scanner, progress: Callable[[str], None] | None = None,
                  cancel: threading.Event | None = None, include_dns: bool = True,
                  dns_pairs: list[tuple[str, str]] | None = None) -> NetworkReport:
    """`dns_pairs` (name, address) from an administrator's deep check replace reading the DNS cache."""
    result = NetworkReport()
    if scanner.vt is None:
        result.errors.append("No VirusTotal API key configured. Run: atlas set-key")
        return result
    say = progress or (lambda text: None)

    say("Listing connections...")
    by_ip: dict[str, RemoteCheck] = {}
    for conn in connections():
        by_ip.setdefault(conn.ip, RemoteCheck(conn.ip, "ip")).connections.append(conn)

    pairs = dns_pairs if dns_pairs is not None else dns_cache() if include_dns else None
    result.dns_available = pairs is not None or not include_dns
    names = set()
    for name, data in pairs or []:
        if data in by_ip and name not in by_ip[data].hostnames:
            by_ip[data].hostnames.append(name)
        if _worth_checking(name):
            names.add(name)
    # One check per site: "a.example.com" and "b.example.com" share their registration and owner.
    sites = {}
    for name in sorted(names):
        sites.setdefault(registered_domain(name), name)
    result.addresses = list(by_ip.values())
    result.sites = [RemoteCheck(name, "domain") for name in list(sites.values())[:MAX_SITES]]

    todo = [(c, _judge_address) for c in result.addresses] + [(c, _judge_site) for c in result.sites]
    done = 0

    def run(item):
        nonlocal done
        check, judge = item
        if cancel and cancel.is_set():
            return
        try:
            judge(scanner, check)
        except VTError as exc:
            check.raise_to(Verdict.ERROR, str(exc))
        except Exception as exc:  # network trouble: report it, keep going
            check.raise_to(Verdict.ERROR, f"Lookup failed: {exc}")
        done += 1
        say(f"Checked {done} of {len(todo)} addresses and sites...")

    with ThreadPoolExecutor(WORKERS) as pool:
        list(pool.map(run, todo))
    for check in result.addresses + result.sites:
        if check.verdict is Verdict.CLEAN and not check.reasons:
            check.reasons.append("Not flagged by VirusTotal" if check.report and check.report.found
                                 else "VirusTotal has no record of it")
    order = lambda c: (-c.verdict.rank, c.target)  # noqa: E731
    result.addresses.sort(key=order)
    result.sites.sort(key=order)
    return result


def program_path(check: RemoteCheck) -> Path | None:
    paths = [c.path for c in check.connections if c.path]
    return Path(paths[0]) if paths else None
