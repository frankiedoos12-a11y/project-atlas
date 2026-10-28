"""Combine local checks and VirusTotal reports into a single verdict for a file."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from urllib.parse import urlparse

from atlas.archives import can_inspect, inspect
from atlas.behaviour import describe_behaviour
from atlas.config import Settings
from atlas.db import Store
from atlas.local_checks import (
    MarkOfTheWeb,
    Signature,
    check_signature,
    is_risky,
    read_motw,
    sha256_file,
)
from atlas.quarantine import quarantine_file
from atlas.sites import age_text, site_warnings
from atlas.vt_client import Report, VTClient, VTError

log = logging.getLogger(__name__)

NEW_FILE_DAYS = 3  # a program VirusTotal first saw this recently gets a note even when clean


def short_url(url: str) -> str:
    """Drop the query string and fragment, which often hold temporary access tokens."""
    parts = urlparse(url)
    return f"{parts.scheme}://{parts.netloc}{parts.path}" if parts.netloc else url


class Verdict(str, Enum):
    CLEAN = "clean"
    UNKNOWN = "unknown"  # VirusTotal has never seen it and it can run code
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    ERROR = "error"

    @property
    def rank(self) -> int:
        return [Verdict.CLEAN, Verdict.ERROR, Verdict.UNKNOWN, Verdict.SUSPICIOUS, Verdict.MALICIOUS].index(self)


@dataclass
class ScanResult:
    path: Path
    sha256: str | None = None
    verdict: Verdict = Verdict.CLEAN
    reasons: list[str] = field(default_factory=list)
    file_report: Report | None = None
    url_report: Report | None = None
    domain_report: Report | None = None
    page_domain_report: Report | None = None
    motw: MarkOfTheWeb | None = None
    signature: Signature | None = None
    action: str | None = None  # e.g. "quarantined #4"
    behaviour: list[str] = field(default_factory=list)  # what sandboxes saw it do, for flagged files
    gti: list[dict] = field(default_factory=list)  # Google Threat Intelligence reports and actors naming it

    @property
    def threat_text(self) -> str | None:
        """e.g. "Remcos (trojan)": the malware family engines and sandboxes agree on."""
        report = self.file_report
        if not (report and report.threat_names and (report.malicious or report.suspicious or report.sandbox)):
            return None
        names = ", ".join(n[:1].upper() + n[1:] for n in report.threat_names[:3])
        kind = report.label.split(".")[0] if report.label else None
        return f"{names} ({kind})" if kind else names

    @property
    def signer_text(self) -> str | None:
        """e.g. "Signed by Foxit Software Inc.", or None for files that can't be signed."""
        sig = self.signature
        if sig is None:
            return None
        if sig.valid:
            return f"Signed by {sig.signer}"
        if sig.status == "NotSigned":
            return "Not signed"
        return f"Signature problem: {sig.status}"

    @property
    def source_text(self) -> str | None:
        """Where the file came from, e.g. "From cdn.example.com via www.foxit.com"."""
        if not (self.motw and self.motw.host_url):
            return None
        text = f"From {urlparse(self.motw.host_url).hostname or short_url(self.motw.host_url)}"
        page = urlparse(self.motw.referrer_url or "").hostname
        return f"{text} via {page}" if page else text

    def raise_to(self, verdict: Verdict, reason: str) -> None:
        self.reasons.append(reason)
        if verdict.rank > self.verdict.rank:
            self.verdict = verdict


def threat_lines(result: ScanResult) -> list[tuple[str, str, None]]:
    """(label, text, None) rows describing a flagged file, for the windows' detail panels."""
    rows = []
    if result.threat_text:
        rows.append(("Known as", result.threat_text, None))
    rows += [("Does", line, None) for line in result.behaviour]
    rows += [("GTI " + g["kind"], g["name"], None) for g in result.gti]
    report = result.file_report
    if report and (report.malicious or report.suspicious or report.sandbox):
        rows += [("Sandbox", s, None) for s in report.sandbox[:4]]
        if report.rules:
            rows.append(("Rules", ", ".join(report.rules[:5]), None))
    return rows


class Scanner:
    def __init__(self, settings: Settings, store: Store, vt: VTClient | None, data_dir: Path):
        self.settings = settings
        self.store = store
        self.vt = vt
        self.data_dir = data_dir

    def lookup(self, kind: str, target: str) -> Report:
        cached = self.store.cached_report(kind, target, self.settings.cache_hours)
        if cached is not None:
            return cached
        report = getattr(self.vt, f"{kind}_report")(target)  # file_report, url_report, domain_report, ip_report
        self.store.cache_report(report)
        return report

    def behaviour(self, sha256: str) -> list[str]:
        """What sandboxes saw the file do, in plain words. Cached like reports."""
        cached = self.store.cached_extra("behaviour", sha256, self.settings.cache_hours)
        if cached is not None:
            return cached
        lines = describe_behaviour(self.vt.behaviour_summary(sha256))
        self.store.cache_extra("behaviour", sha256, lines)
        return lines

    def gti_reports(self, sha256: str) -> list[dict]:
        """Google Threat Intelligence reports and threat actors naming a file (only with a GTI key)."""
        if not self.settings.gti_enabled or not hasattr(self.vt, "api_get"):
            return []
        from atlas import gti

        try:
            return gti.reports_for_file(self.vt, self.store, sha256) if gti.available(self.vt, self.store) else []
        except Exception:  # extra context only: never let it spoil a verdict
            log.exception("GTI lookup failed for %s", sha256)
            return []

    def explain(self, result: ScanResult) -> None:
        """Behaviour and threat reports for a flagged file."""
        result.behaviour = self.behaviour(result.sha256)
        result.gti = self.gti_reports(result.sha256)

    def judge_site_record(self, result, host: str, report: Report | None = None) -> None:
        """Warn about brand-new sites and ones security vendors list as phishing, malware and so on.

        `result` is anything with raise_to() and reasons (a ScanResult or a LinkCheck).
        """
        for warn, text in site_warnings(self.lookup, host, report):
            if warn:
                result.raise_to(Verdict.SUSPICIOUS, text)
            else:
                result.reasons.append(text)

    def judge_report(self, result: ScanResult, report: Report, what: str, site: bool = False) -> None:
        """Turn a VirusTotal report into a verdict.

        Website reports (site=True) are noisy: even big, legitimate sites carry a stray
        vote or two. So a site only causes a warning once it reaches the malicious
        threshold, and never quarantines a file on its own (it may be a shared host).
        """
        if not report.found:
            return
        threshold = self.settings.malicious_threshold
        detail = f"{report.malicious} malicious / {report.suspicious} suspicious of {report.total} engines"
        if report.label:
            detail += f" ({report.label})"
        if site:
            if report.malicious >= threshold:
                result.raise_to(Verdict.SUSPICIOUS, f"{what} flagged by VirusTotal: {detail}")
        elif report.malicious >= threshold:
            result.raise_to(Verdict.MALICIOUS, f"{what} flagged by VirusTotal: {detail}")
        elif report.malicious or report.suspicious:
            result.raise_to(Verdict.SUSPICIOUS, f"{what} flagged by VirusTotal: {detail}")

    def scan(self, path: Path, act: bool = True) -> ScanResult:
        """Scan one file. With act=True, malicious files are quarantined per settings."""
        result = ScanResult(path=path)
        try:
            result.sha256 = sha256_file(path)
        except OSError as exc:
            result.raise_to(Verdict.ERROR, f"Could not read file: {exc}")
            return self._finish(result)

        result.motw = read_motw(path)
        result.signature = check_signature(path)
        risky = is_risky(path)

        if result.signature and result.signature.status == "HashMismatch":
            result.raise_to(Verdict.SUSPICIOUS, "Digital signature is broken: the file was modified after signing")

        if self.vt is None:
            result.raise_to(Verdict.ERROR, "No VirusTotal API key configured; only local checks ran")
            return self._finish(result)

        inside: list[str] = []
        try:
            result.file_report = self.lookup("file", result.sha256)
            self.judge_report(result, result.file_report, "File")
            contents_vouch = None
            if can_inspect(path):
                inside, contents_vouch = self._check_archive(result)
            if not result.file_report.analyzed and risky:
                unseen = ("VirusTotal knows this file but no engine has scanned it"
                          if result.file_report.found else "VirusTotal has never seen this file")
                if result.signature and result.signature.valid:
                    result.reasons.append(f"{unseen}, but it is validly signed by {result.signature.signer}")
                elif contents_vouch:
                    result.reasons.append(f"{unseen}, {contents_vouch}")
                else:
                    result.raise_to(Verdict.UNKNOWN,
                                    f"{unseen}, it can run or contain code, and it is not validly signed")
                    self._maybe_upload(result)

            if self.settings.check_source_url and result.motw and result.motw.host_url:
                url = result.motw.host_url
                if url.lower().startswith(("http://", "https://")):
                    result.url_report = self.lookup("url", url)
                    self.judge_report(result, result.url_report, "Download URL")
                    domain = urlparse(url).hostname
                    if domain:
                        result.domain_report = self.lookup("domain", domain)
                        self.judge_report(result, result.domain_report, f"Download site {domain}", site=True)
                        self.judge_site_record(result, domain, result.domain_report)

                # The page the link was on. Fake download pages often serve their files from
                # legitimate cloud storage, so this site can be the only bad signal.
                # Only the domain is looked up: page URLs can carry search terms or account details.
                page = result.motw.referrer_url or ""
                page_domain = urlparse(page).hostname if page.lower().startswith(("http://", "https://")) else None
                if page_domain and page_domain != urlparse(url).hostname:
                    result.page_domain_report = self.lookup("domain", page_domain)
                    self.judge_report(result, result.page_domain_report, f"Linking page site {page_domain}",
                                       site=True)
                    self.judge_site_record(result, page_domain, result.page_domain_report)

            report = result.file_report
            if report.found and (report.malicious or report.suspicious or report.sandbox):
                self.explain(result)
        except VTError as exc:
            result.raise_to(Verdict.ERROR, str(exc))
        except Exception as exc:  # network failures etc. must never crash the watcher
            log.exception("Lookup failed for %s", path)
            result.raise_to(Verdict.ERROR, f"Lookup failed: {exc}")

        if not result.reasons:
            if result.file_report and result.file_report.analyzed:
                result.reasons.append(f"No engines flagged this file ({result.file_report.total} checked)")
            else:
                result.reasons.append("VirusTotal has no scan results for this file, but it is not a type that can run code")
        report = result.file_report
        if report and report.analyzed and report.first_seen and result.verdict is Verdict.CLEAN and risky:
            days = (time.time() - report.first_seen) / 86400
            if days < NEW_FILE_DAYS:
                result.reasons.append(f"VirusTotal first saw this file {age_text(days)}. Engines can take a few "
                                      "days to catch up with new malware, so be careful with it")
        result.reasons.extend(inside)

        if act and result.verdict is Verdict.MALICIOUS and self.settings.quarantine_malicious:
            try:
                qid = quarantine_file(path, result.sha256, "; ".join(result.reasons), self.store, self.data_dir)
                result.action = f"quarantined #{qid}"
            except OSError as exc:
                result.action = f"quarantine failed: {exc}"
        return self._finish(result)

    def _check_archive(self, result: ScanResult) -> tuple[list[str], str | None]:
        """Look up the programs inside a ZIP, 7z, RAR or ISO. Returns (notes for the end of the reasons,
        and why the contents make an otherwise-unknown archive fine, or None if they don't)."""
        listing = inspect(result.path)
        kind = listing.kind
        for problem in listing.problems:
            result.raise_to(Verdict.SUSPICIOUS, problem)
        unseen = []
        for member in listing.hashed:
            report = self.lookup("file", member.sha256)
            self.judge_report(result, report, f"Inside the {kind}: {member.name}")
            if not report.analyzed:
                unseen.append(member.name)
        if unseen:
            names = ", ".join(unseen[:3]) + (f" and {len(unseen) - 3} more" if len(unseen) > 3 else "")
            result.raise_to(Verdict.UNKNOWN, f"VirusTotal has never seen {len(unseen)} program(s) inside the {kind}: "
                                             f"{names}")
        notes = list(listing.notes)
        if listing.hashed:
            notes.insert(0, f"Checked {len(listing.hashed)} program(s) inside the {kind}")
        elif listing.members and not listing.risky:
            notes.insert(0, f"The {kind} holds {len(listing.members)} file(s), none of which can run code")
        if unseen or listing.problems or listing.notes or result.verdict.rank >= Verdict.SUSPICIOUS.rank:
            return notes, None
        if listing.hashed:
            return notes, f"but every program inside the {kind} is known to VirusTotal and none were flagged"
        return notes, f"but nothing inside the {kind} can run code" if not listing.risky else None

    def _maybe_upload(self, result: ScanResult) -> None:
        if not self.settings.upload_unknown_files:
            return
        try:
            analysis_id = self.vt.upload_file(result.path)
            result.reasons.append(f"Uploaded to VirusTotal for analysis (id {analysis_id}); rescan later")
        except VTError as exc:
            result.reasons.append(f"Upload failed: {exc}")

    def _finish(self, result: ScanResult) -> ScanResult:
        source = short_url(result.motw.host_url) if result.motw and result.motw.host_url else None
        self.store.record_scan(str(result.path), result.sha256, result.verdict.value, result.reasons,
                               source, result.action)
        return result
