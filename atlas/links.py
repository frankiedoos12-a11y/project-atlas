"""Check a link before opening it.

Atlas never visits the link. It asks VirusTotal what it knows about the exact address
and its site, and looks for the tricks scam links use, such as a familiar name buried
in someone else's address ("paypal.com.account-check.xyz").
"""

from __future__ import annotations

import ipaddress
import re
import sys
from dataclasses import dataclass, field
from urllib.parse import urlparse

from atlas.scanner import Scanner, Verdict
from atlas.vt_client import Report, VTError

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
              "cutt.ly", "shorturl.at", "rb.gy", "t.ly", "tiny.cc", "s.id", "lnkd.in"}

# Names scam pages like to borrow. Matched only as a whole domain label: "apple.com.x.xyz", not "pineapple".
BRANDS = {"paypal", "microsoft", "office365", "outlook", "apple", "icloud", "google", "amazon", "netflix",
          "facebook", "instagram", "whatsapp", "steam", "steamcommunity", "battle", "blizzard", "chase",
          "wellsfargo", "bankofamerica", "coinbase", "binance", "dhl", "fedex", "ups", "usps", "irs",
          "onedrive", "dropbox", "docusign", "adobe", "linkedin", "discord", "roblox", "sans", "giac"}


@dataclass
class LinkCheck:
    url: str
    verdict: Verdict = Verdict.CLEAN
    reasons: list[str] = field(default_factory=list)
    url_report: Report | None = None
    domain_report: Report | None = None

    @property
    def host(self) -> str:
        return urlparse(self.url).hostname or ""

    def raise_to(self, verdict: Verdict, reason: str) -> None:
        self.reasons.append(reason)
        if verdict.rank > self.verdict.rank:
            self.verdict = verdict


def normalize(text: str) -> str:
    url = text.strip().strip("<>\"'")
    if not re.match(r"^[a-z][a-z0-9+.-]*://", url, re.I):
        url = "http://" + url
    return url


def _registered_domain(host: str) -> str:
    """Rough "example.co.uk" / "example.com" from a host name."""
    labels = host.split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in {"co", "com", "org", "net", "ac", "gov"}:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def local_warnings(url: str) -> list[tuple[Verdict, str]]:
    """Scam-link tricks that can be spotted without asking anyone."""
    parts = urlparse(url)
    host = (parts.hostname or "").lower()
    found: list[tuple[Verdict, str]] = []
    if not host:
        return [(Verdict.ERROR, "That doesn't look like a web address")]
    if "@" in parts.netloc:
        found.append((Verdict.SUSPICIOUS, f"The address hides its real destination: everything before '@' is "
                                          f"ignored, so it really goes to {host}"))
    try:
        ipaddress.ip_address(host)
        found.append((Verdict.SUSPICIOUS, "Goes to a bare IP address instead of a named website"))
    except ValueError:
        pass
    if any(label.startswith("xn--") for label in host.split(".")):
        found.append((Verdict.SUSPICIOUS, "Uses look-alike foreign letters in the web address (punycode), "
                                          "a common trick to imitate a real site"))
    registered = _registered_domain(host)
    owner = registered.split(".")[0]
    for label in host.split(".")[:-2]:
        if label in BRANDS and label != owner:
            found.append((Verdict.SUSPICIOUS, f"Mentions {label} but the site actually belongs to {registered}"))
            break
    if host in SHORTENERS:
        found.append((Verdict.CLEAN, "This is a shortened link: where it ends up is hidden, and only the short "
                                     "link itself can be checked"))
    if parts.scheme == "http":
        found.append((Verdict.CLEAN, "Not encrypted (http, not https)"))
    return found


def read_clipboard() -> str:
    """The clipboard's text, read without a window (for the tray)."""
    if sys.platform != "win32":
        return ""
    import ctypes
    from ctypes import wintypes

    CF_UNICODETEXT = 13
    user32, kernel32 = ctypes.windll.user32, ctypes.windll.kernel32
    user32.GetClipboardData.restype = wintypes.HANDLE
    kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalLock.restype = ctypes.c_void_p
    kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
    if not user32.OpenClipboard(None):
        return ""
    try:
        handle = user32.GetClipboardData(CF_UNICODETEXT)
        if not handle:
            return ""
        pointer = kernel32.GlobalLock(handle)
        try:
            return ctypes.wstring_at(pointer) if pointer else ""
        finally:
            kernel32.GlobalUnlock(handle)
    finally:
        user32.CloseClipboard()


def _judge_link(check: LinkCheck, report: Report, threshold: int) -> None:
    """Like a file, but a lone "suspicious" vote on a web page is too common to warn about."""
    if not report.found:
        return
    detail = f"{report.malicious} malicious / {report.suspicious} suspicious of {report.total} engines"
    if report.malicious >= threshold:
        check.raise_to(Verdict.MALICIOUS, f"This link flagged by VirusTotal: {detail}")
    elif report.malicious:
        check.raise_to(Verdict.SUSPICIOUS, f"This link flagged by VirusTotal: {detail}")
    elif report.suspicious:
        check.reasons.append(f"{report.suspicious} engine(s) called it suspicious but none malicious, "
                             "which is usually noise")


def check_link(scanner: Scanner | None, text: str) -> LinkCheck:
    check = LinkCheck(normalize(text))
    for verdict, reason in local_warnings(check.url):
        if verdict is Verdict.CLEAN:
            check.reasons.append(reason)
        else:
            check.raise_to(verdict, reason)
    if check.verdict is Verdict.ERROR:
        return check
    if scanner is None or scanner.vt is None:
        check.raise_to(Verdict.ERROR, "No VirusTotal API key configured; only the offline checks ran")
        return check
    try:
        check.url_report = scanner.lookup("url", check.url)
        _judge_link(check, check.url_report, scanner.settings.malicious_threshold)
        check.domain_report = scanner.lookup("domain", check.host)
        scanner.judge_report(check, check.domain_report, f"The site {check.host}", site=True)
    except VTError as exc:
        check.raise_to(Verdict.ERROR, str(exc))
        return check
    except Exception as exc:  # network trouble
        check.raise_to(Verdict.ERROR, f"Lookup failed: {exc}")
        return check
    url_known = check.url_report.analyzed
    site_known = check.domain_report.analyzed
    if check.verdict is Verdict.CLEAN:
        if url_known:
            check.reasons.insert(0, f"No engines called this link malicious ({check.url_report.total} checked)")
        elif site_known:
            check.reasons.insert(0, f"VirusTotal hasn't scanned this exact link, but {check.host} has a clean "
                                    "record")
        else:
            check.raise_to(Verdict.UNKNOWN, f"VirusTotal has never seen this link or {check.host}. "
                                            "Brand-new sites are often scams, so be careful")
    return check
