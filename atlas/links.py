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

from atlas import allowlist
from atlas.scanner import Scanner, Verdict
from atlas.sites import registered_domain, site_warnings
from atlas.vt_client import Report, VTError, gui_link

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
              "cutt.ly", "shorturl.at", "rb.gy", "t.ly", "tiny.cc", "s.id", "lnkd.in"}

# Names scam pages like to borrow. Matched only as a whole domain label: "apple.com.x.xyz", not "pineapple".
BRANDS = {"paypal", "microsoft", "office365", "outlook", "apple", "icloud", "google", "amazon", "netflix",
          "facebook", "instagram", "whatsapp", "steam", "steamcommunity", "battle", "blizzard", "chase",
          "wellsfargo", "bankofamerica", "coinbase", "binance", "dhl", "fedex", "ups", "usps", "irs",
          "onedrive", "dropbox", "docusign", "adobe", "linkedin", "discord", "roblox", "sans", "giac"}
# The other domains each brand really uses, so its own sites aren't taken for look-alikes (outlook.live.com is
# Microsoft's). The shared allow-list (allowlist.json) covers the rest without a new release.
_MICROSOFT = {"microsoft.com", "live.com", "outlook.com", "office.com", "office365.com", "microsoftonline.com",
              "msn.com", "windows.net", "azure.com", "sharepoint.com", "onedrive.com", "skype.com", "xbox.com",
              "bing.com", "microsoft365.com", "cloud.microsoft"}
BRAND_DOMAINS = {
    "microsoft": _MICROSOFT, "outlook": _MICROSOFT, "office365": _MICROSOFT, "onedrive": _MICROSOFT,
    "apple": {"apple.com", "icloud.com"}, "icloud": {"apple.com", "icloud.com"},
    "google": {"google.com", "googleusercontent.com", "googleapis.com", "gstatic.com", "youtube.com", "gmail.com",
               "google.co.uk", "withgoogle.com", "googlesource.com", "appspot.com"},
    "amazon": {"amazon.com", "amazonaws.com", "amazon.co.uk", "amazon.ca", "amazon.de", "aws.com", "a2z.com"},
    "facebook": {"facebook.com", "fb.com", "meta.com", "fbcdn.net"},
    "instagram": {"instagram.com", "facebook.com", "meta.com"}, "whatsapp": {"whatsapp.com", "whatsapp.net", "meta.com"},
    "steam": {"steampowered.com", "steamcommunity.com", "steamstatic.com"},
    "steamcommunity": {"steampowered.com", "steamcommunity.com", "steamstatic.com"},
    "battle": {"battle.net", "blizzard.com"}, "blizzard": {"battle.net", "blizzard.com"},
    "paypal": {"paypal.com", "paypalobjects.com"}, "netflix": {"netflix.com", "nflxext.com", "nflxvideo.net"},
    "chase": {"chase.com", "jpmorganchase.com"}, "wellsfargo": {"wellsfargo.com", "wf.com"},
    "bankofamerica": {"bankofamerica.com", "bofa.com"}, "dhl": {"dhl.com", "dhl.de"},
    "ups": {"ups.com"}, "usps": {"usps.com", "usps.gov"}, "fedex": {"fedex.com"}, "irs": {"irs.gov"},
    "dropbox": {"dropbox.com", "dropboxusercontent.com"}, "docusign": {"docusign.com", "docusign.net"},
    "adobe": {"adobe.com", "adobelogin.com", "adobe.io"}, "linkedin": {"linkedin.com", "licdn.com"},
    "discord": {"discord.com", "discord.gg", "discordapp.com"}, "roblox": {"roblox.com", "rbxcdn.com"},
    "sans": {"sans.org"}, "giac": {"giac.org", "sans.org"},
}


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

    @property
    def vt_link(self) -> str | None:
        """The link's VirusTotal page, or (when nothing was looked up, e.g. no API key) the site's page, to look
        it up by hand. Only the site's name goes in that link: full links can hold sign-in tokens."""
        for report in (self.url_report, self.domain_report):
            if report is not None and report.found:
                return report.gui_link
        if self.url_report is None and self.domain_report is None and self.host:
            try:
                ipaddress.ip_address(self.host)
                return gui_link("ip", self.host)
            except ValueError:
                return gui_link("domain", self.host)
        return None

    def raise_to(self, verdict: Verdict, reason: str) -> None:
        self.reasons.append(reason)
        if verdict.rank > self.verdict.rank:
            self.verdict = verdict


def normalize(text: str) -> str:
    url = text.strip().strip("<>\"'")
    if not re.match(r"^[a-z][a-z0-9+.-]*://", url, re.I):
        url = "http://" + url
    return url


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
    registered = registered_domain(host)
    owner = registered.split(".")[0]
    for label in host.split(".")[:-2]:
        if label in BRANDS and label != owner and registered not in BRAND_DOMAINS.get(label, ()):
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


def trusted_why(scanner: Scanner | None, host: str) -> str | None:
    """Why this site is trusted (your list or the shared allow-list), or None."""
    settings = getattr(scanner, "settings", None)
    if settings is None or not host:
        return None
    shared = allowlist.shared_sites(scanner.store) if getattr(settings, "shared_allowlist", False) else {}
    return allowlist.why_trusted(host, getattr(settings, "trusted_sites", []), shared)


def check_link(scanner: Scanner | None, text: str) -> LinkCheck:
    check = LinkCheck(normalize(text))
    trusted = trusted_why(scanner, check.host)
    if trusted:  # Atlas's own guesses are skipped; VirusTotal and security vendors are still asked
        check.reasons.append(f"{trusted}, so Atlas's own guesses about it are skipped")
    for verdict, reason in local_warnings(check.url):
        if verdict is Verdict.CLEAN:
            check.reasons.append(reason)
        elif not trusted or verdict is Verdict.ERROR:
            check.raise_to(verdict, reason)
    if check.verdict is Verdict.ERROR:
        return check
    if scanner is None or scanner.vt is None:
        check.raise_to(Verdict.ERROR, "VirusTotal isn't connected, so only Atlas's own checks ran. Use View on "
                                      "VirusTotal to look the site up")
        return check
    try:
        check.url_report = scanner.lookup("url", check.url)
        _judge_link(check, check.url_report, scanner.settings.malicious_threshold)
        check.domain_report = scanner.lookup("domain", check.host)
        scanner.judge_report(check, check.domain_report, f"The site {check.host}", site=True)
        if trusted:
            for warn, reason in site_warnings(scanner.lookup, check.host, check.domain_report):
                if warn and reason.startswith("Security vendors list"):
                    check.raise_to(Verdict.SUSPICIOUS, reason)
                else:
                    check.reasons.append(reason)
        else:
            scanner.judge_site_record(check, check.host, check.domain_report)
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
