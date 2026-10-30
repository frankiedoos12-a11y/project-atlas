"""Is this email a scam? Open the email file itself (.eml or Outlook's .msg) and Atlas checks what pasting loses.

- The links' real targets: "Sign in to PayPal" can point anywhere. A link whose text shows one site but goes to
  another is flagged (Outlook's Safe Links and Google's redirect wrappers are unwrapped first).
- The real sender: a display name like "Microsoft Support" sent from someone else's domain, and a Reply-To
  that sends your answer somewhere else.
- The sign-in checks (SPF, DKIM, DMARC) your mail provider recorded when the email arrived.
- How new the sender's domain is, and every attachment (risky types, and the file's fingerprint on VirusTotal).

The text itself then goes through the same rules as the pasted message check. Everything is read on this PC;
only the links, the sender's domain and attachment fingerprints go to VirusTotal. Attachments are never opened
or saved.
"""

from __future__ import annotations

import email
import hashlib
import re
from dataclasses import dataclass, field
from email import policy
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from atlas.links import BRAND_DOMAINS, BRANDS
from atlas.scam import MAX_LINKS, Reason, ScamCheck, check_message, links_in
from atlas.sites import registered_domain, site_warnings

EMAIL_TYPES = {".eml", ".msg"}
MAX_TEXT = 200_000  # characters of body text to read
# Mail and marketing services whose links always point somewhere other than the text shows.
TRACKERS = {"list-manage.com", "sendgrid.net", "mailchimp.com", "mandrillapp.com", "hubspotlinks.com",
            "hs-sites.com", "mcusercontent.com", "exacttarget.com", "sfmc-content.com", "constantcontact.com",
            "rs6.net", "mailgun.org", "awstrack.me", "cmail19.com", "cmail20.com", "createsend.com",
            "klaviyo.com", "substack.com", "linkedin.com", "facebookmail.com"}
FREEMAIL = {"gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "yahoo.com", "aol.com",
            "icloud.com", "proton.me", "protonmail.com", "gmx.com", "mail.com", "yandex.com", "zoho.com"}
RISKY_ATTACHMENTS = {
    4: {".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".hta", ".ps1",
        ".msi", ".lnk", ".jar", ".cpl", ".reg"},
    3: {".html", ".htm", ".shtml", ".svg", ".iso", ".img", ".vhd", ".vhdx", ".one", ".xll"},
    1: {".zip", ".rar", ".7z", ".docm", ".xlsm", ".pptm"},
}
DOMAIN_TEXT = re.compile(r"(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,24})(?:[/:?#]|\s|$)", re.I)
AUTH = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.I)


@dataclass
class Attachment:
    name: str
    data: bytes

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()


@dataclass
class Email:
    subject: str = ""
    sender: str = ""  # "Name <address>"
    sender_name: str = ""
    sender_address: str = ""
    reply_to: str = ""
    auth: str = ""  # the top Authentication-Results header (your own provider's)
    text: str = ""
    anchors: list[tuple[str, str]] = field(default_factory=list)  # (href, the text shown)
    attachments: list[Attachment] = field(default_factory=list)


# --- Reading the file --------------------------------------------------------------------------------------------

class _Anchors(HTMLParser):
    """Links and visible text of an HTML body."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.anchors: list[tuple[str, str]] = []
        self.text: list[str] = []
        self._href: str | None = None
        self._shown: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("style", "script", "head"):
            self._skip += 1
        elif tag == "a":
            self._href = dict(attrs).get("href") or None
            self._shown = []
        elif tag in ("br", "p", "div", "tr", "li"):
            self.text.append("\n")

    def handle_endtag(self, tag):
        if tag in ("style", "script", "head"):
            self._skip = max(0, self._skip - 1)
        elif tag == "a" and self._href is not None:
            self.anchors.append((self._href, " ".join("".join(self._shown).split())))
            self._href = None

    def handle_data(self, data):
        if self._skip:
            return
        self.text.append(data)
        if self._href is not None:
            self._shown.append(data)


def _from_html(html: str, msg: Email) -> None:
    parser = _Anchors()
    try:
        parser.feed(html[:MAX_TEXT])
    except Exception:  # broken HTML: keep what was read
        pass
    msg.anchors += parser.anchors
    if not msg.text.strip():
        msg.text = re.sub(r"[ \t]+", " ", "".join(parser.text))


def _headers(msg: Email, headers) -> None:
    msg.subject = str(headers.get("Subject", "") or "")
    msg.sender = str(headers.get("From", "") or "")
    msg.sender_name, msg.sender_address = parseaddr(msg.sender)
    reply = getaddresses([str(v) for v in headers.get_all("Reply-To", []) or []])
    msg.reply_to = reply[0][1] if reply else ""
    results = headers.get_all("Authentication-Results", []) or []
    msg.auth = str(results[0]) if results else ""  # the top one: added by your own provider when it arrived


def read_eml(data: bytes) -> Email:
    parsed = email.message_from_bytes(data, policy=policy.default)
    msg = Email()
    _headers(msg, parsed)
    html = ""
    for part in parsed.walk():
        if part.is_multipart():
            continue
        name = part.get_filename()
        kind = part.get_content_type()
        if name or part.get_content_disposition() == "attachment":
            msg.attachments.append(Attachment(name or "unnamed", part.get_payload(decode=True) or b""))
        elif kind == "text/plain" and not msg.text:
            msg.text = part.get_content()[:MAX_TEXT]
        elif kind == "text/html" and not html:
            html = part.get_content()
    if html:
        _from_html(html, msg)
    return msg


def read_msg(path: Path) -> Email:
    """Outlook's .msg: an OLE file of MAPI properties (__substg1.0_<id><type>)."""
    import olefile

    with olefile.OleFileIO(str(path)) as ole:
        def prop(code: str, storage: str = "") -> str | bytes | None:
            for kind in ("001F", "001E", "0102"):
                name = f"{storage}__substg1.0_{code}{kind}"
                if ole.exists(name):
                    raw = ole.openstream(name).read()
                    if kind == "001F":
                        return raw.decode("utf-16-le", "replace").rstrip("\x00")
                    if kind == "001E":
                        return raw.decode("cp1252", "replace").rstrip("\x00")
                    return raw
            return None

        headers = prop("007D")  # the transport headers, as received
        msg = Email()
        if isinstance(headers, str) and headers.strip():
            _headers(msg, email.message_from_string(headers, policy=policy.default))
        msg.subject = msg.subject or str(prop("0037") or "")
        if not msg.sender_address:
            msg.sender_name = str(prop("0C1A") or "")
            msg.sender_address = str(prop("5D01") or prop("0C1F") or "")
            msg.sender = f"{msg.sender_name} <{msg.sender_address}>"
        body = prop("1000")
        msg.text = body[:MAX_TEXT] if isinstance(body, str) else ""
        html = prop("1013")
        if isinstance(html, bytes):
            html = html.decode("utf-8", "replace")
        if html:
            _from_html(html, msg)
        for entry in ole.listdir(streams=False, storages=True):
            if len(entry) == 1 and entry[0].startswith("__attach_version1.0_"):
                where = entry[0] + "/"
                data = prop("3701", where)
                name = prop("3707", where) or prop("3704", where) or "unnamed"
                if isinstance(data, bytes):
                    msg.attachments.append(Attachment(str(name), data))
    return msg


def read_email(path: Path) -> Email:
    if path.suffix.lower() == ".msg":
        return read_msg(path)
    return read_eml(path.read_bytes())


# --- Checking it -------------------------------------------------------------------------------------------------

def unwrap(href: str) -> str:
    """The real target behind Outlook Safe Links and Google's redirect links."""
    parts = urlparse(href)
    host = (parts.hostname or "").lower()
    query = parse_qs(parts.query)
    if host.endswith("safelinks.protection.outlook.com") and query.get("url"):
        return query["url"][0]
    if host in ("www.google.com", "google.com") and parts.path == "/url" and (query.get("q") or query.get("url")):
        return (query.get("q") or query.get("url"))[0]
    return href


def _domain(address: str) -> str:
    return registered_domain(address.rsplit("@", 1)[-1]) if "@" in address else ""


def _brand_in(name: str) -> str | None:
    words = re.findall(r"[a-z0-9]+", name.lower())
    joined = "".join(words)
    return next((b for b in sorted(BRANDS, key=len, reverse=True) if b in words or (len(b) > 5 and b in joined)),
                None)


def _owns(brand: str, domain: str) -> bool:
    return domain.split(".")[0] == brand or domain in BRAND_DOMAINS.get(brand, ())


def link_mismatches(anchors: list[tuple[str, str]], sender_domain: str = "") -> list[Reason]:
    found, seen = [], set()
    for href, shown in anchors:
        target = urlparse(unwrap(href))
        if target.scheme not in ("http", "https") or not target.hostname:
            continue
        real = registered_domain(target.hostname)
        m = DOMAIN_TEXT.search(shown + " ")
        if not m or real in TRACKERS or real == sender_domain:
            continue
        says = registered_domain(m.group(1))
        if says != real and (says, real) not in seen:
            seen.add((says, real))
            found.append(Reason("The link isn't what it says", f"The link shows {says} but really goes to {real}. "
                                "Scam emails disguise links this way. Type the address yourself instead.",
                                f"{shown[:80]} -> {target.hostname}", points=3))
    return found


def sender_reasons(msg: Email) -> list[Reason]:
    found = []
    domain = _domain(msg.sender_address)
    brand = _brand_in(msg.sender_name)
    if brand and domain and not _owns(brand, domain):
        free = domain in FREEMAIL
        found.append(Reason("Sender pretends to be a company",
                            f"It's signed {msg.sender_name!r} but was sent from " +
                            (f"a free {domain} address. A real company doesn't email you from one." if free else
                             f"{domain}, which isn't {brand.title()}'s."), msg.sender, points=3))
    reply = _domain(msg.reply_to)
    if reply and domain and reply != domain:
        found.append(Reason("Replies go somewhere else", f"Your reply would go to {msg.reply_to}, not the sender's "
                            f"{domain}. Scammers do this so they get the answers.", msg.reply_to, points=1))
    results = {k.lower(): v.lower() for k, v in AUTH.findall(msg.auth)}
    failed = [k.upper() for k, v in results.items() if v in ("fail", "softfail", "permerror")]
    if failed:
        found.append(Reason("Failed the sender checks", f"Your mail provider's {', '.join(failed)} check failed: "
                            "the email may not really come from the address it shows.", msg.auth[:160], points=3))
    return found


def attachment_reasons(msg: Email, scanner=None) -> list[Reason]:
    found = []
    for a in msg.attachments:
        suffix = Path(a.name).suffix.lower()
        risk = next((points for points, kinds in RISKY_ATTACHMENTS.items() if suffix in kinds), 0)
        if risk >= 3:
            found.append(Reason("Risky attachment", f"{a.name} is a kind of file email scams use to run code or "
                                "show a fake sign-in page. Don't open it.", a.name, points=risk))
        elif risk:
            found.append(Reason("Attachment to be careful with", f"{a.name} can hide a program or macros. Only "
                                "open it if you expected it.", a.name, points=risk))
        if scanner is not None and getattr(scanner, "vt", None) is not None and a.data:
            try:
                report = scanner.lookup("file", a.sha256)
            except Exception:  # no network: the other checks still count
                continue
            if report.found and report.malicious >= scanner.settings.malicious_threshold:
                found.append(Reason("Dangerous attachment", f"VirusTotal: {report.malicious} engines flag {a.name} "
                                    "as malicious.", a.sha256, points=4))
    return found


def domain_reasons(msg: Email, scanner=None) -> list[Reason]:
    domain = _domain(msg.sender_address)
    if not domain or scanner is None or getattr(scanner, "vt", None) is None or domain in FREEMAIL:
        return []
    try:
        warnings = site_warnings(scanner.lookup, domain)
    except Exception:
        return []
    return [Reason("Sender's domain", text, domain, points=2) for warn, text in warnings if warn]


def check_email(path: Path, scanner=None) -> ScamCheck:
    msg = read_email(path)
    domain = _domain(msg.sender_address)
    extra = sender_reasons(msg) + link_mismatches(msg.anchors, domain) + attachment_reasons(msg, scanner) \
        + domain_reasons(msg, scanner)
    targets = []
    for href, _ in msg.anchors:
        url = unwrap(href)
        if url.lower().startswith(("http://", "https://")) and url.lower() not in {t.lower() for t in targets}:
            targets.append(url)
    targets += [u for u in links_in(msg.text) if u.lower() not in {t.lower() for t in targets}]
    # Trackers and the sender's own site are checked last, so the budget goes to the links that matter.
    targets.sort(key=lambda u: registered_domain(urlparse(u if "//" in u else "http://" + u).hostname or "")
                 in TRACKERS | {domain})
    result = check_message(f"{msg.subject}\n{msg.text}", scanner, links=targets[:MAX_LINKS * 4], extra=extra)
    checks = {k.upper(): v for k, v in AUTH.findall(msg.auth)}
    result.about = [("From", msg.sender or "(unknown)"), ("Subject", msg.subject or "(none)")]
    if msg.reply_to:
        result.about.append(("Reply-To", msg.reply_to))
    result.about.append(("Sender checks", ", ".join(f"{k} {v}" for k, v in checks.items()) or
                         "not recorded in this file"))
    if msg.attachments:
        result.about.append(("Attachments", ", ".join(a.name for a in msg.attachments)))
    return result
