"""Report a mistake: when Atlas wrongly warns about a site, file or finding, send it to the project.

"Report a mistake" opens a ready-made report for the user to read and send themselves: a GitHub issue (the
"Wrong warning" form) or, when the project has a report address, an email. Nothing is sent by Atlas, and the
report holds only what's needed: the site name (never the full address, which can hold sign-in tokens), or
the file's name and fingerprint (SHA-256), what Atlas said and why, and the Atlas version. Your user folder
is replaced by %USERPROFILE%.
"""

from __future__ import annotations

import os
import re
from urllib.parse import quote, urlencode

from atlas import __version__
from atlas.updates import REPO

ISSUE_FORM = "false-positive.yml"
REPORT_EMAIL = ""  # set once the project has an address for people without a GitHub account
MAX_REASONS, MAX_REASON = 6, 240


def scrub(text: str) -> str:
    """Take the user's folder and name out of a line."""
    home = os.path.expanduser("~")
    if home and home != "~":
        text = re.sub(re.escape(home), "%USERPROFILE%", text, flags=re.I)
    user = os.environ.get("USERNAME", "")
    if len(user) > 2:
        text = re.sub(rf"\b{re.escape(user)}\b", "%USERNAME%", text, flags=re.I)
    return text


def report_body(what: str, verdict: str, reasons: list[str]) -> dict[str, str]:
    lines = [scrub(r)[:MAX_REASON] for r in reasons[:MAX_REASONS]]
    return {"what": scrub(what)[:300], "verdict": verdict, "reasons": "\n".join(f"- {r}" for r in lines),
            "version": __version__}


def issue_url(kind: str, what: str, verdict: str, reasons: list[str]) -> str:
    """A GitHub "Wrong warning" issue, filled in. `kind` is "Site", "File" or "Finding"."""
    body = report_body(what, verdict, reasons)
    params = {"template": ISSUE_FORM, "title": f"Wrong warning: {body['what'][:80]}", "kind": kind, **body}
    return f"https://github.com/{REPO}/issues/new?{urlencode(params, quote_via=quote)}"


def email_url(kind: str, what: str, verdict: str, reasons: list[str]) -> str | None:
    if not REPORT_EMAIL:
        return None
    body = report_body(what, verdict, reasons)
    text = (f"{kind}: {body['what']}\nAtlas said: {body['verdict']}\nWhy:\n{body['reasons']}\n\n"
            f"Why I think it's wrong:\n\n\nProject Atlas {body['version']}")
    return f"mailto:{REPORT_EMAIL}?subject={quote('Wrong warning: ' + body['what'][:80])}&body={quote(text)}"


def site_subject(url_or_host: str) -> str:
    """Just the site's name from a link."""
    m = re.match(r"^[a-z][a-z0-9+.-]*://([^/?#@]*@)?([^/?#:]+)", url_or_host.strip(), re.I)
    return (m.group(2) if m else url_or_host.split("/")[0]).lower()
