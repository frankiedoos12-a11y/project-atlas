"""What a website's record says besides detections: how old it is, and how security vendors file it.

Download scams, fake installers and the pages malicious ads lead to mostly live on domains
registered days or weeks earlier, and are thrown away once they get flagged. So a very young
domain is a warning sign on its own, even when no engine has caught up with it yet.
Big, genuinely popular sites are exempt: a new product launch can be both new and fine.
"""

from __future__ import annotations

import ipaddress
import re
import time
from collections.abc import Callable

from atlas.vt_client import Report

NEW_SITE_DAYS = 30  # younger than this: warn
YOUNG_SITE_DAYS = 180  # younger than this: mention it
POPULAR_RANK = 100_000  # in the top 100,000 of a current popularity list: not a throwaway site

# Vendors' own words vary ("Phishing and Other Frauds", "malicious web sites", "spyware and adware").
DANGEROUS = re.compile(r"phish|malware|malicious|spyware|scam|fraud|compromised|botnet|command and control|"
                       r"ransom|infection|exploit|cryptojack", re.I)
SHADY = re.compile(r"adware|potentially unwanted|\bpua\b|\bpup\b|suspicious|\bspam|deceptive|elevated exposure", re.I)
MENTION = re.compile(r"parked|newly registered|newly observed|dynamic dns", re.I)

Lookup = Callable[[str, str], Report]


def registered_domain(host: str) -> str:
    """Rough "example.co.uk" / "example.com" from a host name."""
    labels = host.lower().rstrip(".").split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in {"co", "com", "org", "net", "ac", "gov"}:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def age_text(days: float) -> str:
    if days < 1:
        return "today"
    if days < 2:
        return "yesterday"
    if days < 14:
        return f"{int(days)} days ago"
    if days < 60:
        return f"{int(days // 7)} weeks ago"
    if days < 730:
        return f"{int(days // 30)} months ago"
    return f"{int(days // 365)} years ago"


def _join(items: list[str]) -> str:
    quoted = [f'"{c}"' for c in items[:3]]
    return quoted[0] if len(quoted) == 1 else ", ".join(quoted[:-1]) + " and " + quoted[-1]


def site_warnings(lookup: Lookup, host: str, report: Report | None = None,
                  now: float | None = None) -> list[tuple[bool, str]]:
    """(is_warning, text) pairs about a site's age and vendor categories.

    `report` is the host's domain report if the caller already has it. Registration dates
    belong to the registered domain, so "download.example.com" is aged by "example.com".
    """
    host = host.lower().rstrip(".")
    if not host or "." not in host or is_ip(host):
        return []
    reports = [report or lookup("domain", host)]
    registered = registered_domain(host)
    if registered != host and reports[0].created is None:
        reports.append(lookup("domain", registered))

    found: list[tuple[bool, str]] = []
    categories = list(dict.fromkeys(c for r in reports for c in r.categories))
    bad = [c for c in categories if DANGEROUS.search(c)]
    shady = [c for c in categories if SHADY.search(c) and c not in bad]
    if bad:
        found.append((True, f"Security vendors list {host} as {_join(bad)}"))
    elif shady:
        found.append((True, f"Security vendors list {host} as {_join(shady)}"))
    mention = [c for c in categories if MENTION.search(c) and c not in bad and c not in shady]
    if mention:
        found.append((False, f"Security vendors list {host} as {_join(mention)}"))

    created = next((r.created for r in reports if r.created), None)
    ranks = [r.popularity for r in reports if r.popularity]
    popular = bool(ranks) and min(ranks) <= POPULAR_RANK
    if created:
        days = ((now or time.time()) - created) / 86400
        if days < NEW_SITE_DAYS and not popular:
            found.append((True, f"{registered} was registered {age_text(days)}. Scam and fake-download sites "
                                "are usually only days or weeks old"))
        elif days < YOUNG_SITE_DAYS:
            found.append((False, f"{registered} is fairly new: registered {age_text(days)}"))
    return found
