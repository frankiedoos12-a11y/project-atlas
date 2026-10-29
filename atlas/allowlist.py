"""Sites the link checks trust: your own list, and Project Atlas's shared allow-list.

Atlas's own guesses about a site (a brand name on someone else's domain, look-alike letters, a bare IP
address, a brand-new domain) are sometimes wrong. A site you trust (`trusted_sites` in the settings, added
with "Always trust this site") or one on the shared allow-list skips those guesses. VirusTotal's engines and
security vendors are still asked, so a trusted site that turns malicious is still flagged.

The shared allow-list is `allowlist.json` in the GitHub repository: when a reported mistake turns out to be
one, the site goes there and every copy of Atlas picks it up within a day, without a new release. Turn it off
with `shared_allowlist`.
"""

from __future__ import annotations

import logging
import re

import requests

from atlas import config
from atlas.sites import is_ip, registered_domain
from atlas.updates import BRANCH, REPO

log = logging.getLogger(__name__)

SHARED_URL = "https://raw.githubusercontent.com/{repo}/{branch}/allowlist.json"
FRESH_HOURS, STALE_HOURS = 24, 24 * 30
SUFFIX_ONLY = re.compile(r"^(co|com|org|net|ac|gov)\.[a-z]{2}$")
DOMAIN = re.compile(r"^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def site_of(host: str) -> str:
    """What trusting a page trusts: its whole registered domain (outlook.live.com -> live.com)."""
    return registered_domain(host.lower().strip().rstrip("."))


def valid_site(site: str) -> bool:
    """A whole registered domain: not a subdomain, an IP address or a bare suffix like co.uk."""
    return bool(DOMAIN.match(site)) and site_of(site) == site and not SUFFIX_ONLY.match(site)


def trust_site(host: str) -> str:
    """Add the host's domain to your trusted sites. Reads and saves the settings file now, so the browser
    helper and the window see the same list."""
    site = site_of(host)
    if is_ip(host.strip()) or not valid_site(site):
        raise ValueError(f"{host!r} isn't a web site Atlas can trust")
    settings = config.Settings.load()
    if site not in settings.trusted_sites:
        settings.trusted_sites.append(site)
        settings.save()
    return site


def untrust_site(site: str) -> None:
    settings = config.Settings.load()
    settings.trusted_sites = [s for s in settings.trusted_sites if s != site]
    settings.save()


def _clean(data) -> dict[str, str]:
    """Only well-formed domains from the downloaded file: site -> who it belongs to."""
    sites = data.get("sites", {}) if isinstance(data, dict) else {}
    if not isinstance(sites, dict):
        return {}
    return {str(s).lower(): str(why)[:120] for s, why in sites.items() if valid_site(str(s).lower())}


def shared_sites(store=None) -> dict[str, str]:
    """The shared allow-list, downloaded at most once a day (the last good copy is used when offline)."""
    if store is not None:
        cached = store.cached_extra("allowlist", "sites", FRESH_HOURS)
        if cached is not None:
            return cached
    try:
        resp = requests.get(SHARED_URL.format(repo=REPO, branch=BRANCH), timeout=5)
        resp.raise_for_status()
        sites = _clean(resp.json())
    except (requests.RequestException, ValueError):
        log.warning("Couldn't download the shared allow-list")
        sites = (store.cached_extra("allowlist", "sites", STALE_HOURS) or {}) if store is not None else {}
    if store is not None:
        store.cache_extra("allowlist", "sites", sites)  # also when offline, so it waits a day to try again
    return sites


def why_trusted(host: str, mine: list[str], shared: dict[str, str]) -> str | None:
    """Why a host is trusted, or None."""
    site = site_of(host)
    if site in mine:
        return f"You trust {site}"
    if site in shared:
        return f"{site} is on Project Atlas's allow-list ({shared[site]})"
    return None
