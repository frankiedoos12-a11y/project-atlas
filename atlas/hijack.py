"""Hijack check: the settings adware and scams change to steer your browsing.

- Browser start pages and search engine, including ones forced by a "policy"
  (adware's favourite trick: a policy greys the setting out so you can't change it back)
- Proxy settings, which can route all your web traffic through someone else
- The hosts file, which can quietly redirect a site, or block security updates
- DNS servers, which decide where every web address actually leads

Reading is always safe. The only things Atlas changes itself (after asking, with a backup)
are your own proxy setting and per-user browser policies. Everything else needs an
administrator, so Atlas opens the right place instead.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from atlas.browsers import _read_json, chromium_profiles, firefox_profiles
from atlas.findings import NOTE, OK, WARN, Finding
from atlas.local_checks import run_powershell_json
from atlas.sites import registered_domain, site_warnings
from atlas.vt_client import Report

log = logging.getLogger(__name__)

NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
INTERNET_SETTINGS = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
HOSTS = Path(r"C:\Windows\System32\drivers\etc\hosts")

# Search engines people choose on purpose (registered domains).
KNOWN_SEARCH = {"google.com", "bing.com", "duckduckgo.com", "yahoo.com", "ecosia.org", "brave.com", "startpage.com",
                "kagi.com", "qwant.com", "yandex.com", "yandex.ru", "baidu.com", "you.com", "perplexity.ai",
                "mojeek.com", "naver.com", "seznam.cz", "ask.com", "aol.com"}
# Long-known browser hijackers and search redirectors.
HIJACKERS = {"genieo.com", "conduit.com", "babylon.com", "mywebsearch.com", "delta-search.com", "sweetim.com",
             "snap.do", "trovi.com", "search-results.com", "searchqu.com", "iminent.com", "qvo6.com", "v9.com",
             "nationzoom.com", "mystartsearch.com", "istartsurf.com", "webssearches.com", "search.ask.com",
             "searchbaron.com", "chromesearch.win", "search-me.com", "hohosearch.com", "mysearch.com",
             "searchmine.net", "safesearch.net", "yessearches.com", "omniboxes.com", "mixidj.com",
             "onelaunch.com", "wavebrowser.co", "shiftbrowser.com", "searchmarquis.com", "search.yahoo.com.ar"}
# Resolvers people pick on purpose. Anything else is looked up on VirusTotal.
KNOWN_DNS = {
    "8.8.8.8": "Google Public DNS", "8.8.4.4": "Google Public DNS", "2001:4860:4860::8888": "Google Public DNS",
    "2001:4860:4860::8844": "Google Public DNS", "1.1.1.1": "Cloudflare", "1.0.0.1": "Cloudflare",
    "2606:4700:4700::1111": "Cloudflare", "2606:4700:4700::1001": "Cloudflare", "1.1.1.2": "Cloudflare for Families",
    "1.0.0.2": "Cloudflare for Families", "1.1.1.3": "Cloudflare for Families", "1.0.0.3": "Cloudflare for Families",
    "9.9.9.9": "Quad9", "149.112.112.112": "Quad9", "2620:fe::fe": "Quad9", "2620:fe::9": "Quad9",
    "208.67.222.222": "Cisco OpenDNS", "208.67.220.220": "Cisco OpenDNS", "208.67.222.123": "OpenDNS FamilyShield",
    "208.67.220.123": "OpenDNS FamilyShield", "94.140.14.14": "AdGuard DNS", "94.140.15.15": "AdGuard DNS",
    "75.75.75.75": "Comcast Xfinity", "75.75.76.76": "Comcast Xfinity", "2001:558:feed::1": "Comcast Xfinity",
    "2001:558:feed::2": "Comcast Xfinity",
}
# Windows' placeholder "site-local" DNS addresses on adapters with no DNS of their own.
DNS_PLACEHOLDERS = {"fec0:0:0:ffff::1", "fec0:0:0:ffff::2", "fec0:0:0:ffff::3"}
# Hosts-file entries for these mean someone is blocking or faking security and update sites.
SECURITY_SITES = re.compile(r"virustotal|microsoft|windowsupdate|windows\.com|defender|msftncsi|malwarebytes|"
                            r"kaspersky|avast|avg\.com|eset|norton|symantec|mcafee|bitdefender|sophos|trendmicro|"
                            r"f-secure|webroot|emsisoft|hitmanpro|google\.com|gstatic", re.I)

POLICY_BROWSERS = {"Chrome": r"Software\Policies\Google\Chrome", "Edge": r"Software\Policies\Microsoft\Edge",
                   "Brave": r"Software\Policies\BraveSoftware\Brave"}
POLICY_VALUES = {"HomepageLocation": "home page", "NewTabPageLocation": "new tab page",
                 "DefaultSearchProviderSearchURL": "search engine", "ProxyServer": "proxy server",
                 "ProxyPacUrl": "proxy script", "ProxyMode": "proxy mode"}

Lookup = Callable[[str, str], Report]


def _host(url: str) -> str:
    if "://" not in url:
        url = "http://" + url
    return (urlparse(url).hostname or "").lower()


def _is_private(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host.split("%")[0])
        return not ip.is_global
    except ValueError:
        return host in ("localhost", "") or "." not in host


def judge_url(url: str, what: str, lookup: Lookup | None, threshold: int) -> tuple[str, list[str], str | None]:
    """(level, reasons, VirusTotal link) for a start page or search engine address."""
    host = _host(url.replace("{google:baseURL}", "https://www.google.com/"))
    if not host:
        return NOTE, [], None
    registered = registered_domain(host)
    if registered in HIJACKERS or host in HIJACKERS or any(host.endswith("." + h) for h in HIJACKERS):
        return WARN, [f"{registered} is a known browser hijacker: adware sets it so your searches and start page go "
                      "through it, usually to show ads or track you"], None
    if registered in KNOWN_SEARCH:
        partner = parse_qs(urlparse(url).query).get("hspart") or parse_qs(urlparse(url).query).get("partner")
        if partner:
            return WARN, [f"Searches go to {registered}, but through a \"partner\" code ({partner[0]}). That's how "
                          "search hijackers earn money from your searches"], None
        return OK, [], None
    if _is_private(host):
        return NOTE, [f"{host} is on this PC or your home network"], None
    if lookup is None:
        level = WARN if what == "search engine" else NOTE
        return level, ([f"{host} isn't a search engine people usually choose"] if what == "search engine" else []), None
    level, reasons = (WARN if what == "search engine" else NOTE), []
    if what == "search engine":
        reasons.append(f"{host} isn't a search engine people usually choose. If you didn't pick it, adware did")
    report = lookup("domain", host)
    if report.found and report.malicious >= threshold:
        level = WARN
        reasons.append(f"VirusTotal flags {host}: {report.malicious} of {report.total} engines")
    for warn, text in site_warnings(lookup, host, report):
        reasons.append(text)
        level = WARN if warn else level
    return level, reasons, report.gui_link if report.found else None


# --- Browsers -----------------------------------------------------------------

def _chromium_settings(profile) -> list[tuple[str, str]]:
    """(what, url) pairs: start pages and the search engine, from both settings files."""
    found = []
    for name in ("Preferences", "Secure Preferences"):
        prefs = _read_json(profile.path / name)
        session = prefs.get("session") or {}
        if session.get("restore_on_startup") == 4:
            found += [("start page", u) for u in session.get("startup_urls") or [] if isinstance(u, str)]
        if prefs.get("homepage") and not prefs.get("homepage_is_newtabpage", True):
            found.append(("home page", prefs["homepage"]))
        search = ((prefs.get("default_search_provider_data") or {}).get("template_url_data") or {}).get("url")
        if search:
            found.append(("search engine", search))
    return list(dict.fromkeys(found))


def _firefox_settings(profile) -> list[tuple[str, str]]:
    try:
        text = (profile.path / "prefs.js").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    m = re.search(r'user_pref\("browser\.startup\.homepage",\s*"([^"]*)"\);', text)
    if not m or m.group(1).startswith(("about:", "chrome:", "moz-extension:")):
        return []
    return [("start page", u) for u in m.group(1).split("|") if u]


def browser_findings(lookup: Lookup | None, threshold: int = 3) -> list[Finding]:
    found = []
    profiles = [(p, _chromium_settings(p)) for p in chromium_profiles()] + \
               [(p, _firefox_settings(p)) for p in firefox_profiles()]
    for profile, settings in profiles:
        for what, url in settings:
            level, reasons, link = judge_url(url, what, lookup, threshold)
            if level == OK:
                continue
            shown = url.replace("{google:baseURL}", "https://www.google.com/").split("{searchTerms}")[0]
            found.append(Finding(
                profile.label, f"{what.capitalize()}: {shown[:90]}", level,
                reasons or [f"Opens when {profile.browser} starts" if what == "start page" else f"Set as the {what}"],
                key=f"browser:{profile.label}:{what}:{_host(url)}", vt_link=link,
                fix="browser-settings" if profile.browser != "Firefox" else None,
                fix_label=f"Open {profile.browser}'s settings" if profile.browser != "Firefox" else None,
                data={"browser": profile.browser, "exe": profile.exe, "profile": profile.name,
                      "page": "search" if what == "search engine" else "onStartup"}))
    return found


def policy_findings(lookup: Lookup | None, threshold: int = 3, reader=None) -> list[Finding]:
    """Browser settings forced by policy. Home PCs normally have none."""
    reader = reader or _read_policies
    found = []
    for hive, browser, name, value in reader():
        what = POLICY_VALUES.get(name, name)
        level, reasons, link = WARN, [], None
        if isinstance(value, str) and "://" in value or name in ("HomepageLocation", "NewTabPageLocation",
                                                                 "DefaultSearchProviderSearchURL"):
            _, reasons, link = judge_url(str(value), "search engine" if "Search" in name else "start page",
                                         lookup, threshold)
        reasons.insert(0, f"{browser}'s {what} is locked by a policy in {'your account' if hive == 'HKCU' else 'Windows'}"
                          ". Home PCs normally have none; adware uses policies so you can't change the setting back")
        per_user = hive == "HKCU"
        found.append(Finding(f"{browser} policy", f"{what.capitalize()} forced to {str(value)[:80]}", level, reasons,
                             key=f"policy:{hive}:{browser}:{name}:{value}", vt_link=link,
                             fix="remove-policy" if per_user else None,
                             fix_label="Remove this policy..." if per_user else None,
                             data={"key": POLICY_BROWSERS[browser], "name": name, "value": value}))
    return found


def _read_policies() -> list[tuple[str, str, str, object]]:
    if sys.platform != "win32":
        return []
    import winreg

    rows = []
    for hive_name, hive in (("HKCU", winreg.HKEY_CURRENT_USER), ("HKLM", winreg.HKEY_LOCAL_MACHINE)):
        for browser, path in POLICY_BROWSERS.items():
            try:
                with winreg.OpenKey(hive, path) as key:
                    for i in range(winreg.QueryInfoKey(key)[1]):
                        name, value, _ = winreg.EnumValue(key, i)
                        if name in POLICY_VALUES:
                            rows.append((hive_name, browser, name, value))
            except OSError:
                continue
    return rows


# --- Proxy ----------------------------------------------------------------------

def _read_proxy() -> dict:
    if sys.platform != "win32":
        return {}
    import winreg

    values = {}
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS) as key:
            for name in ("ProxyEnable", "ProxyServer", "AutoConfigURL"):
                try:
                    values[name] = winreg.QueryValueEx(key, name)[0]
                except OSError:
                    pass
    except OSError:
        pass
    try:
        out = subprocess.run(["netsh", "winhttp", "show", "proxy"], capture_output=True, timeout=30,
                             creationflags=NO_WINDOW)
        text = out.stdout.decode("utf-8", errors="replace")
        m = re.search(r"Proxy Server\(s\)\s*:\s*(\S+)", text)
        if m:
            values["WinHttp"] = m.group(1)
    except (OSError, subprocess.TimeoutExpired):
        pass
    return values


def proxy_findings(lookup: Lookup | None, threshold: int = 3, values: dict | None = None) -> list[Finding]:
    values = _read_proxy() if values is None else values
    found = []
    server, pac = values.get("ProxyServer") or "", values.get("AutoConfigURL") or ""
    if values.get("ProxyEnable") and server:
        host = _host(server.split(";")[0].split("=")[-1])
        local = _is_private(host)
        reasons = ["Your web traffic goes through this server first. " +
                   ("It's on this PC, so it's probably a VPN, antivirus web shield or debugging tool; make sure you "
                    "know which program set it" if local else
                    "Unless your work or school set this up, adware or malware probably did")]
        found.append(Finding("Proxy", f"A proxy server is set: {server}", WARN, reasons + _host_reasons(lookup, host),
                             key=f"proxy:server:{server}", fix="proxy-off", fix_label="Turn the proxy off...",
                             data=dict(values)))
    if pac:
        host = _host(pac)
        found.append(Finding("Proxy", f"A proxy script is set: {pac}", WARN,
                             ["A proxy script decides, site by site, where your web traffic goes. Adware uses these "
                              "to inject ads or watch your browsing"] + _host_reasons(lookup, host),
                             key=f"proxy:pac:{pac}", fix="proxy-off", fix_label="Turn the proxy off...",
                             data=dict(values)))
    if values.get("WinHttp"):
        found.append(Finding("Proxy", f"A system-wide (WinHTTP) proxy is set: {values['WinHttp']}", WARN,
                             ["Windows services and updates go through it. Removing it needs an administrator: "
                              "netsh winhttp reset proxy"], key=f"proxy:winhttp:{values['WinHttp']}"))
    if not found:
        found.append(Finding("Proxy", "No proxy: your web traffic goes straight out", OK, key="proxy:none"))
    return found


def _host_reasons(lookup: Lookup | None, host: str) -> list[str]:
    if lookup is None or not host or _is_private(host):
        return []
    try:
        kind = "ip" if re.fullmatch(r"[\d.]+|[0-9a-f:]+", host) else "domain"
        report = lookup(kind, host)
    except Exception:
        return []
    if report.found and report.malicious:
        return [f"VirusTotal flags {host}: {report.malicious} of {report.total} engines"]
    return []


# --- Hosts file ----------------------------------------------------------------------

def hosts_entries(text: str) -> list[tuple[str, str]]:
    entries = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        parts = line.split()
        if len(parts) >= 2:
            entries += [(parts[0], name.lower()) for name in parts[1:]]
    return entries


def hosts_findings(text: str | None = None) -> list[Finding]:
    if text is None:
        try:
            text = HOSTS.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return [Finding("Hosts file", "Couldn't read the hosts file", NOTE, [str(exc)], key="hosts:unreadable")]
    entries = [(ip, name) for ip, name in hosts_entries(text)
               if name not in ("localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback", "broadcasthost")]
    fix = {"fix": "edit-hosts", "fix_label": "Open the hosts file (administrator)..."}
    blocked = [(ip, n) for ip, n in entries if ip in ("0.0.0.0", "127.0.0.1", "::1", "::")]
    redirected = [(ip, n) for ip, n in entries if (ip, n) not in blocked and not _is_private(ip)]
    found = []
    security = [n for _, n in blocked if SECURITY_SITES.search(n)]
    if security:
        found.append(Finding("Hosts file", f"Blocks security or update sites: {', '.join(security[:4])}", WARN,
                             ["Malware does this so your antivirus can't update and you can't reach help. "
                              "Remove those lines (editing needs an administrator)."],
                             key="hosts:security:" + ",".join(sorted(security)), **fix))
    for ip, name in redirected:
        found.append(Finding("Hosts file", f"Sends {name} to {ip}", WARN,
                             [f"Every time this PC visits {name} it goes to {ip} instead of the real site. That's how "
                              "fake banking and login pages get shown. Remove the line unless you added it"],
                             key=f"hosts:redirect:{name}:{ip}", **fix))
    others = len(blocked) - len(security)
    if others:
        found.append(Finding("Hosts file", f"Blocks {others} site(s)", NOTE,
                             ["Usually an ad- or tracker-blocking list you or a privacy tool added."],
                             key="hosts:blocklist"))
    redirected_private = [(ip, n) for ip, n in entries if (ip, n) not in blocked and (ip, n) not in redirected]
    if redirected_private:
        found.append(Finding("Hosts file", f"{len(redirected_private)} name(s) point at your home network",
                             NOTE, [", ".join(n for _, n in redirected_private[:5])], key="hosts:private"))
    if not found:
        found.append(Finding("Hosts file", "Hosts file is clean", OK, key="hosts:clean"))
    return found


# --- DNS ---------------------------------------------------------------------------

_DNS_SCRIPT = ("ConvertTo-Json -Compress -InputObject @(Get-DnsClientServerAddress -ErrorAction SilentlyContinue |"
               " Where-Object { $_.ServerAddresses } | ForEach-Object { [pscustomobject]@{adapter=$_.InterfaceAlias;"
               " servers=@($_.ServerAddresses)} })")


def dns_findings(lookup: Lookup | None, threshold: int = 3, rows: list[dict] | None = None) -> list[Finding]:
    if rows is None:
        try:
            rows = run_powershell_json(_DNS_SCRIPT, timeout=60)
        except Exception:
            log.exception("Couldn't read DNS servers")
            rows = []
    servers: dict[str, list[str]] = {}
    for row in rows:
        for server in row.get("servers") or []:
            if server.lower() not in DNS_PLACEHOLDERS:
                servers.setdefault(server.lower(), []).append(row.get("adapter", "?"))
    found = []
    for server, adapters in servers.items():
        on = ", ".join(dict.fromkeys(adapters))
        if _is_private(server):
            found.append(Finding("DNS", f"{on}: your router or local network ({server})", OK, key=f"dns:{server}"))
        elif server in KNOWN_DNS:
            found.append(Finding("DNS", f"{on}: {KNOWN_DNS[server]} ({server})", OK, key=f"dns:{server}"))
        else:
            report = None
            try:
                report = lookup("ip", server) if lookup else None
            except Exception:
                pass
            owner = f" ({report.owner})" if report and report.owner else ""
            if report and report.found and report.malicious >= threshold:
                found.append(Finding("DNS", f"{on}: {server}{owner} is flagged by VirusTotal", WARN,
                                     [f"{report.malicious} of {report.total} engines. A bad DNS server can send you "
                                      "to fake versions of any site. Change it in Settings > Network & internet"],
                                     key=f"dns:{server}", vt_link=report.gui_link, fix="open",
                                     fix_label="Open network settings", data={"url": "ms-settings:network"}))
            else:
                found.append(Finding("DNS", f"{on}: {server}{owner}", NOTE,
                                     ["Not one of the well-known public DNS services. Usually your internet "
                                      "provider's; worth a look if you don't recognise the owner"],
                                     key=f"dns:{server}", vt_link=report.gui_link if report and report.found else None))
    return found


def check_hijacks(lookup: Lookup | None, threshold: int = 3) -> list[Finding]:
    found = []
    for part in (browser_findings, policy_findings, proxy_findings, dns_findings):
        try:
            found += part(lookup, threshold)
        except Exception as exc:  # one broken check mustn't hide the others
            log.exception("Hijack check %s failed", part.__name__)
            found.append(Finding("Atlas", f"A check failed: {part.__name__}", NOTE, [str(exc)]))
    return found + hosts_findings()
