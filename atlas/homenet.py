"""The home network: the router, the Wi-Fi, and every device connected to it.

Atlas only looks at your home network: one Windows calls Private, or one you said is your home (Windows 11
marks new networks Public, home ones included). Never a café's or a hotel's.
Everything here is look-only and needs no administrator rights:
- Windows' own lists: the router's address, the devices this PC has talked to, the Wi-Fi's security.
- One small packet to each address on the network once a day, so Windows learns which devices are there
  (they're never port-scanned or signed in to).
- UPnP: whether the router lets devices open doors to the internet by themselves, and which ones did.
- The router's sign-in page, only to recognise the brand and model (Atlas never signs in). A known model is
  checked against CISA's list of flaws criminals are using, which also says which models are past end of life.
- Who answers this PC's website lookups (DNS), in case the router's settings were changed.
"""

from __future__ import annotations

import gzip
import ipaddress
import json
import logging
import re
import socket
import subprocess
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from urllib.parse import urljoin

import requests

from atlas import identify
from atlas.findings import NOTE, OK, WARN, Finding
from atlas.local_checks import run_powershell_json

log = logging.getLogger(__name__)

NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
DAILY_HOURS = 24  # discovery, UPnP, the router's page and DNS: once a day
SWEEP_LIMIT = 1024  # don't wake more addresses than a /22 (homes are /24)
NEW_DAYS = 7  # a device counts as new for a week
PRIVATE = "Private address"  # the "maker" of a made-up hardware address

# How each router brand is managed. Matched against the router page's title and server, and the router's maker.
ROUTER_BRANDS = [
    (r"xfinity|comcast", "Xfinity", "the Xfinity app"),
    (r"orbi", "Netgear Orbi", "the Orbi app"),
    (r"netgear", "Netgear", "the Nighthawk app or its web page"),
    (r"tp-?link|deco", "TP-Link", "the Tether or Deco app"),
    (r"asus", "ASUS", "the ASUS Router app or its web page"),
    (r"linksys", "Linksys", "the Linksys app"),
    (r"eero", "eero", "the eero app"),
    (r"google|nest", "Google Nest Wifi", "the Google Home app"),
    (r"verizon|fios", "Verizon", "the My Fios app"),
    (r"at&t|att|pace|arris|bgw", "AT&T", "the Smart Home Manager app"),
    (r"spectrum|charter|sagemcom", "Spectrum", "the My Spectrum app"),
    (r"ubiquiti|unifi|ubnt", "Ubiquiti UniFi", "the UniFi app"),
    (r"synology", "Synology", "Synology Router Manager"),
    (r"mikrotik|routeros", "MikroTik", "WinBox or its web page"),
    (r"vantiva|technicolor", "Xfinity or another provider's gateway", "your internet provider's app"),
    (r"d-?link", "D-Link", "the D-Link app or its web page"),
    (r"tenda", "Tenda", "the Tenda WiFi app or its web page"),
    (r"zyxel", "Zyxel", "its web page"),
    (r"draytek|vigor", "DrayTek", "its web page"),
]
# Gateways the internet provider owns and updates by itself; the owner can't update them.
PROVIDER_BRANDS = {"Xfinity", "Verizon", "AT&T", "Spectrum", "Xfinity or another provider's gateway"}
# Doors devices opened to the internet that are risky: anyone online can knock on them.
RISKY_PORTS = {21: "file sharing (FTP)", 22: "remote sign-in (SSH)", 23: "remote sign-in (Telnet)",
               80: "a web page", 443: "a web page", 445: "Windows file sharing", 554: "camera video (RTSP)",
               3389: "Remote Desktop", 5900: "remote control (VNC)", 8000: "a web page", 8080: "a web page",
               8443: "a web page", 34567: "a camera recorder (DVR)", 37777: "a camera recorder (Dahua)"}
# Who usually answers website lookups (DNS). Matched against the owner of the address that asked on our behalf.
FAMILIAR_DNS = r"google|cloudflare|comcast|quad9|opendns|cisco|akamai|at&t|att-|verizon|charter|cox|centurylink|" \
               r"lumen|spectrum|frontier|adguard|nextdns|t-mobile|tmobile|level3|microsoft|apple|amazon"


@dataclass
class Network:
    gateway: str
    gateway_mac: str = ""
    alias: str = ""  # e.g. "Wi-Fi"
    index: int = 0
    ip: str = ""
    prefix: int = 24
    category: str = ""  # Windows' network type: "Private", "Public" or "DomainAuthenticated"
    name: str = ""
    mac: str = ""  # this PC's own

    @property
    def id(self) -> str:
        return (self.gateway_mac or self.gateway).upper()

    def is_home(self, confirmed: list[str] = ()) -> bool:
        return self.category in ("Private", "DomainAuthenticated") or self.id in confirmed


@dataclass
class Wifi:
    ssid: str
    auth: str
    cipher: str = ""


@dataclass
class Mapping:
    external_port: int
    protocol: str
    internal_ip: str
    internal_port: int
    description: str = ""


@dataclass
class Device:
    mac: str
    ip: str
    maker: str = ""
    name: str = ""
    first_seen: str = ""
    last_seen: str = ""
    initial: bool = False  # already there the first time Atlas looked at this network
    role: str = ""  # "Router", "This PC" or ""
    model: str = ""  # what the device says it is, e.g. "Roku 4670RW"

    @property
    def label(self) -> str:
        if self.role:
            return self.role if not self.name else f"{self.role} ({self.name})"
        if self.name:
            return self.name
        if self.maker == PRIVATE:
            return "Phone, tablet or laptop"
        return f"{self.maker} device" if self.maker else "Unknown device"


@dataclass
class HomeCheck:
    network: Network | None = None
    wifi: Wifi | None = None
    devices: list[Device] = field(default_factory=list)
    brand: tuple[str, str] | None = None  # (name, how to manage it)
    page: dict = field(default_factory=dict)  # the router page's "server" and "title"
    upnp: bool = False
    mappings: list[Mapping] = field(default_factory=list)
    resolver: str | None = None
    resolver_owner: str | None = None
    checked_at: str = ""
    findings: list[Finding] = field(default_factory=list)
    clues: dict[str, dict] = field(default_factory=dict)  # {ip: what the device said about itself}
    router_model: str = ""  # e.g. "NETGEAR R7000", when the router says
    router_holes: list[dict] = field(default_factory=list)  # CISA KEV entries for that model


# --- Device makers ----------------------------------------------------------------------------------------

@lru_cache(maxsize=1)
def _makers() -> dict[str, str]:
    path = Path(__file__).with_name("oui.txt.gz")
    try:
        with gzip.open(path, "rt", encoding="utf-8") as fh:
            return dict(line.rstrip("\n").split("\t", 1) for line in fh if line[:1] != "#" and "\t" in line)
    except OSError:
        log.warning("Device maker list missing: %s", path)
        return {}


_SUFFIXES = re.compile(r"[,.\s]+(inc|incorporated|corp|corporation|co|ltd|limited|llc|gmbh|ag|sa|bv|plc|"
                       r"technologies|technology|electronics|international|corporate|company)\.?$", re.I)


def short_maker(name: str) -> str:
    """ "Hon Hai Precision Ind. Co.,Ltd." -> "Hon Hai Precision Ind." ; "Intel Corporate" -> "Intel"."""
    name = name.strip()
    for _ in range(3):
        trimmed = _SUFFIXES.sub("", name).strip(" ,.")
        if trimmed == name or not trimmed:
            break
        name = trimmed
    return name


def normal_mac(mac: str) -> str:
    digits = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()
    return "-".join(digits[i:i + 2] for i in range(0, 12, 2)) if len(digits) == 12 else ""


def is_random_mac(mac: str) -> bool:
    """Phones and tablets use made-up ("private") addresses: the second digit is 2, 6, A or E."""
    mac = normal_mac(mac)
    return bool(mac) and mac[1] in "26AE"


def maker(mac: str) -> str:
    mac = normal_mac(mac)
    if not mac:
        return ""
    if is_random_mac(mac):
        return PRIVATE
    return short_maker(_makers().get(mac.replace("-", "")[:6], ""))


# --- Reading the network ----------------------------------------------------------------------------------

_NETWORK_PS = r"""
$r = Get-NetRoute -DestinationPrefix 0.0.0.0/0 -ErrorAction SilentlyContinue |
     Sort-Object { $_.RouteMetric + $_.InterfaceMetric } | Select-Object -First 1
if (-not $r) { '[]'; return }
$ip = Get-NetIPAddress -InterfaceIndex $r.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
      Select-Object -First 1
$p = Get-NetConnectionProfile -InterfaceIndex $r.InterfaceIndex -ErrorAction SilentlyContinue | Select-Object -First 1
$gw = Get-NetNeighbor -InterfaceIndex $r.InterfaceIndex -IPAddress $r.NextHop -ErrorAction SilentlyContinue |
      Select-Object -First 1
$nic = Get-NetAdapter -InterfaceIndex $r.InterfaceIndex -ErrorAction SilentlyContinue
[pscustomobject]@{gateway="$($r.NextHop)"; alias="$($r.InterfaceAlias)"; index=$r.InterfaceIndex;
  ip="$($ip.IPAddress)"; prefix=[int]$ip.PrefixLength; category="$($p.NetworkCategory)"; name="$($p.Name)";
  gateway_mac="$($gw.LinkLayerAddress)"; mac="$($nic.MacAddress)"} | ConvertTo-Json -Compress
"""

_NEIGHBOURS_PS = r"""
Get-NetNeighbor -InterfaceIndex ([int](Get-Content $env:ATLAS_LIST)) -AddressFamily IPv4 -ErrorAction SilentlyContinue |
  Where-Object { $_.State -in 'Reachable','Stale','Delay','Probe' } |
  ForEach-Object { [pscustomobject]@{ip="$($_.IPAddress)"; mac="$($_.LinkLayerAddress)"} } |
  ConvertTo-Json -Compress
"""


def read_network() -> Network | None:
    rows = run_powershell_json(_NETWORK_PS, timeout=60)
    if not rows or not rows[0].get("gateway") or rows[0]["gateway"] == "0.0.0.0":
        return None
    r = rows[0]
    return Network(gateway=r["gateway"], gateway_mac=normal_mac(r.get("gateway_mac") or ""),
                   alias=r.get("alias") or "", index=int(r.get("index") or 0), ip=r.get("ip") or "",
                   prefix=int(r.get("prefix") or 24), category=r.get("category") or "", name=r.get("name") or "",
                   mac=normal_mac(r.get("mac") or ""))


def read_neighbours(net: Network) -> list[tuple[str, str]]:
    """(ip, mac) of the devices Windows has recently talked to on this network."""
    rows = run_powershell_json(_NEIGHBOURS_PS, [str(net.index)], timeout=60)
    subnet = _subnet(net)
    found = []
    for r in rows:
        mac, ip = normal_mac(r.get("mac") or ""), r.get("ip") or ""
        if not mac or mac in ("00-00-00-00-00-00", "FF-FF-FF-FF-FF-FF") or mac.startswith("01-00-5E"):
            continue  # empty, broadcast and multicast entries
        try:
            if subnet and ipaddress.ip_address(ip) not in subnet:
                continue
        except ValueError:
            continue
        found.append((ip, mac))
    return found


def _subnet(net: Network) -> ipaddress.IPv4Network | None:
    try:
        return ipaddress.ip_network(f"{net.ip}/{net.prefix}", strict=False)
    except ValueError:
        return None


def wake_devices(net: Network) -> int:
    """Send one tiny packet to every address on the network (the "discard" port), so Windows asks who has each
    address and lists the devices that answer. Nothing is scanned. Returns how many addresses were knocked."""
    subnet = _subnet(net)
    if subnet is None or subnet.num_addresses > SWEEP_LIMIT + 2:
        return 0
    sent = 0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        for host in subnet.hosts():
            if str(host) == net.ip:
                continue
            try:
                s.sendto(b"", (str(host), 9))
                sent += 1
            except OSError:
                pass
    time.sleep(2)  # let the answers come in
    return sent


def read_wifi(output: str | None = None) -> Wifi | None:
    """The Wi-Fi this PC is connected to (None on a cable)."""
    if output is None:
        try:
            out = subprocess.run(["netsh", "wlan", "show", "interfaces"], capture_output=True, timeout=20,
                                 creationflags=NO_WINDOW)
            output = out.stdout.decode("utf-8", errors="replace")
        except (OSError, subprocess.TimeoutExpired):
            return None
    fields = {}
    for line in output.splitlines():
        key, sep, value = line.partition(" : ")
        if sep:
            fields.setdefault(key.strip().lower(), value.strip())
    if fields.get("state", "").lower() != "connected" or "authentication" not in fields:
        return None
    return Wifi(fields.get("ssid", ""), fields["authentication"], fields.get("cipher", ""))


def ssdp(timeout: float = 3.0) -> dict[str, list[dict]]:
    """Ask the network's UPnP devices to say hello. {ip: [{"st", "server", "location"}]}."""
    msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\n"
           "ST: ssdp:all\r\n\r\n").encode()
    seen: dict[str, list[dict]] = {}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(0.5)
            s.sendto(msg, ("239.255.255.250", 1900))
            end = time.monotonic() + timeout
            while time.monotonic() < end:
                try:
                    data, addr = s.recvfrom(8192)
                except socket.timeout:
                    continue
                headers = dict((k.strip().lower(), v.strip()) for k, _, v in
                               (line.partition(":") for line in data.decode(errors="replace").splitlines()[1:]))
                row = {"st": headers.get("st", ""), "server": headers.get("server", ""),
                       "location": headers.get("location", "")}
                if row not in seen.setdefault(addr[0], []):
                    seen[addr[0]].append(row)
    except OSError:
        log.exception("UPnP discovery failed")
    return seen


def find_gateway_service(rows: list[dict]) -> str | None:
    """The description address of the router's UPnP internet-gateway service, if it offers one."""
    for row in rows:
        if re.search(r"InternetGatewayDevice|WANIPConnection|WANPPPConnection", row["st"]) and row["location"]:
            return row["location"]
    return None


def port_mappings(location: str, limit: int = 64) -> list[Mapping]:
    """Doors devices opened through the router with UPnP (read-only: GetGenericPortMappingEntry)."""
    try:
        desc = requests.get(location, timeout=5)
        root = ET.fromstring(desc.content)
    except (requests.RequestException, ET.ParseError):
        return []
    control, service = None, None
    for el in root.iter():
        if el.tag.endswith("service"):
            kind = next((c.text for c in el if c.tag.endswith("serviceType")), "") or ""
            if "WANIPConnection" in kind or "WANPPPConnection" in kind:
                control = next((c.text for c in el if c.tag.endswith("controlURL")), None)
                service = kind
                break
    if not control:
        return []
    url = urljoin(location, control)
    found = []
    for i in range(limit):
        body = ('<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
                's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
                f'<u:GetGenericPortMappingEntry xmlns:u="{service}"><NewPortMappingIndex>{i}</NewPortMappingIndex>'
                '</u:GetGenericPortMappingEntry></s:Body></s:Envelope>')
        try:
            r = requests.post(url, data=body, timeout=5, headers={
                "Content-Type": 'text/xml; charset="utf-8"',
                "SOAPAction": f'"{service}#GetGenericPortMappingEntry"'})
        except requests.RequestException:
            break
        if r.status_code != 200:
            break  # past the last entry
        values = {el.tag.split("}")[-1]: (el.text or "") for el in ET.fromstring(r.content).iter()}
        try:
            found.append(Mapping(int(values.get("NewExternalPort") or 0), values.get("NewProtocol", ""),
                                 values.get("NewInternalClient", ""), int(values.get("NewInternalPort") or 0),
                                 values.get("NewPortMappingDescription", "")))
        except ValueError:
            continue
    return found


def router_page(ip: str) -> dict:
    """The router's sign-in page's title and server name, to recognise the brand. Never signs in."""
    import warnings

    for scheme in ("http", "https"):
        try:
            with warnings.catch_warnings():  # routers use self-made certificates; nothing secret is sent
                warnings.simplefilter("ignore")
                r = requests.get(f"{scheme}://{ip}/", timeout=4, verify=False, allow_redirects=True)
        except requests.RequestException:
            continue
        title = re.search(r"<title[^>]*>(.*?)</title>", r.text[:20000], re.I | re.S)
        realm = re.search(r'realm="([^"]*)"', r.headers.get("WWW-Authenticate", ""))  # e.g. "NETGEAR R7000"
        return {"server": r.headers.get("Server", ""), "title": re.sub(r"\s+", " ", title.group(1)).strip()[:80]
                if title else "", "realm": realm.group(1)[:80] if realm else "", "url": r.url}
    return {}


def router_brand(page: dict, router_maker: str) -> tuple[str, str] | None:
    text = f"{page.get('title', '')} {page.get('realm', '')} {page.get('server', '')} {router_maker}".lower()
    for pattern, name, manage in ROUTER_BRANDS:
        if re.search(pattern, text):
            return name, manage
    return None


def model_codes(text: str) -> set[str]:
    """Model numbers in a text: "D-Link DIR-859, Archer AX-21 v3" -> {"dir859", "ax21"}. Words with both letters
    and digits; version and speed words ("v3", "5GHz") don't count."""
    codes = set()
    for word in re.findall(r"[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*", text):
        for part in {word, *word.split("-")}:
            code = part.replace("-", "").lower()
            if (re.search(r"\d", code) and re.search(r"[a-z]", code)
                    and not re.fullmatch(r"v\d+|\d+(?:ghz|mhz|mbps|gbps|g|m)|cve\d+|\d+(?:st|nd|rd|th)", code)):
                codes.add(code)
    return codes


def router_model(page: dict, clue: dict) -> str:
    """The router's model, when it says: its UPnP or Bonjour description, else its sign-in page."""
    if clue.get("model"):
        return clue["model"]
    for text in (page.get("realm", ""), page.get("title", "")):
        if model_codes(text):
            return text
    return ""


def router_holes(model: str, vendor: str, catalog: list[dict]) -> list[dict]:
    """CISA KEV entries naming this router's model. The maker must match too, so "AC1900" from one maker
    never matches another's."""
    have = model_codes(model)
    vendor = re.sub(r"[^a-z0-9]", "", vendor.lower())
    found = []
    for e in catalog:
        maker = re.sub(r"[^a-z0-9]", "", (e.get("vendorProject") or "").lower())
        if not have or not maker or maker not in vendor:
            continue
        named = model_codes(f"{e.get('product')} {e.get('vulnerabilityName')} {e.get('shortDescription')}")
        if have & named:
            found.append(e)
    return sorted(found, key=lambda e: e.get("dateAdded") or "", reverse=True)


def resolver_ip() -> str | None:
    """The address that looks up websites on this PC's behalf, as the internet sees it."""
    try:
        return socket.gethostbyname("whoami.akamai.net")
    except OSError:
        return None


def network_owner(ip: str) -> str | None:
    """Who an internet address belongs to (RDAP, the public registry; free, no key)."""
    try:
        r = requests.get(f"https://rdap.org/ip/{ip}", timeout=8)
        data = r.json()
    except (requests.RequestException, ValueError):
        return None
    for entity in data.get("entities") or []:
        for item in (entity.get("vcardArray") or [None, []])[1]:
            if item[0] == "fn" and item[3]:
                return str(item[3])
    return data.get("name")


def device_names(ips: list[str], deadline: float = 4.0) -> dict[str, str]:
    """Names the router gives devices (reverse DNS), e.g. "Annas-iPhone"."""
    def name(ip: str) -> str:
        try:
            host = socket.gethostbyaddr(ip)[0]
        except OSError:
            return ""
        return "" if re.fullmatch(r"[\d.-]+", host.split(".")[0]) else host.split(".")[0]

    out: dict[str, str] = {}
    pool = ThreadPoolExecutor(max_workers=16)
    futures = {pool.submit(name, ip): ip for ip in ips}
    done, _ = wait(futures, timeout=deadline)
    for f in done:
        if f.result():
            out[futures[f]] = f.result()
    pool.shutdown(wait=False, cancel_futures=True)
    return out


def ssdp_name(rows: list[dict]) -> str:
    """ "Roku/16.0.4 UPnP/1.0 Roku/16.0.4" -> "Roku"."""
    for row in rows:
        for part in row["server"].split():
            product = part.split("/")[0]
            if product and product.lower() not in ("upnp", "linux", "windows", "dlnadoc", "unspecified", "os",
                                                    "portable", "sdk", "http", "miniupnpd"):
                return product
    return ""


# --- Judging ----------------------------------------------------------------------------------------------

def wifi_findings(w: Wifi | None) -> list[Finding]:
    if w is None:
        return []
    auth, where = w.auth.lower(), f"Wi-Fi \"{w.ssid}\"" if w.ssid else "Your Wi-Fi"
    key = "homenet:wifi"
    if auth == "open":
        return [Finding("Wi-Fi", f"{where} has no password", WARN,
                        ["Anyone nearby can join it and see what isn't encrypted. Set WPA2 or WPA3 with a long "
                         "password in your router's settings."], key=f"{key}:open")]
    if "wep" in auth or auth in ("wpa-personal", "wpa-enterprise", "shared") or "tkip" in w.cipher.lower():
        return [Finding("Wi-Fi", f"{where} uses old, breakable security ({w.auth}, {w.cipher})", WARN,
                        ["Its password can be cracked in minutes. Switch to WPA2 (AES) or WPA3 in your router's "
                         "settings."], key=f"{key}:weak")]
    if "wpa3" in auth:
        return [Finding("Wi-Fi", f"{where} uses WPA3, the newest Wi-Fi security", OK, key=f"{key}:ok")]
    return [Finding("Wi-Fi", f"{where} uses {w.auth}", OK,
                    ["That's fine. If your router offers WPA3 (or \"WPA2/WPA3\"), it's a little stronger."],
                    key=f"{key}:ok")]


def router_findings(check: HomeCheck) -> list[Finding]:
    net = check.network
    name, manage = check.brand or ("", "its app or web page")
    model = check.router_model
    if model and name and name.split()[0].lower() not in model.lower():
        model = f"{name} {model}"
    what = model or name
    title = f"Your router: {what} ({net.gateway})" if what else f"Your router is at {net.gateway}"
    url = check.page.get("url") or f"http://{net.gateway}/"
    provider = name in PROVIDER_BRANDS
    updates = ("- Firmware updates: your internet provider installs them by itself; you can't (and don't need "
               "to) update it." if provider else "- Automatic firmware updates are on. Atlas can't see the "
               "firmware version without signing in.")
    found = [Finding("Router", title, NOTE, [
        f"Atlas never signs in to your router, so check these in {manage}:",
        "- Its admin password isn't the one printed on the label or the default (such as \"admin\" or "
        "\"password\").",
        updates,
        "- WPS (the push-button or PIN pairing) is off.",
        "- Remote management (managing it from the internet) is off unless you use it.",
    ], key="homenet:router", fix="open", fix_label="Open the router's page", data={"url": url})]
    holes = check.router_holes
    if holes:
        from atlas.softwareupdates import KEV_LINK

        cves = ", ".join(e["cveID"] for e in holes[:3]) + (f" and {len(holes) - 3} more" if len(holes) > 3 else "")
        details = [f"CISA lists flaws in this model that criminals are using right now: {cves}."]
        if any(e.get("eol") for e in holes):
            title = f"Your router ({what}) has flaws under attack and may never be fixed"
            details.append("CISA says some affected models are past end of life: the maker no longer fixes them. "
                           "Check the maker's support page for your exact model and version; if it gets no more "
                           "updates, replace the router.")
        else:
            title = f"Your router ({what}) has flaws under attack: update its firmware"
            details.append(f"Install the latest firmware in {manage} (or the maker's support page), and turn on "
                           "automatic updates. Atlas can't see the firmware version, so this may already be done.")
        if provider:
            details.append("It's your internet provider's gateway: if it's old, ask them for a new one.")
        found.append(Finding("Router", title, WARN, details, key=f"homenet:router:kev:{holes[0]['cveID']}",
                             vt_link=KEV_LINK + holes[0]["cveID"]))
    return found


def upnp_findings(check: HomeCheck) -> list[Finding]:
    if not check.upnp:
        return [Finding("Router", "UPnP is off (devices can't open doors to the internet by themselves)", OK,
                        key="homenet:upnp:off")]
    names = {d.ip: d.label for d in check.devices}
    found = [Finding("Router", "UPnP is on: devices can open doors to the internet by themselves", NOTE,
                     ["Games consoles and video calls use it. If nobody here needs it, turning it off in the "
                      "router's settings is safer."], key="homenet:upnp:on")]
    for m in check.mappings:
        who = names.get(m.internal_ip, m.internal_ip)
        what = RISKY_PORTS.get(m.internal_port)
        detail = [f"Port {m.external_port} ({m.protocol}) on your internet address leads to {who}, port "
                  f"{m.internal_port}." + (f" It was opened by \"{m.description}\"." if m.description else "")]
        if what:
            found.append(Finding("Router", f"{who} is reachable from the internet: {what}", WARN, detail + [
                "Anyone online can try to sign in or attack it. Unless you set this up on purpose, turn off "
                "the device's remote access or UPnP."], key=f"homenet:open:{m.internal_ip}:{m.internal_port}"))
        else:
            found.append(Finding("Router", f"{who} opened port {m.external_port} to the internet", NOTE, detail,
                                 key=f"homenet:open:{m.internal_ip}:{m.internal_port}"))
    return found


def resolver_findings(check: HomeCheck, lookup=None, threshold: int = 3) -> list[Finding]:
    ip, owner = check.resolver, check.resolver_owner
    if not ip:
        return []
    who = f"{owner} ({ip})" if owner else ip
    from atlas.vt_client import gui_link

    link = gui_link("ip", ip)
    if lookup is not None:
        try:
            report = lookup("ip", ip)
        except Exception:
            report = None
        if report is not None and report.found and report.malicious >= threshold:
            return [Finding("DNS", f"Website lookups go through a flagged server: {who}", WARN, [
                f"{report.malicious} security vendors flag it. Someone may have changed your router's DNS "
                "setting to send you to fake sites. Check DNS in the router's settings, or reset it."],
                key=f"homenet:resolver:{ip}", vt_link=link)]
    if owner and re.search(FAMILIAR_DNS, owner, re.I):
        return [Finding("DNS", f"Website lookups are answered by {who}", OK, key="homenet:resolver", vt_link=link)]
    return [Finding("DNS", f"Website lookups are answered by an unfamiliar provider: {who}", NOTE, [
        "That's fine if you chose it. If not, someone may have changed your router's DNS setting: check it in the "
        "router's settings."], key=f"homenet:resolver:{ip}", vt_link=link)]


def new_device_findings(devices: list[Device], now: datetime | None = None) -> list[Finding]:
    now = now or datetime.now()
    found = []
    for d in devices:
        if d.initial or d.role or not d.first_seen:
            continue
        try:
            age = now - datetime.fromisoformat(d.first_seen)
        except ValueError:
            continue
        if age.days < NEW_DAYS:
            found.append(Finding("Home network", f"New on your network: {d.label} ({d.ip})", NOTE, [
                f"First seen {datetime.fromisoformat(d.first_seen):%a %d %b %H:%M}. Maker: {d.maker or 'unknown'}. "
                "If nobody in the house knows it, change the Wi-Fi password."], key=f"homenet:new:{d.mac}"))
    return found


# --- Putting it together ----------------------------------------------------------------------------------

def check_home(store, lookup=None, threshold: int = 3, force: bool = False,
               homes: list[str] | None = None) -> HomeCheck:
    """Look at the home network. The heavier parts run once a day (or when `force`). `homes`: the networks
    the user said are home (default: from the settings)."""
    check = HomeCheck(checked_at=datetime.now().isoformat(timespec="seconds"))
    net = check.network = read_network()
    if net is None:
        return check
    if homes is None:
        from atlas import config

        homes = config.Settings.load().home_networks
    if not net.is_home(homes):
        check.findings = [Finding("Home network", f"Is \"{net.name or net.alias}\" your home network?", NOTE,
                                  ["Atlas only looks at your home network, never other people's (a café's or a "
                                   "hotel's). If this is home, open the Atlas window > Protection > Home network "
                                   "and click This is my home network."], key="homenet:ask")]
        return check
    daily = None if force or store is None else store.cached_extra("homenet", net.id, DAILY_HOURS)
    if daily is None:
        wake_devices(net)
        hello = ssdp()
        gateway_service = find_gateway_service(hello.get(net.gateway, []))
        resolver = resolver_ip()
        neighbours = read_neighbours(net)
        ips = [ip for ip, _ in neighbours]
        locations = {ip: rows[0]["location"] for ip, rows in hello.items() if rows and rows[0]["location"]}
        if gateway_service:
            locations[net.gateway] = gateway_service  # names the router's model
        clues = identify.merge(identify.ask_bonjour(net.ip), identify.read_upnp_descriptions(locations),
                               identify.ask_pc_names(ips))
        daily = {"page": router_page(net.gateway), "upnp": gateway_service is not None,
                 "mappings": [m.__dict__ for m in port_mappings(gateway_service)] if gateway_service else [],
                 "resolver": resolver, "resolver_owner": network_owner(resolver) if resolver else None,
                 "names": device_names(ips),
                 "ssdp": {ip: ssdp_name(rows) for ip, rows in hello.items() if ssdp_name(rows)},
                 "clues": clues}
        if store is not None:
            store.cache_extra("homenet", net.id, daily)
    else:
        neighbours = read_neighbours(net)
    check.page, check.upnp = daily["page"], daily["upnp"]
    check.mappings = [Mapping(**m) for m in daily["mappings"]]
    check.resolver, check.resolver_owner = daily["resolver"], daily["resolver_owner"]
    check.brand = router_brand(check.page, maker(net.gateway_mac))
    found = {mac: ip for ip, mac in neighbours}
    found.setdefault(net.mac, net.ip)
    check.clues = daily.get("clues", {})  # answers cached by 0.14.0 lack them
    check.router_model = router_model(check.page, check.clues.get(net.gateway) or {})
    if check.router_model:  # the catalog is shared with Windows updates' daily download
        from atlas.softwareupdates import kev_catalog

        vendor = f"{check.brand[0] if check.brand else ''} {maker(net.gateway_mac)} {check.router_model}"
        check.router_holes = router_holes(check.router_model, vendor, kev_catalog(store, years=None))

    def clue(ip: str, key: str) -> str:
        return (check.clues.get(ip) or {}).get(key) or ""

    devices = [Device(mac, ip, maker(mac), clue(ip, "name") or daily["names"].get(ip) or daily["ssdp"].get(ip, ""),
                      model=clue(ip, "model")) for mac, ip in found.items() if mac]
    for d in devices:
        d.role = "Router" if d.mac == net.gateway_mac else "This PC" if d.mac == net.mac else ""
        if d.role == "This PC":
            d.name = d.name or socket.gethostname()
    if store is not None:
        devices = store.record_home_devices(net.id, devices)
    check.devices = sorted(devices, key=lambda d: (d.role != "Router", d.role != "This PC",
                                                   ipaddress.ip_address(d.ip)))
    check.wifi = read_wifi() if "wi" in net.alias.lower() or "wlan" in net.alias.lower() else None
    check.findings = (wifi_findings(check.wifi) + router_findings(check) + upnp_findings(check)
                      + resolver_findings(check, lookup, threshold) + new_device_findings(check.devices))
    return check


def home_findings(store, lookup=None, threshold: int = 3) -> list[Finding]:
    """For the Protection checks (hourly in the tray)."""
    return check_home(store, lookup, threshold).findings


def summary(check: HomeCheck) -> str:
    net = check.network
    if net is None:
        return "Not connected to a network."
    if check.findings and check.findings[0].key == "homenet:ask":
        return check.findings[0].title
    router = check.router_model or (check.brand[0] if check.brand else "Router")
    look = sum(1 for f in check.findings if f.level == WARN)
    return (f"{router} at {net.gateway}  ·  {len(check.devices)} device(s) seen  ·  "
            + (f"{look} need a look" if look else "nothing needs a look")
            + f"  ·  checked {check.checked_at[11:16]}")


def as_json(check: HomeCheck) -> str:
    """For `atlas home --json`."""
    return json.dumps({"network": check.network.__dict__ if check.network else None,
                       "router": {"brand": check.brand[0] if check.brand else None, "model": check.router_model,
                                  "exploited_flaws": [e["cveID"] for e in check.router_holes]},
                       "devices": [d.__dict__ | {"label": d.label} for d in check.devices],
                       "findings": [f.__dict__ for f in check.findings]}, indent=2, default=str)
