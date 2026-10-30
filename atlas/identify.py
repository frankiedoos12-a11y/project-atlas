"""What is that device? Clues the devices on the home network give out about themselves.

Protect, not disturb: nothing here floods or scans. Once a day Atlas listens to what devices announce:
- Bonjour (mDNS): Apple devices, Chromecasts, printers, speakers and smart-home gear say their name and model.
- UPnP: TVs, consoles and media boxes publish a description with their friendly name, maker and model.
- Windows PCs answer one standard name request (NetBIOS).
Only when you click "Identify this device" does Atlas knock on about 20 well-known ports of that one device
(a normal connection attempt each, closed straight away), and read its web page's title if it has one.
"""

from __future__ import annotations

import logging
import os
import re
import socket
import struct
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

import requests

log = logging.getLogger(__name__)

MDNS = ("224.0.0.251", 5353)
# Bonjour services worth asking about, and what offering one says about a device.
MDNS_SERVICES = {
    "_googlecast._tcp.local": "Google Cast device (Chromecast, Google TV or speaker)",
    "_airplay._tcp.local": "AirPlay device (Apple TV, Mac or smart TV)",
    "_raop._tcp.local": "AirPlay speaker",
    "_companion-link._tcp.local": "Apple device (iPhone, iPad, Mac or Apple TV)",
    "_device-info._tcp.local": "",
    "_ipp._tcp.local": "Printer",
    "_ipps._tcp.local": "Printer",
    "_printer._tcp.local": "Printer",
    "_pdl-datastream._tcp.local": "Printer",
    "_scanner._tcp.local": "Scanner",
    "_hap._tcp.local": "HomeKit smart-home device",
    "_matter._tcp.local": "Matter smart-home device",
    "_sonos._tcp.local": "Sonos speaker",
    "_spotify-connect._tcp.local": "Speaker or TV (Spotify Connect)",
    "_amzn-wplay._tcp.local": "Amazon Fire TV or Echo",
    "_hue._tcp.local": "Philips Hue bridge",
    "_smb._tcp.local": "Computer or storage with shared folders",
    "_afpovertcp._tcp.local": "Mac or storage with shared folders",
    "_ssh._tcp.local": "Computer that accepts remote sign-in (SSH)",
    "_workstation._tcp.local": "Computer",
    "_http._tcp.local": "",
}
MODEL_KEYS = ("md", "model", "am", "ty", "product", "rpmd", "mdl", "usb_mdl")
NAME_KEYS = ("fn", "n", "name")

# "Identify this device": well-known ports, and what an open one suggests.
PORT_HINTS = {
    22: "remote sign-in (SSH): a computer, storage box or router",
    23: "old remote sign-in (Telnet): often a cheap camera or router",
    53: "answers DNS: a router, mesh point or ad blocker",
    80: "a web page",
    443: "a secure web page",
    445: "Windows file sharing: a PC or storage box",
    548: "Apple file sharing: a Mac or storage box",
    554: "camera video (RTSP): a camera or video recorder",
    631: "printing (IPP): a printer",
    1883: "smart-home messages (MQTT): a hub",
    3074: "Xbox online play",
    3389: "Remote Desktop: a Windows PC",
    5000: "a web page (often Synology storage)",
    5900: "remote control (VNC)",
    7000: "AirPlay: an Apple TV or AirPlay speaker",
    8008: "Google Cast: a Chromecast, Google TV or speaker",
    8009: "Google Cast: a Chromecast, Google TV or speaker",
    8060: "Roku remote control",
    8080: "a web page",
    9100: "printing: a printer",
    9295: "PlayStation Remote Play",
    62078: "Apple sync: an iPhone or iPad",
}


@dataclass
class Clues:
    """Everything a device said about itself."""
    name: str = ""
    model: str = ""
    kinds: list[str] = field(default_factory=list)  # e.g. "Printer"
    source: list[str] = field(default_factory=list)  # e.g. "Bonjour"

    def add(self, source: str, name: str = "", model: str = "", kind: str = "") -> None:
        name, model = _clean(name), _clean(model)
        if name and not self.name:
            self.name = name
        if model and not self.model:
            self.model = model
        if kind and kind not in self.kinds:
            self.kinds.append(kind)
        if source not in self.source:
            self.source.append(source)

    def as_dict(self) -> dict:
        return {"name": self.name, "model": self.model, "kinds": self.kinds, "source": self.source}


def _clean(text: str) -> str:
    text = re.sub(r"\s+", " ", (text or "").replace("\\032", " ")).strip()
    return "" if re.fullmatch(r"[0-9a-fA-F:-]{12,}|[\d.]+", text) else text[:60]


# --- Bonjour (mDNS) ----------------------------------------------------------------------------------------

def _encode_name(name: str) -> bytes:
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".") if p) + b"\0"


def _query(names: list[str], qtype: int = 12, unicast: bool = True) -> bytes:
    """A DNS query; class 0x8001 asks for a direct (unicast) answer, 0x0001 for one to the whole group."""
    header = struct.pack("!HHHHHH", 0, 0, len(names), 0, 0, 0)
    klass = 0x8001 if unicast else 0x0001
    return header + b"".join(_encode_name(n) + struct.pack("!HH", qtype, klass) for n in names)


def _read_name(data: bytes, pos: int, depth: int = 0) -> tuple[str, int]:
    labels = []
    while pos < len(data) and depth < 20:
        length = data[pos]
        if length == 0:
            return ".".join(labels), pos + 1
        if length & 0xC0 == 0xC0:  # compressed: the rest is elsewhere
            pointer = struct.unpack("!H", data[pos:pos + 2])[0] & 0x3FFF
            rest, _ = _read_name(data, pointer, depth + 1)
            return ".".join(labels + ([rest] if rest else [])), pos + 2
        labels.append(data[pos + 1:pos + 1 + length].decode("utf-8", errors="replace"))
        pos += 1 + length
    return ".".join(labels), pos


def parse_records(data: bytes) -> list[tuple[str, int, object]]:
    """(name, type, value) for every answer and extra record in an mDNS reply. PTR/SRV values are names, TXT
    values are {key: value}, A values are addresses."""
    try:
        _, _, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
        pos = 12
        for _ in range(qd):
            _, pos = _read_name(data, pos)
            pos += 4
        records = []
        for _ in range(an + ns + ar):
            name, pos = _read_name(data, pos)
            rtype, _, _, length = struct.unpack("!HHIH", data[pos:pos + 10])
            pos += 10
            body = data[pos:pos + length]
            if rtype == 12:  # PTR
                records.append((name, rtype, _read_name(data, pos)[0]))
            elif rtype == 33:  # SRV: the host name after priority, weight and port
                records.append((name, rtype, _read_name(data, pos + 6)[0]))
            elif rtype == 16:  # TXT
                txt, i = {}, 0
                while i < len(body):
                    entry = body[i + 1:i + 1 + body[i]].decode("utf-8", errors="replace")
                    key, _, value = entry.partition("=")
                    txt[key.lower()] = value
                    i += 1 + body[i]
                records.append((name, rtype, txt))
            elif rtype == 1 and length == 4:  # A
                records.append((name, rtype, socket.inet_ntoa(body)))
            pos += length
        return records
    except (struct.error, IndexError):
        return []


def clues_from_mdns(replies: list[tuple[str, bytes]]) -> dict[str, Clues]:
    """{ip: Clues} from (sender, reply) pairs."""
    found: dict[str, Clues] = {}
    for ip, data in replies:
        clues = found.setdefault(ip, Clues())
        for name, rtype, value in parse_records(data):
            service = next((s for s in MDNS_SERVICES if name.endswith(s) or value == s), None)
            if rtype == 12 and isinstance(value, str):
                service = next((s for s in MDNS_SERVICES if name == s), service)
                instance = value.split("._")[0] if "._" in value else ""
                clues.add("Bonjour", name=instance, kind=MDNS_SERVICES.get(service or "", ""))
            elif rtype == 16 and isinstance(value, dict):
                model = next((value[k] for k in MODEL_KEYS if value.get(k)), "")
                friendly = next((value[k] for k in NAME_KEYS if value.get(k)), "")
                clues.add("Bonjour", name=friendly or name.split("._")[0], model=model,
                          kind=MDNS_SERVICES.get(service or "", ""))
    return {ip: c for ip, c in found.items() if c.name or c.model or c.kinds}


def _group_listener(own_ip: str) -> socket.socket | None:
    """A socket on the Bonjour port, for devices that only answer to the whole group. None if Windows won't
    share the port."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("", MDNS[1]))
        group = struct.pack("4s4s", socket.inet_aton(MDNS[0]), socket.inet_aton(own_ip or "0.0.0.0"))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, group)
        if own_ip:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(own_ip))
        return s
    except OSError:
        return None


def ask_bonjour(own_ip: str = "", timeout: float = 3.0) -> dict[str, Clues]:
    """Ask once for each kind of Bonjour service, both "answer me" and "answer the group" (devices differ in
    which they honour), and collect the answers."""
    import select

    replies = []
    names = list(MDNS_SERVICES)
    direct = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    group = _group_listener(own_ip)
    sockets = [direct] + ([group] if group else [])
    try:
        direct.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        if own_ip:
            direct.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(own_ip))
        for i in range(0, len(names), 6):  # a few questions per packet keeps each one small
            direct.sendto(_query(names[i:i + 6]), MDNS)
            if group:
                group.sendto(_query(names[i:i + 6], unicast=False), MDNS)
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            ready, _, _ = select.select(sockets, [], [], 0.3)
            for s in ready:
                try:
                    data, addr = s.recvfrom(9000)
                except OSError:
                    continue
                if addr[0] != own_ip:
                    replies.append((addr[0], data))
    except OSError:
        log.exception("Bonjour discovery failed")
    finally:
        for s in sockets:
            s.close()
    return clues_from_mdns(replies)


# --- UPnP descriptions -------------------------------------------------------------------------------------

def parse_upnp_description(xml: bytes) -> Clues:
    clues = Clues()
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return clues
    for el in root.iter():
        if el.tag.endswith("}device") or el.tag == "device":
            values = {c.tag.split("}")[-1]: (c.text or "").strip() for c in el}
            model = " ".join(v for v in (values.get("manufacturer", ""), values.get("modelName", ""))
                             if v and v.lower() not in ("unknown", "n/a"))
            kind = values.get("deviceType", "").split(":")[-2] if values.get("deviceType", "").count(":") >= 2 \
                else ""
            clues.add("UPnP", name=values.get("friendlyName", ""), model=model,
                      kind={"MediaRenderer": "TV or media player", "MediaServer": "Media server",
                            "InternetGatewayDevice": "Router", "Basic": ""}.get(kind, ""))
            break
    return clues


def read_upnp_descriptions(locations: dict[str, str]) -> dict[str, Clues]:
    """{ip: Clues} from each device's own UPnP description (one request per device)."""
    def fetch(location: str) -> Clues:
        try:
            return parse_upnp_description(requests.get(location, timeout=4).content)
        except requests.RequestException:
            return Clues()

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = dict(zip(locations, pool.map(fetch, locations.values())))
    return {ip: c for ip, c in results.items() if c.name or c.model}


# --- Windows PC names (NetBIOS) ----------------------------------------------------------------------------

NBSTAT = struct.pack("!HHHHHH", 0x4154, 0, 1, 0, 0, 0) + b"\x20" + b"CK" + b"A" * 30 + b"\0" + struct.pack("!HH", 0x21, 1)


def parse_nbstat(data: bytes) -> str:
    """The computer's name from a NetBIOS status answer."""
    try:
        pos = 12
        while data[pos]:
            pos += data[pos] + 1
        pos += 1 + 10  # end of name, then type, class, TTL and length
        count = data[pos]
        pos += 1
        for _ in range(count):
            name, suffix, flags = data[pos:pos + 15], data[pos + 15], struct.unpack("!H", data[pos + 16:pos + 18])[0]
            pos += 18
            if suffix == 0 and not flags & 0x8000:  # the unique workstation name, not a group
                return name.decode("ascii", errors="replace").strip()
    except (IndexError, struct.error):
        pass
    return ""


def ask_pc_names(ips: list[str], timeout: float = 1.5) -> dict[str, Clues]:
    """One name request to each address; Windows PCs (and some storage boxes) answer."""
    found: dict[str, Clues] = {}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(0.3)
            for ip in ips:
                try:
                    s.sendto(NBSTAT, (ip, 137))
                except OSError:
                    pass
            end = time.monotonic() + timeout
            while time.monotonic() < end:
                try:
                    data, addr = s.recvfrom(2048)
                except socket.timeout:
                    continue
                name = parse_nbstat(data)
                if name:
                    found.setdefault(addr[0], Clues()).add("Windows name", name=name, kind="Computer")
    except OSError:
        log.exception("PC name lookup failed")
    return found


def merge(*sources: dict[str, Clues]) -> dict[str, dict]:
    """Combine every source's clues per address, as plain dicts (for the daily cache)."""
    out: dict[str, Clues] = {}
    for source in sources:
        for ip, c in source.items():
            mine = out.setdefault(ip, Clues())
            for kind in c.kinds or [""]:
                for src in c.source:
                    mine.add(src, c.name, c.model, kind)
    return {ip: c.as_dict() for ip, c in out.items()}


# --- "Identify this device" (only when clicked) ------------------------------------------------------------

@dataclass
class Knock:
    open_ports: list[int] = field(default_factory=list)
    hints: list[str] = field(default_factory=list)
    page_title: str = ""


def knock(ip: str, ports: dict[int, str] | None = None, timeout: float = 0.8) -> Knock:
    """Try a normal connection to each well-known port of one device, closing it straight away."""
    ports = ports or PORT_HINTS

    def is_open(port: int) -> bool:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return True
        except OSError:
            return False

    with ThreadPoolExecutor(max_workers=min(8, os.cpu_count() or 4)) as pool:
        opened = [p for p, ok in zip(ports, pool.map(is_open, ports)) if ok]
    result = Knock(opened, [f"Port {p}: {ports[p]}" for p in opened])
    for port, scheme in ((80, "http"), (8080, "http"), (443, "https")):
        if port in opened:
            result.page_title = page_title(f"{scheme}://{ip}:{port}/")
            if result.page_title:
                break
    return result


def page_title(url: str) -> str:
    import warnings

    try:
        with warnings.catch_warnings():  # devices use self-made certificates; nothing secret is sent
            warnings.simplefilter("ignore")
            r = requests.get(url, timeout=3, verify=False)
    except requests.RequestException:
        return ""
    title = re.search(r"<title[^>]*>(.*?)</title>", r.text[:20000], re.I | re.S)
    return _clean(title.group(1)) if title else ""


def guess(knocked: Knock) -> str:
    """A plain-words guess from the open ports (rules, not AI)."""
    ports = set(knocked.open_ports)
    if 62078 in ports:
        return "Probably an iPhone or iPad"
    if ports & {8008, 8009}:
        return "Probably a Chromecast, Google TV or Google speaker"
    if 8060 in ports:
        return "Probably a Roku or a TV with Roku built in"
    if ports & {9100, 631}:
        return "Probably a printer"
    if 554 in ports or 34567 in ports or 37777 in ports:
        return "Probably a camera or video recorder"
    if 7000 in ports:
        return "Probably an Apple TV or AirPlay speaker"
    if 3389 in ports or (445 in ports and 548 not in ports):
        return "Probably a Windows PC"
    if 548 in ports:
        return "Probably a Mac or a storage box"
    if 3074 in ports:
        return "Probably an Xbox"
    if 9295 in ports:
        return "Probably a PlayStation"
    if 53 in ports:
        return "Probably a router or Wi-Fi mesh point"
    if ports:
        return "Not sure what it is"
    return "It didn't answer on any well-known port (common for phones and smart plugs)"
