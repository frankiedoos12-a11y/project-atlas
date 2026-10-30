"""v0.14.1: what devices say about themselves (Bonjour, UPnP, NetBIOS) and "Identify this device"."""

import socket
import struct

from atlas import identify


def name(text: str) -> bytes:
    return identify._encode_name(text)


def record(owner: str, rtype: int, body: bytes) -> bytes:
    return name(owner) + struct.pack("!HHIH", rtype, 1, 120, len(body)) + body


def txt(**values) -> bytes:
    return b"".join(bytes([len(e)]) + e for e in (f"{k}={v}".encode() for k, v in values.items()))


def test_bonjour_reply_gives_name_model_and_kind():
    instance = "Living Room._googlecast._tcp.local"
    answers = [record("_googlecast._tcp.local", 12, name(instance)),
               record(instance, 16, txt(fn="Living Room", md="M65Q6M-K04")),
               record("vizio.local", 1, socket.inet_aton("10.0.0.167"))]
    reply = struct.pack("!HHHHHH", 0, 0x8400, 0, len(answers), 0, 0) + b"".join(answers)
    clues = identify.clues_from_mdns([("10.0.0.167", reply)])["10.0.0.167"]
    assert clues.name == "Living Room" and clues.model == "M65Q6M-K04"
    assert clues.kinds == ["Google Cast device (Chromecast, Google TV or speaker)"]


def test_compressed_names_and_rubbish():
    # "b.local" then a pointer back to "local" at offset 14
    data = struct.pack("!HHHHHH", 0, 0, 0, 0, 0, 0) + b"\x01b\x05local\x00" + b"\x01c\xc0\x0e"
    assert identify._read_name(data, 12) == ("b.local", 21)
    assert identify._read_name(data, 21)[0] == "c.local"
    assert identify.parse_records(b"\x00\x01") == []


def test_upnp_description():
    xml = b"""<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0"><device>
      <deviceType>urn:roku-com:device:player:1-0</deviceType><friendlyName>Roku Ultra</friendlyName>
      <manufacturer>Roku</manufacturer><modelName>4670RW</modelName></device></root>"""
    clues = identify.parse_upnp_description(xml)
    assert (clues.name, clues.model, clues.source) == ("Roku Ultra", "Roku 4670RW", ["UPnP"])
    assert identify.parse_upnp_description(b"not xml").name == ""


def test_netbios_status_answer():
    names = (b"DESKTOP-ANNA   " + b"\x00" + struct.pack("!H", 0x0400)
             + b"WORKGROUP      " + b"\x00" + struct.pack("!H", 0x8400))
    answer = (struct.pack("!HHHHHH", 0x4154, 0x8400, 0, 1, 0, 0) + b"\x20" + b"CK" + b"A" * 30 + b"\0"
              + struct.pack("!HHIH", 0x21, 1, 0, len(names) + 1) + b"\x02" + names)
    assert identify.parse_nbstat(answer) == "DESKTOP-ANNA"
    assert identify.parse_nbstat(b"\x00" * 5) == ""


def test_merge_keeps_the_first_name_and_every_kind():
    a = {"10.0.0.5": identify.Clues()}
    a["10.0.0.5"].add("Bonjour", "Office printer", "HP LaserJet", "Printer")
    b = {"10.0.0.5": identify.Clues()}
    b["10.0.0.5"].add("Windows name", "HPPRINT", "", "Computer")
    merged = identify.merge(a, b)["10.0.0.5"]
    assert merged["name"] == "Office printer" and merged["kinds"] == ["Printer", "Computer"]
    assert merged["source"] == ["Bonjour", "Windows name"]


def test_guess_from_open_ports():
    def g(*ports):
        return identify.guess(identify.Knock(list(ports)))
    assert g(62078) == "Probably an iPhone or iPad"
    assert g(80, 554) == "Probably a camera or video recorder"
    assert g(9100) == "Probably a printer"
    assert g(445, 3389) == "Probably a Windows PC"
    assert g().startswith("It didn't answer")


def test_knock_only_tries_the_listed_ports_on_one_device():
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen()
        port = server.getsockname()[1]
        knocked = identify.knock("127.0.0.1", {port: "test service", 1: "nothing here"}, timeout=0.5)
    assert knocked.open_ports == [port] and knocked.hints == [f"Port {port}: test service"]
