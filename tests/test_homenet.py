"""v0.14: the home network (router, Wi-Fi, devices), with every outside answer faked."""

from datetime import datetime, timedelta

from atlas import homenet
from atlas.findings import NOTE, OK, WARN
from atlas.homenet import Device, HomeCheck, Mapping, Network, Wifi

NET = Network("10.0.0.1", "F8-5E-42-42-C5-EE", "Wi-Fi", 15, "10.0.0.66", 24, "Private", "Home", "58-96-71-BB-AE-7A")


def test_makers_and_private_addresses():
    assert homenet.maker("8c:49:62:04:f9:c4") == "Roku"
    assert homenet.maker("F0B61E7F18F9") == "Intel"
    assert homenet.maker("06-F1-3D-72-7B-BD") == homenet.PRIVATE  # second digit 6: made up
    assert Device("06-F1-3D-72-7B-BD", "10.0.0.68", homenet.PRIVATE).label == "Phone, tablet or laptop"
    assert homenet.short_maker("Hon Hai Precision Ind. Co.,Ltd.") == "Hon Hai Precision Ind"
    assert homenet.normal_mac("bad") == ""


def test_home_is_private_or_confirmed():
    assert NET.is_home()
    public = Network("10.0.0.1", "F8-5E-42-42-C5-EE", category="Public")
    assert not public.is_home() and public.is_home(["F8-5E-42-42-C5-EE"])


WIFI = """
    Name                   : Wi-Fi
    State                  : connected
    SSID                   : Home
    Authentication         : {auth}
    Cipher                 : {cipher}
"""


def test_wifi_security():
    def level(auth, cipher="CCMP"):
        return homenet.wifi_findings(homenet.read_wifi(WIFI.format(auth=auth, cipher=cipher)))[0].level
    assert level("Open", "None") == WARN
    assert level("WEP", "WEP") == WARN
    assert level("WPA2-Personal", "TKIP") == WARN
    assert level("WPA2-Personal") == OK
    assert level("WPA3-Personal") == OK
    assert homenet.read_wifi("    State : disconnected\n") is None


def test_router_brand_and_checklist():
    assert homenet.router_brand({"title": "XFINITY", "server": ""}, "")[0] == "Xfinity"
    assert homenet.router_brand({}, "TP-Link Systems")[0] == "TP-Link"
    assert homenet.router_brand({}, "") is None
    check = HomeCheck(network=NET, brand=("Xfinity", "the Xfinity app"), page={"url": "http://10.0.0.1/"})
    (f,) = homenet.router_findings(check)
    assert f.level == NOTE and "never signs in" in f.details[0] and f.data["url"] == "http://10.0.0.1/"


def test_upnp_doors():
    assert homenet.upnp_findings(HomeCheck(network=NET))[0].level == OK
    cam = Device("AA-BB-CC-00-00-01", "10.0.0.50", "Hikvision", "Front camera")
    check = HomeCheck(network=NET, upnp=True, devices=[cam], mappings=[
        Mapping(8554, "TCP", "10.0.0.50", 554, "camera"), Mapping(3074, "UDP", "10.0.0.60", 3074, "Xbox")])
    found = homenet.upnp_findings(check)
    assert [f.level for f in found] == [NOTE, WARN, NOTE]
    assert "Front camera is reachable from the internet: camera video (RTSP)" in found[1].title


def test_dns_answerer():
    check = HomeCheck(network=NET, resolver="74.125.80.28", resolver_owner="Google LLC")
    assert homenet.resolver_findings(check)[0].level == OK
    check.resolver_owner = "Shady Hosting Ltd"
    assert homenet.resolver_findings(check)[0].level == NOTE

    class Flagged:
        found, malicious = True, 9

    assert homenet.resolver_findings(check, lambda kind, ip: Flagged())[0].level == WARN


def test_new_devices_skip_the_first_look_and_old_ones():
    now = datetime(2026, 10, 29, 12, 0)
    devices = [Device("AA-00-00-00-00-01", "10.0.0.2", "Vizio", first_seen="2026-10-28T09:00:00"),
               Device("AA-00-00-00-00-02", "10.0.0.3", "Roku", first_seen="2026-10-28T09:00:00", initial=True),
               Device("AA-00-00-00-00-03", "10.0.0.4", "Intel", first_seen=(now - timedelta(days=9)).isoformat()),
               Device("AA-00-00-00-00-04", "10.0.0.1", "Vantiva", first_seen="2026-10-28T09:00:00", role="Router")]
    (f,) = homenet.new_device_findings(devices, now)
    assert f.key == "homenet:new:AA-00-00-00-00-01" and "Vizio device" in f.title


def fake_network(monkeypatch, category="Private"):
    net = Network(**{**NET.__dict__, "category": category})
    monkeypatch.setattr(homenet, "read_network", lambda: net)
    monkeypatch.setattr(homenet, "wake_devices", lambda n: 0)
    monkeypatch.setattr(homenet, "ssdp", lambda timeout=3.0: {"10.0.0.208": [
        {"st": "upnp:rootdevice", "server": "Roku/16.0.4 UPnP/1.0 Roku/16.0.4", "location": ""}]})
    monkeypatch.setattr(homenet, "router_page", lambda ip: {"title": "XFINITY", "server": "", "url": "http://x/"})
    monkeypatch.setattr(homenet, "resolver_ip", lambda: "74.125.80.28")
    monkeypatch.setattr(homenet, "network_owner", lambda ip: "Google LLC")
    monkeypatch.setattr(homenet, "device_names", lambda ips, deadline=4.0: {})
    monkeypatch.setattr(homenet, "read_wifi", lambda output=None: Wifi("Home", "WPA2-Personal", "CCMP"))
    neighbours = [("10.0.0.1", "F8-5E-42-42-C5-EE"), ("10.0.0.208", "8C-49-62-04-F9-C4")]
    monkeypatch.setattr(homenet, "read_neighbours", lambda n: list(neighbours))
    return neighbours


def test_check_home_end_to_end(store, monkeypatch):
    neighbours = fake_network(monkeypatch)
    first = homenet.check_home(store, homes=[])
    assert [d.label for d in first.devices] == ["Router", "This PC (" + first.devices[1].name + ")", "Roku"]
    assert all(d.initial for d in first.devices)  # the first look announces nothing
    assert not [f for f in first.findings if f.key.startswith("homenet:new:")]
    assert "Xfinity at 10.0.0.1" in homenet.summary(first)

    neighbours.append(("10.0.0.167", "E8-38-A0-27-45-87"))
    second = homenet.check_home(store, homes=[])  # today's discovery comes from the cache
    news = [f for f in second.findings if f.key.startswith("homenet:new:")]
    assert [f.key for f in news] == ["homenet:new:E8-38-A0-27-45-87"] and "Vizio device" in news[0].title


def test_public_network_asks_first_and_looks_at_nothing(store, monkeypatch):
    fake_network(monkeypatch, category="Public")
    monkeypatch.setattr(homenet, "read_neighbours", lambda n: (_ for _ in ()).throw(AssertionError("looked")))
    check = homenet.check_home(store, homes=[])
    assert [f.key for f in check.findings] == ["homenet:ask"] and check.devices == []
    monkeypatch.setattr(homenet, "read_neighbours", lambda n: [("10.0.0.208", "8C-49-62-04-F9-C4")])
    assert homenet.check_home(store, homes=[NET.id]).devices  # once the user says it's home
