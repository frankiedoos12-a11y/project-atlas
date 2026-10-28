"""Browser extension: the extension's fixed ID, the link-check helper, and its registration."""

import base64
import hashlib
import io
import json
import struct

import pytest

from atlas import browserext, nativehost
from atlas.nativehost import handle, read_message, write_message
from conftest import FakeVT
from test_scanwindow import FakeRegistry

CLEAN = {"malicious": 0, "suspicious": 0, "harmless": 60, "undetected": 30}


def test_extension_id_matches_the_manifest_key():
    manifest = json.loads((browserext.extension_dir() / "manifest.json").read_text(encoding="utf-8"))
    digest = hashlib.sha256(base64.b64decode(manifest["key"])).hexdigest()[:32]
    assert "".join(chr(ord("a") + int(c, 16)) for c in digest) == browserext.EXTENSION_ID


def test_extension_files_are_all_there():
    folder = browserext.extension_dir()
    manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
    referenced = [manifest["background"]["service_worker"], manifest["action"]["default_popup"],
                  *manifest["icons"].values(), "warning.html", "warning.js", "popup.js", "style.css"]
    assert [f for f in referenced if not (folder / f).exists()] == []
    assert "nativeMessaging" in manifest["permissions"]


def test_message_framing_round_trip():
    buf = io.BytesIO()
    write_message(buf, {"id": 7, "verdict": "clean", "reasons": ["ünïcode ok"]})
    raw = buf.getvalue()
    assert struct.unpack("<I", raw[:4])[0] == len(raw) - 4
    assert read_message(io.BytesIO(raw)) == {"id": 7, "verdict": "clean", "reasons": ["ünïcode ok"]}
    assert read_message(io.BytesIO(b"")) is None  # browser closed the connection


def test_oversized_messages_are_refused():
    with pytest.raises(ValueError):
        read_message(io.BytesIO(struct.pack("<I", 50 * 1024 * 1024)))


def test_page_checks_drop_query_strings(make_scanner):
    vt = FakeVT(domains={"shop.example": CLEAN})
    reply = handle({"type": "check", "url": "https://shop.example/cart?session=SECRET#pay", "auto": True},
                   make_scanner(vt))
    assert reply["verdict"] == "clean"
    assert all("SECRET" not in target for _, target in vt.calls)


def test_right_click_checks_send_the_full_link(make_scanner):
    url = "https://shop.example/item?id=42"
    vt = FakeVT(urls={url: {"malicious": 9, "suspicious": 0, "harmless": 50, "undetected": 30}})
    reply = handle({"type": "check", "url": url, "auto": False}, make_scanner(vt))
    assert reply["verdict"] == "malicious" and reply["vt_link"]
    assert ("url", url) in vt.calls


@pytest.mark.parametrize("url", ["http://192.168.1.1/admin", "http://localhost:8080/", "http://router/",
                                 "https://nas.local/", "http://10.0.0.5/", "file:///C:/x.html"])
def test_home_network_and_local_addresses_are_never_sent(url, make_scanner):
    vt = FakeVT()
    assert handle({"type": "check", "url": url}, make_scanner(vt))["verdict"] == "skipped"
    assert vt.calls == []


def test_ping_reports_version_and_key(make_scanner):
    reply = handle({"type": "ping"}, make_scanner(FakeVT()))
    assert reply["ok"] and reply["key"] and reply["version"]


def test_registration_for_each_browser(monkeypatch, isolated_dirs):
    fake = FakeRegistry()
    monkeypatch.setattr(browserext, "winreg", fake)
    manifest = browserext.enable()
    for base in browserext.BROWSER_KEYS.values():
        assert fake.keys[rf"{base}\{nativehost.HOST_NAME}"][""] == str(manifest)
    data = json.loads(manifest.read_text(encoding="utf-8"))
    assert data["allowed_origins"] == [f"chrome-extension://{browserext.EXTENSION_ID}/"]
    launcher = (manifest.parent / "atlas-link-helper.bat").read_text(encoding="utf-8")
    assert data["path"].endswith("atlas-link-helper.bat") and "-m atlas.nativehost" in launcher
    assert browserext.is_enabled()
    browserext.disable()
    assert fake.keys == {} and not browserext.is_enabled()
