"""Link-check helper for the Project Atlas browser extension (Chrome, Edge, Brave).

The browser starts this program and talks to it over stdin/stdout using Chrome's
"native messaging" format: a 4-byte little-endian length, then that much JSON. The
VirusTotal key never leaves Windows Credential Manager; the extension only ever sees
verdicts.

Two kinds of request:
- {"id": 1, "type": "check", "url": "...", "auto": true}  every page you open. Only the
  address without its query string (?...) and #fragment is checked, since those often
  hold search terms, session tokens or email addresses.
- {"id": 2, "type": "check", "url": "...", "auto": false} a link you chose to check from
  the right-click menu: the full address is checked.
- {"id": 3, "type": "trust", "host": "outlook.live.com"} "Always trust this site" on the warning
  page: adds the site's domain (live.com) to `trusted_sites` in the settings.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import struct
import sys
from urllib.parse import urlparse

from atlas import __version__, allowlist, config, mistakes
from atlas.app import build_scanner, setup_logging
from atlas.links import check_link
from atlas.scanner import short_url

log = logging.getLogger(__name__)

HOST_NAME = "com.projectatlas.linkcheck"
MAX_MESSAGE = 1024 * 1024  # Chrome's limit for messages sent to a host


def read_message(stream) -> dict | None:
    header = stream.read(4)
    if len(header) < 4:
        return None  # the browser closed the connection
    (length,) = struct.unpack("<I", header)
    if length > MAX_MESSAGE:
        raise ValueError(f"message too long ({length} bytes)")
    return json.loads(stream.read(length).decode("utf-8"))


def write_message(stream, message: dict) -> None:
    data = json.dumps(message).encode("utf-8")
    stream.write(struct.pack("<I", len(data)) + data)
    stream.flush()


def is_private(url: str) -> bool:
    """Addresses on this PC or the home network: nothing VirusTotal could know about."""
    host = (urlparse(url).hostname or "").lower()
    if host in ("localhost", "") or host.endswith((".local", ".lan", ".home", ".internal", ".localhost")):
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return "." not in host  # single-word names like "router"


def handle(request: dict, scanner) -> dict:
    kind = request.get("type")
    if kind == "ping":
        return {"ok": True, "version": __version__, "key": scanner.vt is not None}
    if kind == "trust":
        try:
            site = allowlist.trust_site(str(request.get("host", "")))
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
        scanner.settings.trusted_sites = config.Settings.load().trusted_sites
        return {"ok": True, "site": site}
    if kind != "check":
        return {"error": f"unknown request {kind!r}"}
    # Read now: a site trusted or removed in the Atlas window counts at once.
    scanner.settings.trusted_sites = config.Settings.load().trusted_sites
    url = str(request.get("url", ""))
    if not url.lower().startswith(("http://", "https://")):
        return {"verdict": "skipped", "reasons": ["Only web addresses are checked"]}
    if is_private(url):
        return {"verdict": "skipped", "reasons": ["An address on this PC or your home network"]}
    target = short_url(url) if request.get("auto", True) else url
    check = check_link(scanner, target)
    report = check.url_report if check.url_report and check.url_report.found else check.domain_report
    reply = {"verdict": check.verdict.value, "url": check.url, "host": check.host, "reasons": check.reasons,
             "vt_link": report.gui_link if report and report.found else None}
    if check.verdict.value in ("malicious", "suspicious", "unknown"):  # only the site's name goes in the report
        reply["report"] = mistakes.issue_url("Site", check.host, check.verdict.value, check.reasons)
    return reply


def main() -> int:
    setup_logging()
    stdin, stdout = sys.stdin.buffer, sys.stdout.buffer
    scanner, store = build_scanner(config.Settings.load())
    log.info("Browser link-check helper started (v%s)", __version__)
    try:
        while (request := read_message(stdin)) is not None:
            try:
                reply = handle(request, scanner)
            except Exception as exc:  # one bad request must not end the session
                log.exception("Link check failed")
                reply = {"verdict": "error", "reasons": [f"Check failed: {exc}"]}
            reply["id"] = request.get("id")
            write_message(stdout, reply)
    finally:
        store.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
