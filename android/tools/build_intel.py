"""Builds the Android app's threat data (app/src/main/assets/intel.txt) from public lists.

Source: Stalkerware indicators by Echap (CC BY 4.0), https://github.com/AssoEchap/stalkerware-indicators
  - ioc.yaml: stalkerware families, their app names, signing certificates, websites and servers
  - watchware.yaml: monitoring ("parental control") apps that let someone else watch the phone
  - samples.csv: fingerprints (SHA-256) of known stalkerware app files

Commercial ("mercenary") spyware, from the indicators Amnesty International's Security Lab, Citizen Lab, Google,
Lookout and others published with their investigations, as collected for MVT (the Mobile Verification Toolkit):
https://github.com/mvt-project/mvt-indicators (MIT), with Amnesty's own sets from https://github.com/AmnestyTech/
investigations (CC BY 2.0). Only what a phone app can check is kept: websites and servers, app names, signing
certificates and app file fingerprints.

Optional sources by abuse.ch (CC0). They need a free abuse.ch account key, read from the ABUSE_CH_KEY environment
variable (a repository secret in the weekly workflow), never from a file here:
  - MalwareBazaar, https://bazaar.abuse.ch: the newest Android app samples, plus the newest of each common Android
    malware family (ANDROID_FAMILIES), named by family
  - ThreatFox, https://threatfox.abuse.ch: domains malware used in the last 7 days (its servers and download sites),
    for link protection and the scam check

Stdlib only. Run with no arguments to download the lists, or --from DIR to read them from a folder (which may hold
saved abuse.ch answers as malwarebazaar.json and threatfox.json, and the spyware sets as spyware.json).
The output is one line per indicator, tab-separated, so the phone reads it without a library:
  F <id> <name> <type>      a family
  P <package> <id>          an app's package name
  C <sha1> <id>             an app's signing certificate (SHA-1, upper case)
  H <sha256> <id>           an app file's fingerprint (lower case)
  D <domain> <id>           a website or server (it and its subdomains)
"""

from __future__ import annotations

import argparse
import csv
import datetime
import io
import json
import os
import re
import sys
import urllib.parse
import urllib.request
from pathlib import Path

BASE = "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/"
FILES = ("ioc.yaml", "watchware.yaml", "samples.csv")
MVT = "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/"
AMNESTY = "https://raw.githubusercontent.com/AmnestyTech/investigations/master/"
SPY_FILE = "spyware.json"
# Each set: the name the phone shows, and where its STIX file is. Echap's stalkerware set is already read above.
SPYWARE = (
    ("Pegasus (NSO Group)", AMNESTY + "2021-07-18_nso/pegasus.stix2"),
    ("Predator (Intellexa)", MVT + "intellexa_predator/predator.stix2"),
    ("Hermit (RCS Lab)", MVT + "2022-06-23_rcs_lab/rcs.stix2"),
    ("Mercenary spyware campaign (2023)", AMNESTY + "2023-03-29_android_campaign/malware.stix2"),
    ("KingSpawn (QuaDream)", MVT + "2023-04-11_quadream/kingspawn.stix2"),
    ("Operation Triangulation", MVT + "2023-06_01_operation_triangulation/operation_triangulation.stix2"),
    ("WyrmSpy and DragonEgg (APT41)", MVT + "2023-07-25_wyrmspy_dragonegg/wyrmspy_dragonegg.stix2"),
    ("Helios (Wintego)", AMNESTY + "2024-05-02_wintego_helios/wintego_helios.stix2"),
    ("NoviSpy", AMNESTY + "2024-12-16_serbia_novispy/novispy.stix2"),
    ("EagleMsgSpy", MVT + "2024-12-25_eaglemsgspy/eaglemsgspy.stix2"),
    ("DevilsTongue (Candiru)", MVT + "candiru/candiru.stix2"),
    ("ResidentBat", MVT + "ResidentBat/residentbat.stix2"),
    ("Cellebrite phone extraction", MVT + "cellebrite/cellebrite.stix2"),
    ("DarkSword", MVT + "2026-03-30_darksword/darksword.stix2"),
    ("Coruna", MVT + "2026-03-03_coruna_cryptowaters/coruna.stix2"),
    ("Morpheus", MVT + "2026-04-23_ips_morpheus/morpheus.stix2"),
    ("BTMOB", MVT + "2026-05-26_btmob/btmob.stix2"),
    ("Spyrtacus", MVT + "2026-04-09_sio_spyrtacus/spyrtacus.stix2"),
)
# The STIX patterns a phone app can check: "[domain-name:value = 'example.com']" and the like.
STIX = re.compile(r"\[(domain-name:value|app:id|app:cert\.sha1|file:hashes\.sha256)\s*=\s*'([^']+)'\]")
MALWAREBAZAAR = "https://mb-api.abuse.ch/api/v1/"
MB_FILE = "malwarebazaar.json"
THREATFOX = "https://threatfox-api.abuse.ch/api/v1/"
TF_FILE = "threatfox.json"
# Android banking trojans, spyware and fraud apps seen most often; MalwareBazaar is asked for each one's newest samples.
ANDROID_FAMILIES = ("SpyNote", "SpyMax", "Hydra", "Anatsa", "TeaBot", "Cerberus", "Alien", "ERMAC", "Hook", "Octo",
                    "SharkBot", "Joker", "FluBot", "BRATA", "Xenomorph", "Godfather", "Vultur", "IRATA", "BtmobRAT",
                    "Coper", "Medusa", "Chameleon", "AhMyth", "Rafel", "CraxsRAT", "TgToxic", "ToxicPanda",
                    "Copybara", "Rocinante", "NGate", "BingoMod", "Brokewell", "Mamont", "SoumniBot", "Dendroid")
MAX_SAMPLES = 15_000  # keeps the app's threat data a few hundred KB
MIN_CONFIDENCE = 75  # ThreatFox's own 0-100 certainty
OUT = Path(__file__).resolve().parent.parent / "app" / "src" / "main" / "assets" / "intel.txt"
FORMAT = 1
# Shared hosting: listing the whole domain would flag everyone who uses it.
SHARED = {"google.com", "googleapis.com", "firebaseio.com", "firebaseapp.com", "amazonaws.com", "github.com",
          "github.io", "cloudfront.net", "appspot.com", "herokuapp.com", "blogspot.com", "wordpress.com",
          "web.app", "000webhostapp.com", "azurewebsites.net", "play.google.com", "t.me", "youtube.com",
          "duckdns.org", "ngrok.io", "ngrok-free.app", "trycloudflare.com", "workers.dev", "pages.dev", "vercel.app",
          "netlify.app", "glitch.me", "r2.dev", "onrender.com", "dropbox.com", "discord.com", "discordapp.com",
          "telegram.org", "pastebin.com", "googleusercontent.com", "windows.net", "cloudflare.com", "microsoft.com"}
SHA1 = re.compile(r"^[0-9A-Fa-f]{40}$")
SHA256 = re.compile(r"^[0-9A-Fa-f]{64}$")
DOMAIN = re.compile(r"^(?:[a-z0-9-]+\.)+[a-z]{2,}$")


def parse_yaml(text: str) -> list[dict]:
    """Just enough YAML for these lists: entries of keys holding a value, a list, or keys holding lists."""
    entries: list[dict] = []
    entry: dict | None = None
    key = sub = None
    for raw in text.splitlines():
        line = raw.split(" #")[0].rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        body = line.strip()
        if indent == 0 and body.startswith("- "):
            entry, key, sub = {}, None, None
            entries.append(entry)
            body, indent = body[2:], 2
        if entry is None:
            continue
        if body.startswith("- "):
            value = body[2:].strip().strip("'\"")
            if sub is not None and indent >= 4:
                entry[key].setdefault(sub, []).append(value)
            elif key is not None:
                if not isinstance(entry.get(key), list):
                    entry[key] = []
                entry[key].append(value)
            continue
        name, _, value = body.partition(":")
        value = value.strip().strip("'\"")
        if indent <= 2:
            key, sub = name.strip(), None
            entry[key] = value if value else {}
        else:
            sub = name.strip()
            if not isinstance(entry.get(key), dict):
                entry[key] = {}
            if value:
                entry[key][sub] = value
    return entries


def as_list(value) -> list[str]:
    return value if isinstance(value, list) else []


def build(texts: dict[str, str], today: datetime.date) -> str:
    families: list[tuple[str, str]] = []
    index: dict[str, int] = {}
    rows: dict[str, dict[str, int]] = {"P": {}, "C": {}, "H": {}, "D": {}}

    def add(kind: str, value: str, family: int) -> None:
        rows[kind].setdefault(value, family)  # the first family named keeps it

    def domain(value: str, family: int) -> None:
        value = value.lower().strip().rstrip(".")
        if value.startswith("*."):
            value = value[2:]
        if DOMAIN.match(value) and value not in SHARED:
            add("D", value, family)

    for file, kind in (("ioc.yaml", "stalkerware"), ("watchware.yaml", "watchware")):
        for entry in parse_yaml(texts[file]):
            name = str(entry.get("name") or "").strip()
            if not name or "\t" in name:
                continue
            fid = len(families)
            families.append((name, str(entry.get("type") or kind)))
            for alias in [name] + as_list(entry.get("names")):
                index.setdefault(alias.lower(), fid)
            for package in as_list(entry.get("packages")):
                add("P", package.strip(), fid)
            for cert in as_list(entry.get("certificates")):
                if SHA1.match(cert):
                    add("C", cert.upper(), fid)
            for site in as_list(entry.get("websites")):
                domain(site, fid)
            for part in ("c2", "distribution"):
                block = entry.get(part)
                if isinstance(block, dict):
                    for site in as_list(block.get("domains")):
                        domain(site, fid)
                else:
                    for site in as_list(block):
                        domain(site, fid)

    for row in csv.DictReader(io.StringIO(texts["samples.csv"])):
        app = (row.get("App") or "").strip()
        fid = index.get(app.lower())
        if fid is None:
            if not app or "\t" in app:
                continue
            fid = len(families)
            families.append((app, "stalkerware"))
            index[app.lower()] = fid
        if SHA256.match(row.get("SHA256") or ""):
            add("H", row["SHA256"].lower(), fid)
        if SHA1.match(row.get("Certificate") or ""):
            add("C", row["Certificate"].upper(), fid)
        if row.get("Package Name"):
            add("P", row["Package Name"].strip(), fid)

    spy = texts.get(SPY_FILE)
    if spy:
        for name, stix in json.loads(spy).items():
            fid = len(families)
            families.append((name, "spyware"))
            for obj in json.loads(stix).get("objects") or []:
                if obj.get("type") != "indicator":
                    continue
                for what, value in STIX.findall(obj.get("pattern") or ""):
                    if what == "domain-name:value":
                        domain(value, fid)
                    elif what == "app:id":
                        add("P", value.strip(), fid)
                    elif what == "app:cert.sha1" and SHA1.match(value):
                        add("C", value.upper(), fid)
                    elif what == "file:hashes.sha256" and SHA256.match(value):
                        add("H", value.lower(), fid)

    named: dict[str, int] = {}  # malware families, shared by MalwareBazaar and ThreatFox

    def malware(name: object) -> int:
        name = " ".join(str(name or "").split()) or "Unnamed Android malware"
        if name not in named:
            named[name] = len(families)
            families.append((name, "malware"))
        return named[name]

    mb = texts.get(MB_FILE)
    if mb:
        for sample in json.loads(mb).get("data") or []:
            digest = str(sample.get("sha256_hash") or "").lower()
            if not SHA256.match(digest) or digest in rows["H"]:
                continue  # already known as stalkerware: that's the more useful name
            if sample.get("file_type") not in (None, "apk"):
                continue  # a family's Windows or Linux samples
            add("H", digest, malware(sample.get("signature")))

    tf = texts.get(TF_FILE)
    if tf:
        for ioc in json.loads(tf).get("data") or []:
            if ioc.get("ioc_type") != "domain" or int(ioc.get("confidence_level") or 0) < MIN_CONFIDENCE:
                continue  # only whole domains malware uses, and only ones ThreatFox is sure of
            value = str(ioc.get("ioc") or "").lower().strip().rstrip(".")
            if DOMAIN.match(value) and value not in SHARED and value not in rows["D"]:
                add("D", value, malware(ioc.get("malware_printable")))

    out = [f"# atlas-intel {FORMAT}", f"# version {today:%Y%m%d}",
           "# source: Stalkerware indicators by Echap, CC BY 4.0, https://github.com/AssoEchap/stalkerware-indicators"]
    if spy:
        out.append("# source: Commercial spyware indicators by Amnesty International, Citizen Lab and others, "
                   "CC BY 2.0 and MIT, https://github.com/mvt-project/mvt-indicators")
    if mb:
        out.append("# source: MalwareBazaar by abuse.ch, CC0, https://bazaar.abuse.ch")
    if tf:
        out.append("# source: ThreatFox by abuse.ch, CC0, https://threatfox.abuse.ch")
    out += [f"F\t{i}\t{name}\t{kind}" for i, (name, kind) in enumerate(families)]
    for kind in ("P", "C", "H", "D"):
        out += [f"{kind}\t{value}\t{fid}" for value, fid in sorted(rows[kind].items())]
    return "\n".join(out) + "\n"


def _ask(url: str, body: bytes, key: str, post=None) -> dict:
    request = urllib.request.Request(url, data=body, headers={"Auth-Key": key, "User-Agent": "Project-Atlas"})
    if post is not None:
        return json.loads(post(request))
    with urllib.request.urlopen(request, timeout=60) as resp:
        return json.loads(resp.read().decode("utf-8"))


def malwarebazaar(key: str, post=None) -> str:
    """The newest Android app samples, then the newest of each family in ANDROID_FAMILIES, as one answer; "" when
    MalwareBazaar can't answer at all (the build goes on without it)."""
    try:
        first = _ask(MALWAREBAZAAR, b"query=get_file_type&file_type=apk&limit=1000", key, post)
        if first.get("query_status") != "ok":
            raise ValueError(f"MalwareBazaar answered {first.get('query_status')}")
        samples = list(first.get("data") or [])
        for family in ANDROID_FAMILIES:
            body = urllib.parse.urlencode({"query": "get_siginfo", "signature": family, "limit": 1000}).encode()
            try:
                answer = _ask(MALWAREBAZAAR, body, key, post)
            except Exception:
                continue  # one family failing leaves the rest
            if answer.get("query_status") == "ok":
                samples += [s for s in answer.get("data") or [] if s.get("file_type") == "apk"]
        seen, unique = set(), []
        for sample in samples:
            digest = sample.get("sha256_hash")
            if digest and digest not in seen:
                seen.add(digest)
                unique.append(sample)
        return json.dumps({"query_status": "ok", "data": unique[:MAX_SAMPLES]})
    except Exception as e:  # only the error's name and message: never the request, which carries the key
        print(f"MalwareBazaar left out ({type(e).__name__}: {e})", file=sys.stderr)
        return ""


def threatfox(key: str, post=None) -> str:
    """Indicators from the last 7 days, or "" when ThreatFox can't answer (the build goes on without it)."""
    try:
        answer = _ask(THREATFOX, json.dumps({"query": "get_iocs", "days": 7}).encode(), key, post)
        if answer.get("query_status") != "ok":
            raise ValueError(f"ThreatFox answered {answer.get('query_status')}")
        return json.dumps(answer)
    except Exception as e:
        print(f"ThreatFox left out ({type(e).__name__}: {e})", file=sys.stderr)
        return ""


def spyware(get=None) -> str:
    """Every set in SPYWARE that downloads, as {name: STIX text}; "" when none do."""
    sets = {}
    for name, url in SPYWARE:
        try:
            if get is not None:
                text = get(url)
            else:
                with urllib.request.urlopen(url, timeout=60) as resp:
                    text = resp.read().decode("utf-8")
            json.loads(text)
            sets[name] = text
        except Exception as e:
            print(f"{name} left out ({type(e).__name__}: {e})", file=sys.stderr)
    return json.dumps(sets) if sets else ""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--from", dest="folder", type=Path, help="read the lists from this folder")
    parser.add_argument("--out", type=Path, default=OUT)
    args = parser.parse_args(argv)
    texts = {}
    for name in FILES:
        if args.folder:
            texts[name] = (args.folder / name).read_text(encoding="utf-8")
        else:
            with urllib.request.urlopen(BASE + name, timeout=60) as resp:
                texts[name] = resp.read().decode("utf-8")
    if args.folder and (args.folder / SPY_FILE).exists():
        texts[SPY_FILE] = (args.folder / SPY_FILE).read_text(encoding="utf-8")
    elif not args.folder:
        texts[SPY_FILE] = spyware()
    for name, fetch in ((MB_FILE, malwarebazaar), (TF_FILE, threatfox)):
        if args.folder and (args.folder / name).exists():
            texts[name] = (args.folder / name).read_text(encoding="utf-8")
        elif os.environ.get("ABUSE_CH_KEY"):
            texts[name] = fetch(os.environ["ABUSE_CH_KEY"])
    result = build(texts, datetime.date.today())
    counts = {k: sum(1 for line in result.splitlines() if line.startswith(k + "\t")) for k in "FPCHD"}
    if counts["F"] < 100 or counts["H"] < 1000:  # a broken download must never replace good data
        print(f"Too little data, not written: {counts}", file=sys.stderr)
        return 1
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(result, encoding="utf-8", newline="\n")
    print(f"Wrote {args.out}: {counts['F']} families, {counts['P']} app names, {counts['C']} certificates, "
          f"{counts['H']} fingerprints, {counts['D']} websites" + "".join(f" (with {n})" for n, f in
          (("spyware sets", SPY_FILE), ("MalwareBazaar", MB_FILE), ("ThreatFox", TF_FILE)) if texts.get(f)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
