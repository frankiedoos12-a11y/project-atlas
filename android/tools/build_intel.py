"""Builds the Android app's threat data (app/src/main/assets/intel.txt) from public lists.

Source: Stalkerware indicators by Echap (CC BY 4.0), https://github.com/AssoEchap/stalkerware-indicators
  - ioc.yaml: stalkerware families, their app names, signing certificates, websites and servers
  - watchware.yaml: monitoring ("parental control") apps that let someone else watch the phone
  - samples.csv: fingerprints (SHA-256) of known stalkerware app files

Optional source: MalwareBazaar by abuse.ch (CC0), https://bazaar.abuse.ch
  - the newest Android app samples (up to 1,000), named by malware family. It needs a free abuse.ch account key, read
    from the ABUSE_CH_KEY environment variable (a repository secret in the weekly workflow), never from a file here.

Stdlib only. Run with no arguments to download the lists, or --from DIR to read them from a folder (which may hold a
saved MalwareBazaar answer as malwarebazaar.json).
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
import urllib.request
from pathlib import Path

BASE = "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/"
FILES = ("ioc.yaml", "watchware.yaml", "samples.csv")
MALWAREBAZAAR = "https://mb-api.abuse.ch/api/v1/"
MB_FILE = "malwarebazaar.json"
OUT = Path(__file__).resolve().parent.parent / "app" / "src" / "main" / "assets" / "intel.txt"
FORMAT = 1
# Shared hosting: listing the whole domain would flag everyone who uses it.
SHARED = {"google.com", "googleapis.com", "firebaseio.com", "firebaseapp.com", "amazonaws.com", "github.com",
          "github.io", "cloudfront.net", "appspot.com", "herokuapp.com", "blogspot.com", "wordpress.com",
          "web.app", "000webhostapp.com", "azurewebsites.net", "play.google.com", "t.me", "youtube.com"}
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

    mb = texts.get(MB_FILE)
    if mb:
        named: dict[str, int] = {}
        for sample in json.loads(mb).get("data") or []:
            digest = str(sample.get("sha256_hash") or "").lower()
            if not SHA256.match(digest) or digest in rows["H"]:
                continue  # already known as stalkerware: that's the more useful name
            name = " ".join(str(sample.get("signature") or "").split()) or "Unnamed Android malware"
            if name not in named:
                named[name] = len(families)
                families.append((name, "malware"))
            add("H", digest, named[name])

    out = [f"# atlas-intel {FORMAT}", f"# version {today:%Y%m%d}",
           "# source: Stalkerware indicators by Echap, CC BY 4.0, https://github.com/AssoEchap/stalkerware-indicators"]
    if mb:
        out.append("# source: MalwareBazaar by abuse.ch, CC0, https://bazaar.abuse.ch")
    out += [f"F\t{i}\t{name}\t{kind}" for i, (name, kind) in enumerate(families)]
    for kind in ("P", "C", "H", "D"):
        out += [f"{kind}\t{value}\t{fid}" for value, fid in sorted(rows[kind].items())]
    return "\n".join(out) + "\n"


def malwarebazaar(key: str, post=None) -> str:
    """The newest Android app samples, or "" when MalwareBazaar can't answer (the build goes on without them)."""
    request = urllib.request.Request(MALWAREBAZAAR, data=b"query=get_file_type&file_type=apk&limit=1000",
                                     headers={"Auth-Key": key, "User-Agent": "Project-Atlas"})
    try:
        if post is not None:
            body = post(request)
        else:
            with urllib.request.urlopen(request, timeout=60) as resp:
                body = resp.read().decode("utf-8")
        status = json.loads(body).get("query_status")
        if status != "ok":
            raise ValueError(f"MalwareBazaar answered {status}")
        return body
    except Exception as e:  # only the error's name and message: never the request, which carries the key
        print(f"MalwareBazaar left out ({type(e).__name__}: {e})", file=sys.stderr)
        return ""


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
    if args.folder and (args.folder / MB_FILE).exists():
        texts[MB_FILE] = (args.folder / MB_FILE).read_text(encoding="utf-8")
    elif os.environ.get("ABUSE_CH_KEY"):
        texts[MB_FILE] = malwarebazaar(os.environ["ABUSE_CH_KEY"])
    result = build(texts, datetime.date.today())
    counts = {k: sum(1 for line in result.splitlines() if line.startswith(k + "\t")) for k in "FPCHD"}
    if counts["F"] < 100 or counts["H"] < 1000:  # a broken download must never replace good data
        print(f"Too little data, not written: {counts}", file=sys.stderr)
        return 1
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(result, encoding="utf-8", newline="\n")
    print(f"Wrote {args.out}: {counts['F']} families, {counts['P']} app names, {counts['C']} certificates, "
          f"{counts['H']} fingerprints, {counts['D']} websites" + (" (with MalwareBazaar)" if texts.get(MB_FILE) else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
