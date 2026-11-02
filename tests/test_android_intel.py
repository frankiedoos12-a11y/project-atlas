"""The Android app's threat data builder (android/tools/build_intel.py)."""

import datetime
import json
import importlib.util
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "build_intel", Path(__file__).resolve().parent.parent / "android" / "tools" / "build_intel.py")
build_intel = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(build_intel)

IOC = """- name: TheTruthSpy
  names:
  - Copy9
  type: stalkerware
  packages:
  - com.thetruth
  certificates:
  - 31a6ececd97cf39bc4126b8745cd94a7c30bf81c
  - not-a-hash
  websites:
  - thetruthspy.com
  - firebaseio.com # shared hosting: never listed whole
  c2:
    ips:
    - 1.2.3.4
    domains:
    - api.thetruthspy.com
    - "*.copy9.com"

- name: Another
  type: stalkerware
  packages:
  - com.another
"""
WATCH = """- name: FamiSafe
  type: watchware
  packages:
  - com.wondershare.famisafe
"""
SAMPLES = """SHA256,Package Name,Certificate,Version,App
2F3BC9EBE8C249F0416F5B0367F34B4B8F6AAA7D351DC5B4912FE2558491B6B7,com.thetruth.v2,ABCDEF0123456789ABCDEF0123456789ABCDEF01,9,Copy9
1111111111111111111111111111111111111111111111111111111111111111,com.newone,,1,BrandNew
"""


def test_builds_the_phone_format():
    text = build_intel.build({"ioc.yaml": IOC, "watchware.yaml": WATCH, "samples.csv": SAMPLES},
                             datetime.date(2026, 10, 30))
    lines = text.splitlines()
    assert lines[:2] == ["# atlas-intel 1", "# version 20261030"]
    assert "F\t0\tTheTruthSpy\tstalkerware" in lines
    assert "F\t2\tFamiSafe\twatchware" in lines
    assert "F\t3\tBrandNew\tstalkerware" in lines  # a sample of a family the lists don't name yet
    assert "C\t31A6ECECD97CF39BC4126B8745CD94A7C30BF81C\t0" in lines
    assert "C\tABCDEF0123456789ABCDEF0123456789ABCDEF01\t0" in lines  # "Copy9" is TheTruthSpy's other name
    assert "H\t2f3bc9ebe8c249f0416f5b0367f34b4b8f6aaa7d351dc5b4912fe2558491b6b7\t0" in lines
    assert "P\tcom.wondershare.famisafe\t2" in lines
    domains = [line.split("\t")[1] for line in lines if line.startswith("D\t")]
    assert domains == ["api.thetruthspy.com", "copy9.com", "thetruthspy.com"]
    assert not any("not-a-hash" in line or "1.2.3.4" in line for line in lines)


def test_too_little_data_is_never_written(tmp_path):
    for name, text in (("ioc.yaml", IOC), ("watchware.yaml", WATCH), ("samples.csv", SAMPLES)):
        (tmp_path / name).write_text(text, encoding="utf-8")
    out = tmp_path / "intel.txt"
    assert build_intel.main(["--from", str(tmp_path), "--out", str(out)]) == 1
    assert not out.exists()


MB = """{"query_status": "ok", "data": [
 {"sha256_hash": "AAAA111111111111111111111111111111111111111111111111111111111111", "signature": "SpyNote"},
 {"sha256_hash": "bbbb222222222222222222222222222222222222222222222222222222222222", "signature": "SpyNote"},
 {"sha256_hash": "cccc333333333333333333333333333333333333333333333333333333333333", "signature": null},
 {"sha256_hash": "2f3bc9ebe8c249f0416f5b0367f34b4b8f6aaa7d351dc5b4912fe2558491b6b7", "signature": "Other"},
 {"sha256_hash": "not-a-hash", "signature": "Junk"}]}"""


def test_malwarebazaar_samples_are_added_by_family():
    text = build_intel.build({"ioc.yaml": IOC, "watchware.yaml": WATCH, "samples.csv": SAMPLES,
                              build_intel.MB_FILE: MB}, datetime.date(2026, 10, 30))
    lines = text.splitlines()
    assert "# source: MalwareBazaar by abuse.ch, CC0, https://bazaar.abuse.ch" in lines
    assert "F\t4\tSpyNote\tmalware" in lines and "F\t5\tUnnamed Android malware\tmalware" in lines
    assert "H\taaaa111111111111111111111111111111111111111111111111111111111111\t4" in lines
    assert "H\tcccc333333333333333333333333333333333333333333333333333333333333\t5" in lines
    # A sample the stalkerware list already names keeps that name; "Other" and junk add nothing.
    assert "H\t2f3bc9ebe8c249f0416f5b0367f34b4b8f6aaa7d351dc5b4912fe2558491b6b7\t0" in lines
    assert not any("Other" in line or "Junk" in line for line in lines)


def test_malwarebazaar_asks_for_android_families_and_keeps_the_key_in_the_header(capsys):
    sent = []

    def post(request):
        sent.append(request)
        body = request.data.decode()
        if "get_file_type" in body:
            return json.dumps({"query_status": "ok", "data": [{"sha256_hash": "a" * 64, "file_type": "apk"}]})
        if "signature=SpyNote" in body:
            return json.dumps({"query_status": "ok", "data": [
                {"sha256_hash": "a" * 64, "file_type": "apk"},  # already there
                {"sha256_hash": "b" * 64, "file_type": "apk", "signature": "SpyNote"},
                {"sha256_hash": "c" * 64, "file_type": "exe", "signature": "SpyNote"}]})
        return '{"query_status": "signature_not_found"}'

    answer = json.loads(build_intel.malwarebazaar("secret-key", post))
    assert [s["sha256_hash"] for s in answer["data"]] == ["a" * 64, "b" * 64]
    assert len(sent) == 1 + len(build_intel.ANDROID_FAMILIES)
    assert all(r.get_header("Auth-key") == "secret-key" and b"secret-key" not in r.data for r in sent)
    assert build_intel.malwarebazaar("bad", lambda r: '{"query_status": "unknown_auth_key"}') == ""

    def offline(request):
        raise OSError("no network")

    assert build_intel.malwarebazaar("secret-key", offline) == ""
    assert build_intel.threatfox("secret-key", offline) == ""
    assert "secret-key" not in capsys.readouterr().err


TF = json.dumps({"query_status": "ok", "data": [
    {"ioc": "evil-c2.example", "ioc_type": "domain", "malware_printable": "SpyNote", "confidence_level": 100},
    {"ioc": "maybe.example", "ioc_type": "domain", "malware_printable": "X", "confidence_level": 50},
    {"ioc": "duckdns.org", "ioc_type": "domain", "malware_printable": "X", "confidence_level": 100},
    {"ioc": "1.2.3.4:443", "ioc_type": "ip:port", "malware_printable": "X", "confidence_level": 100},
    {"ioc": "thetruthspy.com", "ioc_type": "domain", "malware_printable": "X", "confidence_level": 100}]})


def test_threatfox_domains_join_their_malware_family():
    text = build_intel.build({"ioc.yaml": IOC, "watchware.yaml": WATCH, "samples.csv": SAMPLES,
                              build_intel.MB_FILE: MB, build_intel.TF_FILE: TF}, datetime.date(2026, 10, 31))
    lines = text.splitlines()
    assert "# source: ThreatFox by abuse.ch, CC0, https://threatfox.abuse.ch" in lines
    assert "D	evil-c2.example	4" in lines  # the same SpyNote family as MalwareBazaar's samples
    assert "D	thetruthspy.com	0" in lines  # the stalkerware list named it first
    assert not any("maybe.example" in l or "duckdns.org" in l or "1.2.3.4" in l for l in lines)
    assert not any(l.startswith("F	") and l.split("	")[2] == "X" for l in lines)


def test_commercial_spyware_sets_keep_what_a_phone_can_check():
    stix = json.dumps({"type": "bundle", "objects": [
        {"type": "malware", "name": "Pegasus"},
        {"type": "indicator", "pattern": "[domain-name:value = 'free247downloads.com']"},
        {"type": "indicator", "pattern": "[domain-name:value = 'google.com']"},  # shared: never listed whole
        {"type": "indicator", "pattern": "[app:id = 'com.spy.helper']"},
        {"type": "indicator", "pattern": "[file:hashes.sha256 = '" + "AB" * 32 + "']"},
        {"type": "indicator", "pattern": "[process:name = 'bh']"},  # needs the whole phone: left out
    ]})
    text = build_intel.build({"ioc.yaml": IOC, "watchware.yaml": WATCH, "samples.csv": SAMPLES,
                              build_intel.SPY_FILE: json.dumps({"Pegasus (NSO Group)": stix})},
                             datetime.date(2026, 10, 31))
    lines = text.splitlines()
    fid = next(line.split("\t")[1] for line in lines if line.endswith("\tPegasus (NSO Group)\tspyware"))
    assert f"D\tfree247downloads.com\t{fid}" in lines
    assert f"P\tcom.spy.helper\t{fid}" in lines
    assert f"H\t{'ab' * 32}\t{fid}" in lines
    assert not any(line.startswith("D\tgoogle.com") for line in lines)
    assert any("Amnesty International" in line for line in lines if line.startswith("# source: "))


def test_spyware_sets_that_fail_to_download_are_left_out(capsys):
    good = json.dumps({"objects": []})

    def get(url):
        if "pegasus" in url:
            raise OSError("down")
        return good

    sets = json.loads(build_intel.spyware(get))
    assert "Pegasus (NSO Group)" not in sets and "Predator (Intellexa)" in sets
    assert "Pegasus (NSO Group) left out" in capsys.readouterr().err
