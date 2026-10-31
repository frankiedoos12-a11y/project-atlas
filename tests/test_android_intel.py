"""The Android app's threat data builder (android/tools/build_intel.py)."""

import datetime
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


def test_malwarebazaar_key_goes_only_in_the_header(capsys):
    sent = []

    def post(request):
        sent.append(request)
        return '{"query_status": "ok", "data": []}'

    assert build_intel.malwarebazaar("secret-key", post) == '{"query_status": "ok", "data": []}'
    assert sent[0].get_header("Auth-key") == "secret-key" and b"secret-key" not in sent[0].data
    assert build_intel.malwarebazaar("bad", lambda r: '{"query_status": "unknown_auth_key"}') == ""

    def offline(request):
        raise OSError("no network")

    assert build_intel.malwarebazaar("secret-key", offline) == ""
    assert "secret-key" not in capsys.readouterr().err
