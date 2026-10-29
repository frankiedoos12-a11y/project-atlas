"""v0.11.1: brands' own domains, trusted sites, the shared allow-list and "Report a mistake"."""

from urllib.parse import parse_qs, urlparse

import pytest

from atlas import allowlist, config, links, mistakes
from atlas.links import check_link, local_warnings
from atlas.nativehost import handle
from atlas.scanner import Verdict
from tests.conftest import FakeVT


def test_brands_own_domains_are_not_look_alikes():
    assert local_warnings("https://outlook.live.com/mail/0/") == []
    assert local_warnings("https://login.microsoftonline.com/") == []
    assert local_warnings("https://apple.icloud.com/") == []
    fake = local_warnings("https://outlook.live-mail-check.xyz/")
    assert any("Mentions outlook" in r for _, r in fake)


def test_trusted_site_skips_atlas_guesses_but_not_virustotal(make_scanner):
    vt = FakeVT(domains={"paypal.example-pay.com": {"malicious": 0, "harmless": 60}})
    scanner = make_scanner(vt, trusted_sites=["example-pay.com"])
    check = check_link(scanner, "https://paypal.example-pay.com/")
    assert check.verdict is Verdict.CLEAN
    assert any("You trust example-pay.com" in r for r in check.reasons)
    vt = FakeVT(urls={"https://paypal.example-pay.com/bad": {"malicious": 9}})
    check = check_link(make_scanner(vt, trusted_sites=["example-pay.com"]), "https://paypal.example-pay.com/bad")
    assert check.verdict is Verdict.MALICIOUS  # VirusTotal's engines still count


def test_untrusted_look_alike_still_warns(make_scanner):
    check = check_link(make_scanner(FakeVT()), "https://paypal.example-pay.com/")
    assert check.verdict is Verdict.SUSPICIOUS


def test_shared_allow_list_counts(make_scanner, monkeypatch):
    monkeypatch.setattr(allowlist, "shared_sites", lambda store=None: {"example-pay.com": "Example Pay"})
    check = check_link(make_scanner(FakeVT()), "https://paypal.example-pay.com/")
    assert check.verdict is not Verdict.SUSPICIOUS
    assert any("allow-list (Example Pay)" in r for r in check.reasons)
    off = check_link(make_scanner(FakeVT(), shared_allowlist=False), "https://paypal.example-pay.com/")
    assert off.verdict is Verdict.SUSPICIOUS


def test_trust_site_saves_the_whole_domain():
    assert allowlist.trust_site("Outlook.Live.com") == "live.com"
    allowlist.trust_site("mail.live.com")
    assert config.Settings.load().trusted_sites == ["live.com"]
    allowlist.untrust_site("live.com")
    assert config.Settings.load().trusted_sites == []
    for bad in ("", "localhost", "192.168.1.1", "co.uk", "x"):
        with pytest.raises(ValueError):
            allowlist.trust_site(bad)


def test_shared_list_keeps_only_real_domains():
    assert allowlist._clean({"sites": {"live.com": "Microsoft", "www.live.com": "x", "not a domain": "x",
                                       "LIVE.org": "y"}}) == {"live.com": "Microsoft", "live.org": "y"}
    assert allowlist._clean(["live.com"]) == {}


def test_shared_list_is_cached_and_survives_being_offline(store, monkeypatch):
    import importlib

    real = importlib.reload(allowlist)  # the un-faked function
    answers = [{"sites": {"live.com": "Microsoft"}}]

    class Resp:
        def raise_for_status(self):
            pass

        def json(self):
            return answers[0]

    calls = []
    monkeypatch.setattr(real.requests, "get", lambda url, timeout: calls.append(url) or Resp())
    assert real.shared_sites(store) == {"live.com": "Microsoft"}
    assert real.shared_sites(store) == {"live.com": "Microsoft"} and len(calls) == 1  # a day's cache
    assert calls[0].endswith("/main/allowlist.json")


def test_browser_helper_trusts_and_offers_a_report(make_scanner):
    scanner = make_scanner(FakeVT())
    reply = handle({"type": "check", "url": "https://paypal.example-pay.com/login?token=SECRET"}, scanner)
    assert reply["verdict"] == "suspicious"
    report = parse_qs(urlparse(reply["report"]).query)
    assert report["what"] == ["paypal.example-pay.com"] and report["template"] == ["false-positive.yml"]
    assert "SECRET" not in reply["report"] and "/login" not in report["what"][0]
    assert handle({"type": "trust", "host": "paypal.example-pay.com"}, scanner) == {"ok": True,
                                                                                    "site": "example-pay.com"}
    assert handle({"type": "check", "url": "https://paypal.example-pay.com/"}, scanner)["verdict"] != "suspicious"
    assert handle({"type": "trust", "host": "localhost"}, scanner)["ok"] is False


def test_reports_leave_out_the_user_folder(monkeypatch, tmp_path):
    home = tmp_path / "Frankie"
    monkeypatch.setattr(mistakes.os.path, "expanduser", lambda p: str(home))
    monkeypatch.setenv("USERNAME", "Frankie")
    url = mistakes.issue_url("File", "tool.exe", "suspicious", [f"Found in {home}\\Downloads\\tool.exe",
                                                                "Signed by Frankie"])
    reasons = parse_qs(urlparse(url).query)["reasons"][0]
    assert "Frankie" not in reasons and "%USERPROFILE%\\Downloads" in reasons
    assert mistakes.email_url("File", "x", "y", []) is None  # no report address yet


def test_site_subject_is_just_the_host():
    assert mistakes.site_subject("https://user@outlook.live.com:443/mail/0/?x=1") == "outlook.live.com"


def test_brand_domains_cover_every_brand_they_name():
    assert set(links.BRAND_DOMAINS) <= links.BRANDS
