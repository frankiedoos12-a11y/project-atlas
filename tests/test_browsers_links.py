"""Link checker and ad-spam finder. Browser profiles are fake folders; VirusTotal is faked."""

import json

import pytest

from atlas import browsers
from atlas.links import check_link, local_warnings, normalize
from atlas.scanner import Verdict
from conftest import FakeVT

CLEAN = {"malicious": 0, "suspicious": 0, "harmless": 60, "undetected": 30}


def warnings(url):
    return [reason for verdict, reason in local_warnings(url) if verdict is not Verdict.CLEAN]


# --- Link checker -------------------------------------------------------------------

def test_normalize_adds_scheme():
    assert normalize("  example.com/a ") == "http://example.com/a"
    assert normalize("<https://x.org>") == "https://x.org"


@pytest.mark.parametrize("url, expected", [
    ("http://paypal.com.account-verify.xyz/login", "Mentions paypal"),
    ("https://www.microsoft.com@evil.example/", "hides its real destination"),
    ("http://203.0.113.9/invoice", "bare IP address"),
    ("https://xn--pypal-4ve.com/", "look-alike foreign letters"),
])
def test_scam_tricks_are_spotted(url, expected):
    assert any(expected in w for w in warnings(url))


@pytest.mark.parametrize("url", ["https://www.paypal.com/signin", "https://accounts.google.com/",
                                 "https://www.sans.org/", "https://pineapple.example.com/", "https://bbc.co.uk/news"])
def test_real_sites_are_not_accused(url):
    assert warnings(url) == []


def test_lone_suspicious_vote_is_not_a_warning(store, make_scanner):
    url = "https://www.sans.org/courses/"
    vt = FakeVT(urls={url: {"malicious": 0, "suspicious": 1, "harmless": 60, "undetected": 29}},
                domains={"www.sans.org": CLEAN})
    check = check_link(make_scanner(vt), url)
    assert check.verdict is Verdict.CLEAN
    assert any("usually noise" in r for r in check.reasons)


def test_flagged_link_is_malicious(make_scanner):
    url = "https://bad.example/payload"
    vt = FakeVT(urls={url: {"malicious": 12, "suspicious": 0, "harmless": 50, "undetected": 20}})
    assert check_link(make_scanner(vt), url).verdict is Verdict.MALICIOUS


def test_never_seen_link_and_site_is_unknown(make_scanner):
    check = check_link(make_scanner(FakeVT()), "brand-new-site.example/x")
    assert check.verdict is Verdict.UNKNOWN


def test_new_link_on_known_clean_site_is_clean(make_scanner):
    vt = FakeVT(domains={"github.com": CLEAN})
    check = check_link(make_scanner(vt), "https://github.com/some/new/repo")
    assert check.verdict is Verdict.CLEAN
    assert "has a clean record" in check.reasons[0]


def test_not_a_link():
    assert check_link(None, "http://").verdict is Verdict.ERROR


# --- Ad-spam finder -------------------------------------------------------------------

@pytest.fixture
def chrome(tmp_path, monkeypatch):
    """A fake Chrome 'User Data' folder with one profile."""
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "Local"))
    monkeypatch.setenv("APPDATA", str(tmp_path / "Roaming"))
    profile = tmp_path / "Local" / "Google" / "Chrome" / "User Data" / "Default"
    profile.mkdir(parents=True)
    return profile


def write_prefs(profile, notifications=None, extensions=None, secure_extensions=None):
    prefs = {"profile": {"content_settings": {"exceptions": {"notifications": notifications or {}}}},
             "extensions": {"settings": extensions or {}}, "other": {"kept": True}}
    (profile / "Preferences").write_text(json.dumps(prefs), encoding="utf-8")
    (profile / "Secure Preferences").write_text(json.dumps({"extensions": {"settings": secure_extensions or {}}}),
                                                encoding="utf-8")


def test_only_allowed_notification_sites_are_listed(chrome):
    write_prefs(chrome, notifications={
        "https://news-alerts.example:443,*": {"setting": 1, "last_modified": "1"},
        "https://blocked.example:443,*": {"setting": 2, "last_modified": "1"},
    })
    sites = browsers.notification_sites()
    assert [(s.site, s.host, s.profile.label) for s in sites] == [
        ("https://news-alerts.example:443", "news-alerts.example", "Chrome")]


def test_sites_are_judged_once_per_domain(chrome, make_scanner):
    write_prefs(chrome, notifications={
        "https://spam.example:443,*": {"setting": 1},
        "http://spam.example:80,*": {"setting": 1},
    })
    vt = FakeVT(domains={"spam.example": {"malicious": 6, "suspicious": 0, "harmless": 40, "undetected": 40}})
    sites = browsers.notification_sites()
    browsers.judge_sites(sites, make_scanner(vt))
    assert [s.verdict for s in sites] == ["suspicious", "suspicious"]
    assert vt.calls == [("domain", "spam.example")]


def test_block_notifications_backs_up_and_flips_the_setting(chrome, tmp_path):
    write_prefs(chrome, notifications={"https://spam.example:443,*": {"setting": 1, "last_modified": "1"}})
    (site,) = browsers.notification_sites()
    backup = browsers.block_notifications(site, tmp_path / "backups", running=set())
    prefs = json.loads((chrome / "Preferences").read_text(encoding="utf-8"))
    assert prefs["profile"]["content_settings"]["exceptions"]["notifications"]["https://spam.example:443,*"]["setting"] == 2
    assert prefs["other"] == {"kept": True}
    assert json.loads(backup.read_text(encoding="utf-8"))["profile"]["content_settings"]["exceptions"][
        "notifications"]["https://spam.example:443,*"]["setting"] == 1
    assert browsers.notification_sites() == []


def test_block_refuses_while_the_browser_is_open(chrome, tmp_path):
    write_prefs(chrome, notifications={"https://spam.example:443,*": {"setting": 1}})
    (site,) = browsers.notification_sites()
    with pytest.raises(PermissionError, match="Close Chrome first"):
        browsers.block_notifications(site, tmp_path / "backups", running={"chrome.exe"})
    assert not (tmp_path / "backups").exists()


def ext(location, name="Thing", from_webstore=True, **manifest):
    return {"location": location, "from_webstore": from_webstore, "state": 1, "path": "x\\1.0_0",
            "manifest": {"name": name, "version": "1.0", **manifest}}


def test_extension_adware_signs(chrome):
    write_prefs(chrome, secure_extensions={
        "store": ext(1, "Store Tool", permissions=["storage"]),
        "bundled": ext(6, "Acrobat", host_permissions=["<all_urls>"]),
        "sideloaded": ext(6, "Search Helper Pro", from_webstore=False),
        "hijack": ext(1, "Cool Tab", chrome_url_overrides={"newtab": "tab.html"},
                      chrome_settings_overrides={"search_provider": {"search_url": "https://ads.example/?q={searchTerms}"}}),
        "policy": ext(7, "Forced"),
        "unpacked": ext(4, "My Dev Ext"),
        "builtin": ext(5, "PDF Viewer"),
    })
    found = {e.name: e for e in browsers.extensions()}
    assert "PDF Viewer" not in found
    assert not found["Store Tool"].needs_look
    assert not found["Acrobat"].needs_look and any("every website" in n for n in found["Acrobat"].notes)
    assert "Added by another program, from outside the store" in found["Search Helper Pro"].concerns
    assert {"Replaces your new tab page", "Changes your search engine"} <= set(found["Cool Tab"].concerns)
    assert found["Forced"].needs_look and found["My Dev Ext"].needs_look
    assert all(e.needs_look for e in browsers.extensions()[:4])  # needs-a-look ones sort first


def test_extension_name_from_locale_files(chrome):
    folder = chrome / "Extensions" / "abc" / "2.0_0"
    (folder / "_locales" / "en").mkdir(parents=True)
    (folder / "_locales" / "en" / "messages.json").write_text(json.dumps({"appName": {"message": "Real Name"}}),
                                                              encoding="utf-8")
    (folder / "manifest.json").write_text(json.dumps({"name": "__MSG_appName__", "version": "2.0"}),
                                          encoding="utf-8")
    write_prefs(chrome, secure_extensions={"abc": {"location": 1, "path": "abc\\2.0_0", "state": 0}})
    (e,) = browsers.extensions()
    assert e.name == "Real Name" and not e.enabled
