"""v0.12: the message check reads email files (.eml, .msg) and screenshots."""

import io
import sys
import types
from email.message import EmailMessage
from pathlib import Path

from atlas import emailcheck, ocr, scam
from tests.conftest import FakeVT


def scam_email(tmp_path: Path, **headers) -> Path:
    msg = EmailMessage()
    msg["From"] = headers.get("sender", '"Microsoft Support" <billing@ms-renewal-desk.top>')
    msg["To"] = "you@example.com"
    msg["Subject"] = "Your subscription has been renewed"
    if "reply_to" in headers:
        msg["Reply-To"] = headers["reply_to"]
    msg["Authentication-Results"] = headers.get("auth", "mx.example.com; spf=fail smtp.mailfrom=ms-renewal-desk.top; "
                                                        "dkim=none; dmarc=fail header.from=ms-renewal-desk.top")
    msg.set_content("Your order was renewed. Call 1-888-555-0142 to cancel.")
    msg.add_alternative('<p>Your order was renewed.</p><a href="https://evil-login.example/ms">'
                        'https://account.microsoft.com/billing</a><a href="https://nam12.safelinks.protection.'
                        'outlook.com/?url=https%3A%2F%2Fpaypa1-help.example%2Fx&data=1">www.paypal.com</a>',
                        subtype="html")
    msg.add_attachment(b"<html>sign in</html>", maintype="text", subtype="html", filename="Invoice.html")
    path = tmp_path / "renewal.eml"
    path.write_bytes(bytes(msg))
    return path


def test_eml_is_read_with_links_sender_and_attachments(tmp_path):
    msg = emailcheck.read_email(scam_email(tmp_path))
    assert msg.sender_name == "Microsoft Support" and msg.sender_address == "billing@ms-renewal-desk.top"
    assert ("https://evil-login.example/ms", "https://account.microsoft.com/billing") in msg.anchors
    assert [a.name for a in msg.attachments] == ["Invoice.html"]
    assert "spf=fail" in msg.auth


def test_scam_email_is_called_a_scam(tmp_path):
    result = emailcheck.check_email(scam_email(tmp_path))
    titles = {r.title for r in result.reasons}
    assert result.verdict == scam.SCAM
    assert {"Sender pretends to be a company", "The link isn't what it says", "Failed the sender checks",
            "Risky attachment", "Call this number"} <= titles
    mismatch = [r.why for r in result.reasons if r.title == "The link isn't what it says"]
    assert any("paypa1-help.example" in w for w in mismatch)  # Safe Links unwrapped
    assert ("Attachments", "Invoice.html") in result.about


def test_real_company_from_its_own_domain_is_fine(tmp_path):
    path = scam_email(tmp_path, sender='"Microsoft account team" <account-security-noreply@accountprotection.'
                                       'microsoft.com>', auth="mx.example.com; spf=pass; dkim=pass; dmarc=pass")
    reasons = emailcheck.sender_reasons(emailcheck.read_email(path))
    assert reasons == []


def test_free_address_and_reply_to(tmp_path):
    msg = emailcheck.read_email(scam_email(tmp_path, sender='"PayPal Service" <paypal.help4u@gmail.com>',
                                           reply_to="refunds@other-desk.example", auth=""))
    titles = {r.title: r.why for r in emailcheck.sender_reasons(msg)}
    assert "free gmail.com address" in titles["Sender pretends to be a company"]
    assert "Replies go somewhere else" in titles


def test_newsletter_trackers_are_not_mismatches():
    anchors = [("https://click.list-manage.com/track?u=1", "www.shop.example"),
               ("https://shop.example/sale", "shop.example/sale"), ("mailto:x@y.example", "y.example")]
    assert emailcheck.link_mismatches(anchors, "shop.example") == []


def test_attachment_fingerprint_goes_to_virustotal(tmp_path, make_scanner):
    path = scam_email(tmp_path)
    sha = emailcheck.read_email(path).attachments[0].sha256
    vt = FakeVT(files={sha: {"malicious": 20}})
    reasons = emailcheck.attachment_reasons(emailcheck.read_email(path), make_scanner(vt))
    assert any(r.title == "Dangerous attachment" for r in reasons)
    assert ("file", sha) in vt.calls


class FakeOle:
    """olefile.OleFileIO over a dict of stream name -> bytes."""

    def __init__(self, streams):
        self.streams = streams

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def exists(self, name):
        return name in self.streams

    def openstream(self, name):
        return io.BytesIO(self.streams[name])

    def listdir(self, streams=True, storages=False):
        return sorted({tuple(n.split("/")[:1]) for n in self.streams if "/" in n})


def test_outlook_msg_is_read(tmp_path, monkeypatch):
    u = lambda text: text.encode("utf-16-le")  # noqa: E731
    headers = ('From: "Amazon" <orders@amaz0n-support.example>\r\nSubject: Order problem\r\n'
               'Authentication-Results: mx.outlook.com; dmarc=fail\r\n\r\n')
    streams = {"__substg1.0_007D001F": u(headers), "__substg1.0_1000001F": u("Verify your order at once."),
               "__substg1.0_10130102": b'<a href="https://amaz0n-support.example/v">amazon.com</a>',
               "__attach_version1.0_#00000000/__substg1.0_3707001F": u("label.zip"),
               "__attach_version1.0_#00000000/__substg1.0_37010102": b"PK\x03\x04"}
    monkeypatch.setitem(sys.modules, "olefile", types.SimpleNamespace(OleFileIO=lambda p: FakeOle(streams)))
    path = tmp_path / "order.msg"
    path.write_bytes(b"x")
    msg = emailcheck.read_email(path)
    assert msg.sender_name == "Amazon" and msg.subject == "Order problem" and "dmarc=fail" in msg.auth
    assert msg.anchors == [("https://amaz0n-support.example/v", "amazon.com")]
    assert [(a.name, a.data) for a in msg.attachments] == [("label.zip", b"PK\x03\x04")]


def test_screenshot_is_shrunk_before_reading(monkeypatch):
    from PIL import Image

    saved = []
    monkeypatch.setattr(ocr.sys, "platform", "win32")
    monkeypatch.setattr(ocr.subprocess, "run", lambda *a, **k: saved.append(Image.open(k["env"]["ATLAS_OCR_IMAGE"])
                                                                            .size) or types.SimpleNamespace(
        returncode=0, stdout="Call now\r\n".encode(), stderr=b""))
    assert ocr.read_image(Image.new("RGB", (9000, 3000))) == "Call now"
    assert max(saved[0]) == ocr.MAX_SIDE


def test_fake_security_popup_is_a_scam():
    popup = scam.check_message("Windows Defender Security Alert\nYour PC is blocked. Do not restart.\n"
                               "Call Microsoft Support: +1 (888) 555-0142")
    assert popup.verdict == scam.SCAM and "Fake security pop-up" in {r.title for r in popup.reasons}
    notice = scam.check_message("Your Microsoft account security info was updated. If this was you, no action "
                                "is needed.")
    assert notice.verdict == scam.NOTHING
