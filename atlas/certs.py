"""Root certificates: has anything taught Windows to trust a certificate authority it shouldn't?

A root certificate in the Trusted Root store lets whoever holds its private key fake any website,
bank and Microsoft included, without a browser warning. Adware and "privacy" tools have installed
their own (Superfish, eDellRoot, PrivDog) to read and inject into HTTPS pages.

Atlas compares every root in your account and the machine's store with Microsoft's own trusted root
list, which Windows keeps in the registry and updates by itself. Roots that aren't on it are
listed with what they belong to; recently added ones, and ones Microsoft has explicitly distrusted,
need a look.
"""

from __future__ import annotations

import ctypes
import logging
import re
import struct
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from atlas.findings import NOTE, OK, WARN, Finding

log = logging.getLogger(__name__)

STORES = [("HKCU", r"Software\Microsoft\SystemCertificates\Root\Certificates", "your account"),
          ("HKLM", r"SOFTWARE\Microsoft\SystemCertificates\Root\Certificates", "this PC"),
          ("HKLM", r"SOFTWARE\Policies\Microsoft\SystemCertificates\Root\Certificates", "a Windows policy"),
          ("HKCU", r"Software\Policies\Microsoft\SystemCertificates\Root\Certificates", "a policy in your account")]
AUTOUPDATE = r"SOFTWARE\Microsoft\SystemCertificates\AuthRoot\AutoUpdate"
# Roots that Windows itself installs outside the auto-updated list.
WINDOWS_BUILTIN = {"245C97DF7514E7CF2DF8BE72AE957B9E04741E85",  # Copyright (c) 1997 Microsoft Corp.
                   "7F88CD7223F3C813818C994614A89C99FA3B5247",  # Microsoft Authenticode(tm) Root Authority
                   "D1EB23A46D17D68FD92564C2F1F1601764D8E349"}  # AAA Certificate Services (Comodo/Sectigo)
KNOWN_BAD = re.compile(r"superfish|edellroot|dsdtestprovider|komodia|privdog|sendori|wajam|"
                       r"lenovo.*(visual|discovery)|do_not_trust(?!_fiddler)", re.I)
INSPECTION_TOOLS = re.compile(r"fiddler|mitmproxy|charles proxy|portswigger|burp|httptoolkit|http toolkit|"
                              r"mkcert|proxyman|telerik|zscaler|netskope|cisco umbrella", re.I)
ANTIVIRUS = re.compile(r"avast|avg|kaspersky|eset|bitdefender|norton|symantec|mcafee|sophos|trend ?micro|"
                       r"f-secure|webroot|emsisoft|malwarebytes|adguard|gdata|g data|panda|comodo internet security|"
                       r"360 ", re.I)
# Government and military PKI roots, installed by tools like DoD InstallRoot for CAC sign-in and .mil sites.
GOVERNMENT = re.compile(r"\bdod (root|interoperability)|federal (common policy|bridge)|u\.?s\.? government|"
                        r"\beca root|department of (defense|state|the treasury)", re.I)
DEVELOPER = re.compile(r"localhost|iis express|asp\.net core https|development|dev cert|vscode|docker", re.I)
RECENT_DAYS = 30


@dataclass
class RootCert:
    thumbprint: str
    subject: str
    issuer: str
    where: str  # "your account", "this PC", ...
    added: datetime | None  # when its registry entry was last written


def microsoft_list() -> tuple[set[str], set[str]]:
    """(trusted, distrusted) SHA-1 thumbprints from the lists Windows keeps up to date."""
    if sys.platform != "win32":
        return set(), set()
    import winreg

    def thumbprints(value: str) -> set[str]:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, AUTOUPDATE) as key:
                blob = winreg.QueryValueEx(key, value)[0]
        except OSError:
            return set()
        return parse_ctl(blob)

    return thumbprints("EncodedCtl"), thumbprints("DisallowedCertEncodedCtl")


def parse_ctl(blob: bytes) -> set[str]:
    """The SHA-1 thumbprints in a Microsoft certificate trust list (each is a 20-byte OCTET STRING)."""
    return {m.group(1).hex().upper() for m in re.finditer(rb"\x04\x14(.{20})", blob, re.S)}


def _der(blob: bytes) -> bytes | None:
    """The certificate inside a registry "Blob" value (a list of id/length/data properties)."""
    i = 0
    while i + 12 <= len(blob):
        prop, _, size = struct.unpack_from("<III", blob, i)
        if prop == 32:  # CERT_CERT_PROP_ID
            return blob[i + 12:i + 12 + size]
        i += 12 + size
    return None


def _names(der: bytes) -> tuple[str, str]:
    crypt32 = ctypes.windll.crypt32
    crypt32.CertCreateCertificateContext.restype = ctypes.c_void_p
    crypt32.CertCreateCertificateContext.argtypes = [ctypes.c_uint32, ctypes.c_char_p, ctypes.c_uint32]
    crypt32.CertGetNameStringW.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
                                           ctypes.c_wchar_p, ctypes.c_uint32]
    crypt32.CertFreeCertificateContext.argtypes = [ctypes.c_void_p]
    ctx = crypt32.CertCreateCertificateContext(0x10001, der, len(der))  # X509_ASN | PKCS_7_ASN
    if not ctx:
        return "?", "?"
    try:
        out = []
        for flags in (0, 1):  # subject, issuer
            buf = ctypes.create_unicode_buffer(512)
            crypt32.CertGetNameStringW(ctx, 4, flags, None, buf, 512)  # CERT_NAME_SIMPLE_DISPLAY_TYPE
            out.append(buf.value or "?")
        return out[0], out[1]
    finally:
        crypt32.CertFreeCertificateContext(ctx)


def installed_roots() -> list[RootCert]:
    if sys.platform != "win32":
        return []
    import winreg

    hives = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}
    found = []
    for hive, path, where in STORES:
        try:
            store = winreg.OpenKey(hives[hive], path)
        except OSError:
            continue
        with store:
            for i in range(winreg.QueryInfoKey(store)[0]):
                thumb = winreg.EnumKey(store, i).upper()
                try:
                    with winreg.OpenKey(store, thumb) as key:
                        blob = winreg.QueryValueEx(key, "Blob")[0]
                        written = winreg.QueryInfoKey(key)[2]  # 100 ns intervals since 1601
                except OSError:
                    continue
                der = _der(blob)
                subject, issuer = _names(der) if der else ("?", "?")
                added = datetime(1601, 1, 1) + timedelta(microseconds=written // 10) if written else None
                found.append(RootCert(thumb, subject, issuer, where, added))
    return found


def judge(roots: list[RootCert], trusted: set[str], distrusted: set[str], now: datetime | None = None) -> list[Finding]:
    now = now or datetime.now(timezone.utc).replace(tzinfo=None)
    found, fine = [], 0
    for c in roots:
        name = c.subject if c.subject == c.issuer else f"{c.subject} (issued by {c.issuer})"
        common = dict(key=f"cert:{c.thumbprint}", fix="open", fix_label="Open certificates",
                      data={"url": "certmgr.msc" if "account" in c.where else "certlm.msc",
                            "thumbprint": c.thumbprint})
        details = [f"Trusted root certificate in {c.where}. Thumbprint {c.thumbprint}" +
                   (f", added or changed {c.added:%Y-%m-%d}" if c.added else "")]
        if c.thumbprint in distrusted:
            found.append(Finding("Certificates", f"Microsoft has blocked this certificate, but it's trusted here: "
                                 f"{c.subject}", WARN, ["Microsoft distrusts it (it was misused or its key leaked). "
                                                        "Remove it."] + details, **common))
        elif KNOWN_BAD.search(name):
            found.append(Finding("Certificates", f"Known spying certificate: {c.subject}", WARN,
                                 ["Adware installs this certificate so it can read and change your secure (HTTPS) "
                                  "pages. Uninstall the program that brought it, then remove the certificate."]
                                 + details, **common))
        elif c.thumbprint in trusted or c.thumbprint in WINDOWS_BUILTIN:
            fine += 1
        elif INSPECTION_TOOLS.search(name):
            found.append(Finding("Certificates", f"Traffic inspection certificate: {c.subject}", NOTE,
                                 ["A debugging proxy or company web filter uses this to read secure (HTTPS) "
                                  "traffic. Fine if you use that tool; otherwise remove it."] + details, **common))
        elif ANTIVIRUS.search(name):
            found.append(Finding("Certificates", f"Antivirus web shield certificate: {c.subject}", NOTE,
                                 ["Your antivirus uses this to scan secure (HTTPS) pages. Fine while it's installed; "
                                  "remove it if you've uninstalled that antivirus."] + details, **common))
        elif GOVERNMENT.search(name):
            found.append(Finding("Certificates", f"Government certificate: {c.subject}", NOTE,
                                 ["A government or military root, installed for sites and smart-card sign-in that use "
                                  "it (for example by DoD InstallRoot). Fine if you use those."] + details, **common))
        elif c.added and now - c.added < timedelta(days=RECENT_DAYS):
            found.append(Finding("Certificates", f"New trusted root certificate: {c.subject}", WARN,
                                 [f"Added in the last {RECENT_DAYS} days and not on Microsoft's trusted list. If you "
                                  "didn't install it for work, school or a tool you use, something may be setting up "
                                  "to read your secure traffic."] + details, **common))
        elif DEVELOPER.search(name):
            found.append(Finding("Certificates", f"Developer certificate: {c.subject}", NOTE,
                                 ["Made by a development tool (IIS Express, .NET, Docker...) for local testing."]
                                 + details, **common))
        else:
            found.append(Finding("Certificates", f"Not on Microsoft's list: {c.subject}", NOTE,
                                 ["Usually installed for work, school or government sites (for example by "
                                  "InstallRoot), or by a VPN. Worth knowing where it came from."] + details, **common))
    if not trusted:
        found.append(Finding("Certificates", "Couldn't read Microsoft's trusted root list", NOTE,
                             ["Windows keeps it up to date automatically; it may be blocked on this PC."],
                             key="cert:no-list"))
    found.append(Finding("Certificates", f"{fine} trusted root certificate(s) are on Microsoft's list", OK,
                         key="cert:ok"))
    return found


def check_certificates() -> list[Finding]:
    trusted, distrusted = microsoft_list()
    return judge(installed_roots(), trusted, distrusted)
