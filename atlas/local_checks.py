"""Checks that run on this PC without contacting VirusTotal.

- SHA-256 hashing
- Mark-of-the-Web: the Zone.Identifier stream Windows attaches to downloads,
  which records the page and URL a file came from
- Authenticode signature: whether an executable is signed, and by whom
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

# Extensions that can run code when opened. These get extra scrutiny.
RISKY_EXTENSIONS = {
    ".exe", ".msi", ".msix", ".appx", ".dll", ".scr", ".com", ".pif", ".bat", ".cmd",
    ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".lnk", ".jar",
    ".iso", ".img", ".vhd", ".vhdx", ".zip", ".7z", ".rar", ".cab", ".reg", ".chm",
    ".docm", ".xlsm", ".pptm", ".one",
}

# Extensions Authenticode signatures apply to.
SIGNABLE_EXTENSIONS = {".exe", ".msi", ".msix", ".appx", ".dll", ".scr", ".sys", ".cab", ".ps1", ".psm1", ".cat"}

ZONE_NAMES = {0: "Local", 1: "Intranet", 2: "Trusted", 3: "Internet", 4: "Restricted"}


def sha256_file(path: Path, chunk: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while block := fh.read(chunk):
            h.update(block)
    return h.hexdigest()


def is_risky(path: Path) -> bool:
    return path.suffix.lower() in RISKY_EXTENSIONS


@dataclass
class MarkOfTheWeb:
    zone: int | None = None
    host_url: str | None = None  # the download URL
    referrer_url: str | None = None  # the page you were on

    @property
    def zone_name(self) -> str:
        return ZONE_NAMES.get(self.zone, "Unknown") if self.zone is not None else "None"


def read_motw(path: Path) -> MarkOfTheWeb | None:
    """Read the NTFS Zone.Identifier alternate data stream, if present."""
    try:
        text = Path(f"{path}:Zone.Identifier").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    motw = MarkOfTheWeb()
    for line in text.splitlines():
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if key == "ZoneId" and value.isdigit():
            motw.zone = int(value)
        elif key == "HostUrl" and value.lower() not in ("", "about:internet"):
            motw.host_url = value
        elif key == "ReferrerUrl":
            motw.referrer_url = value or None
    return motw


@dataclass
class Signature:
    status: str  # "Valid", "NotSigned", "HashMismatch", ... or "Unavailable"
    signer: str | None = None

    @property
    def valid(self) -> bool:
        return self.status == "Valid"


def run_powershell_json(script: str, items: list[str] | None = None, timeout: int = 600) -> list[dict]:
    """Run a PowerShell script that prints JSON and return the result as a list.

    `items` are written to a temporary file the script reads from $env:ATLAS_LIST,
    one per line, so paths never pass through command-line quoting.
    """
    env = dict(os.environ)
    list_file = None
    if items is not None:
        fd, list_file = tempfile.mkstemp(prefix="atlas_", suffix=".txt")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write("\n".join(items))
        env["ATLAS_LIST"] = list_file
    try:
        out = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
             "[Console]::OutputEncoding = [Text.Encoding]::UTF8; " + script],
            capture_output=True, timeout=timeout, env=env,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        text = out.stdout.decode("utf-8", errors="replace").strip()
        if not text:
            return []
        data = json.loads(text)
        return data if isinstance(data, list) else [data]
    finally:
        if list_file:
            os.unlink(list_file)


_SIGNATURE_SCRIPT = (
    "$r = Get-Content -LiteralPath $env:ATLAS_LIST -Encoding UTF8 | Where-Object { $_ } | ForEach-Object {"
    " $s = Get-AuthenticodeSignature -LiteralPath $_ -ErrorAction SilentlyContinue;"
    " [pscustomobject]@{path=[string]$_; status=if ($s) { [string]$s.Status } else { 'Unavailable' };"
    " signer=if ($s -and $s.SignerCertificate) { $s.SignerCertificate.GetNameInfo('SimpleName', $false) }"
    " else { $null }} };"
    " ConvertTo-Json -InputObject @($r) -Compress"
)


def check_signatures(paths: list[Path]) -> dict[str, Signature]:
    """Verify many files' Authenticode signatures in one PowerShell call. Keyed by str(path)."""
    if not paths:
        return {}
    unavailable = {str(p): Signature(status="Unavailable") for p in paths}
    if sys.platform != "win32":
        return unavailable
    try:
        rows = run_powershell_json(_SIGNATURE_SCRIPT, [str(p) for p in paths])
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return unavailable
    found = {r["path"]: Signature(status=r.get("status") or "Unavailable", signer=r.get("signer")) for r in rows}
    return {**unavailable, **found}


def check_signature(path: Path) -> Signature | None:
    """Ask Windows to verify the file's Authenticode signature.

    Returns None for file types that cannot carry a signature.
    """
    if path.suffix.lower() not in SIGNABLE_EXTENSIONS:
        return None
    return check_signatures([path])[str(path)]
