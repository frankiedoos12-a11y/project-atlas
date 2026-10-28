"""Minimal VirusTotal API v3 client.

Only the lookups Project Atlas needs: file reports by hash, URL reports, domain
reports, and (opt-in only) file uploads.
"""

from __future__ import annotations

import base64
import time
from dataclasses import dataclass, field
from pathlib import Path

import requests

API_BASE = "https://www.virustotal.com/api/v3"
GUI_BASE = "https://www.virustotal.com/gui"


class VTError(Exception):
    pass


@dataclass
class Report:
    """Detection summary for a file, URL, or domain."""

    kind: str  # "file", "url", or "domain"
    target: str  # sha256, url, or domain name
    found: bool
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    label: str | None = None  # e.g. "trojan.emotet/heodo"
    names: list[str] = field(default_factory=list)  # engine names that flagged it

    @property
    def total(self) -> int:
        return self.malicious + self.suspicious + self.harmless + self.undetected

    @property
    def analyzed(self) -> bool:
        """False when VirusTotal knows the item but no engine has scanned it yet."""
        return self.found and self.total > 0

    @property
    def gui_link(self) -> str:
        if self.kind == "file":
            return f"{GUI_BASE}/file/{self.target}"
        if self.kind == "domain":
            return f"{GUI_BASE}/domain/{self.target}"
        return f"{GUI_BASE}/url/{url_id(self.target)}"

    @classmethod
    def from_attributes(cls, kind: str, target: str, attrs: dict) -> Report:
        stats = attrs.get("last_analysis_stats") or {}
        results = attrs.get("last_analysis_results") or {}
        flagged = sorted(
            engine for engine, r in results.items() if r.get("category") in ("malicious", "suspicious")
        )
        label = (attrs.get("popular_threat_classification") or {}).get("suggested_threat_label")
        return cls(
            kind=kind,
            target=target,
            found=True,
            malicious=int(stats.get("malicious", 0)),
            suspicious=int(stats.get("suspicious", 0)),
            harmless=int(stats.get("harmless", 0)),
            undetected=int(stats.get("undetected", 0)),
            label=label,
            names=flagged,
        )


def url_id(url: str) -> str:
    """VirusTotal's identifier for a URL: unpadded URL-safe base64."""
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


class VTClient:
    def __init__(self, api_key: str, session: requests.Session | None = None, max_retries: int = 4):
        if not api_key:
            raise VTError("No VirusTotal API key configured. Run: atlas set-key")
        self.session = session or requests.Session()
        self.session.headers.update({"x-apikey": api_key, "accept": "application/json"})
        self.max_retries = max_retries

    def _get(self, path: str) -> dict | None:
        """GET a resource. Returns None when VirusTotal has never seen it."""
        for attempt in range(self.max_retries + 1):
            resp = self.session.get(f"{API_BASE}{path}", timeout=30)
            if resp.status_code == 404:
                return None
            if resp.status_code == 429 and attempt < self.max_retries:
                time.sleep(2**attempt * 5)  # quota exceeded: back off and retry
                continue
            if resp.status_code == 401:
                raise VTError("VirusTotal rejected the API key (401). Run: atlas set-key")
            if not resp.ok:
                raise VTError(f"VirusTotal error {resp.status_code}: {resp.text[:200]}")
            return resp.json()["data"]
        raise VTError("VirusTotal quota exceeded; gave up after retries")

    def file_report(self, sha256: str) -> Report:
        data = self._get(f"/files/{sha256}")
        if data is None:
            return Report(kind="file", target=sha256, found=False)
        return Report.from_attributes("file", sha256, data["attributes"])

    def url_report(self, url: str) -> Report:
        data = self._get(f"/urls/{url_id(url)}")
        if data is None:
            return Report(kind="url", target=url, found=False)
        return Report.from_attributes("url", url, data["attributes"])

    def domain_report(self, domain: str) -> Report:
        data = self._get(f"/domains/{domain}")
        if data is None:
            return Report(kind="domain", target=domain, found=False)
        return Report.from_attributes("domain", domain, data["attributes"])

    def upload_file(self, path: Path) -> str:
        """Upload a file for analysis and return the analysis id.

        WARNING: uploaded files become downloadable by VirusTotal Intelligence
        subscribers. Only called when the user has opted in.
        """
        size = path.stat().st_size
        url = f"{API_BASE}/files"
        if size > 32 * 1024 * 1024:
            resp = self.session.get(f"{API_BASE}/files/upload_url", timeout=30)
            if not resp.ok:
                raise VTError(f"Could not get large-upload URL: {resp.status_code}")
            url = resp.json()["data"]
        with path.open("rb") as fh:
            resp = self.session.post(url, files={"file": (path.name, fh)}, timeout=300)
        if not resp.ok:
            raise VTError(f"Upload failed {resp.status_code}: {resp.text[:200]}")
        return resp.json()["data"]["id"]
