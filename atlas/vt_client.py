"""Minimal VirusTotal API v3 client.

Only the lookups Project Atlas needs: file reports by hash, URL, domain and IP address
reports, sandbox behaviour summaries, and (opt-in only) file uploads.
"""

from __future__ import annotations

import base64
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import requests

API_BASE = "https://www.virustotal.com/api/v3"
GUI_BASE = "https://www.virustotal.com/gui"


class VTError(Exception):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status  # HTTP status, when VirusTotal answered


@dataclass
class Report:
    """Detection summary for a file, URL, or domain."""

    kind: str  # "file", "url", "domain" or "ip"
    target: str  # sha256, url, domain name or IP address
    found: bool
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    label: str | None = None  # e.g. "trojan.emotet/heodo"
    names: list[str] = field(default_factory=list)  # engine names that flagged it
    # Extra detail, when VirusTotal has it. Reports cached by older versions simply lack it.
    created: int | None = None  # site: when the domain was registered (Unix time)
    first_seen: int | None = None  # when VirusTotal first saw the file or site
    categories: list[str] = field(default_factory=list)  # site: security vendors' categories
    popularity: int | None = None  # site: best current rank in a popularity list (1 = most visited)
    threat_names: list[str] = field(default_factory=list)  # file: malware family names, e.g. "remcos"
    threat_kinds: list[str] = field(default_factory=list)  # file: e.g. "trojan", "adware", "pua"
    sandbox: list[str] = field(default_factory=list)  # file: sandboxes that called it bad, and why
    rules: list[str] = field(default_factory=list)  # file: detection rules it matched
    owner: str | None = None  # IP address: the network that owns it, and its country

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
        if self.kind == "ip":
            return f"{GUI_BASE}/ip-address/{self.target}"
        return f"{GUI_BASE}/url/{url_id(self.target)}"

    @classmethod
    def from_attributes(cls, kind: str, target: str, attrs: dict) -> Report:
        stats = attrs.get("last_analysis_stats") or {}
        results = attrs.get("last_analysis_results") or {}
        flagged = sorted(
            engine for engine, r in results.items() if r.get("category") in ("malicious", "suspicious")
        )
        threat = attrs.get("popular_threat_classification") or {}
        sandbox, families = [], []
        for name, v in (attrs.get("sandbox_verdicts") or {}).items():
            if v.get("category") in ("malicious", "suspicious"):
                kinds = ", ".join(c.lower() for c in v.get("malware_classification") or [] if c != "MALWARE")
                malware = ", ".join(v.get("malware_names") or [])
                families += v.get("malware_names") or []
                detail = "; ".join(x for x in (kinds, malware) if x)
                sandbox.append(f"{v.get('sandbox_name') or name}: {v['category']}" + (f" ({detail})" if detail else ""))
        rules = [y["rule_name"] for y in attrs.get("crowdsourced_yara_results") or [] if y.get("rule_name")]
        rules += [s["rule_title"] for s in attrs.get("sigma_analysis_results") or []
                  if s.get("rule_level") in ("critical", "high") and s.get("rule_title")]
        owner = ", ".join(str(x) for x in (attrs.get("as_owner"), attrs.get("country")) if x) or None
        return cls(
            kind=kind,
            target=target,
            found=True,
            malicious=int(stats.get("malicious", 0)),
            suspicious=int(stats.get("suspicious", 0)),
            harmless=int(stats.get("harmless", 0)),
            undetected=int(stats.get("undetected", 0)),
            label=threat.get("suggested_threat_label"),
            names=flagged,
            created=attrs.get("creation_date"),
            first_seen=attrs.get("first_submission_date") or attrs.get("first_seen_date"),
            categories=_unique(attrs.get("categories", {}).values()),
            popularity=_best_rank(attrs.get("popularity_ranks") or {}),
            threat_names=_unique([n["value"] for n in threat.get("popular_threat_name") or []] + families),
            threat_kinds=_unique(n["value"] for n in threat.get("popular_threat_category") or []),
            sandbox=sandbox,
            rules=_unique(rules)[:8],
            owner=owner,
        )


def _unique(values) -> list[str]:
    """Distinct values, first spelling wins, ignoring case."""
    seen, out = set(), []
    for v in values:
        if isinstance(v, str) and v.strip() and v.lower() not in seen:
            seen.add(v.lower())
            out.append(v.strip())
    return out


def _best_rank(ranks: dict, max_age_days: int = 400) -> int | None:
    """The best rank among popularity lists updated in the last year (some lists stopped years ago)."""
    cutoff = time.time() - max_age_days * 86400
    current = [r["rank"] for r in ranks.values() if r.get("rank") and r.get("timestamp", 0) >= cutoff]
    return min(current) if current else None


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
        # Called with (kind, status) after every request, e.g. ("files", 200); used for the quota meter.
        self.on_request: Callable[[str, int], None] | None = None

    def _count(self, path: str, status: int) -> None:
        if self.on_request:
            try:
                self.on_request(path.strip("/").split("/")[0], status)
            except Exception:  # the meter must never break a lookup
                pass

    def _get(self, path: str) -> dict | None:
        """GET a resource. Returns None when VirusTotal has never seen it."""
        body = self.api_get(path)
        return None if body is None else body["data"]

    def api_get(self, path: str, params: dict | None = None) -> dict | None:
        """GET any API path and return the whole JSON answer (data, meta, links). None for 404."""
        for attempt in range(self.max_retries + 1):
            resp = self.session.get(f"{API_BASE}{path}", params=params, timeout=30)
            self._count(path, resp.status_code)
            if resp.status_code == 404:
                return None
            if resp.status_code == 429 and attempt < self.max_retries:
                time.sleep(2**attempt * 5)  # quota exceeded: back off and retry
                continue
            if resp.status_code == 401:
                raise VTError("VirusTotal rejected the API key (401). Run: atlas set-key")
            if not resp.ok:
                raise VTError(f"VirusTotal error {resp.status_code}: {resp.text[:200]}", resp.status_code)
            return resp.json()
        raise VTError("VirusTotal quota exceeded; gave up after retries", 429)

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

    def ip_report(self, ip: str) -> Report:
        data = self._get(f"/ip_addresses/{ip}")
        if data is None:
            return Report(kind="ip", target=ip, found=False)
        return Report.from_attributes("ip", ip, data["attributes"])

    def behaviour_summary(self, sha256: str) -> dict | None:
        """What sandboxes saw the file do (all sandboxes merged), or None if it was never run in one."""
        data = self._get(f"/files/{sha256}/behaviour_summary")
        return data or None

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
        self._count("uploads", resp.status_code)
        if not resp.ok:
            raise VTError(f"Upload failed {resp.status_code}: {resp.text[:200]}")
        return resp.json()["data"]["id"]
