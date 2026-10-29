from pathlib import Path

import pytest

from atlas.config import Settings
from atlas.db import Store
from atlas.scanner import Scanner
from atlas.vt_client import Report


class FakeVT:
    """Stands in for VTClient; returns canned reports and counts calls."""

    def __init__(self, files=None, urls=None, domains=None, ips=None, behaviour=None):
        self.files = files or {}
        self.urls = urls or {}
        self.domains = domains or {}
        self.ips = ips or {}
        self.behaviours = behaviour or {}  # sha256 -> raw behaviour summary
        self.calls: list[tuple[str, str]] = []

    def _get(self, kind, table, target):
        self.calls.append((kind, target))
        stats = table.get(target)
        if stats is None:
            return Report(kind=kind, target=target, found=False)
        return Report(kind=kind, target=target, found=True, **stats)

    def file_report(self, sha256):
        return self._get("file", self.files, sha256)

    def url_report(self, url):
        return self._get("url", self.urls, url)

    def domain_report(self, domain):
        return self._get("domain", self.domains, domain)

    def ip_report(self, ip):
        return self._get("ip", self.ips, ip)

    def behaviour_summary(self, sha256):
        self.calls.append(("behaviour", sha256))
        return self.behaviours.get(sha256)


@pytest.fixture(autouse=True)
def isolated_dirs(tmp_path, monkeypatch):
    monkeypatch.setenv("ATLAS_CONFIG_DIR", str(tmp_path / "config"))
    monkeypatch.setenv("ATLAS_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.delenv("ATLAS_VT_API_KEY", raising=False)
    from atlas import allowlist

    monkeypatch.setattr(allowlist, "shared_sites", lambda store=None: {})  # never download it in tests


@pytest.fixture
def store(tmp_path):
    s = Store(tmp_path / "data" / "atlas.db")
    yield s
    s.close()


@pytest.fixture
def make_scanner(store, tmp_path):
    def make(vt, **overrides):
        return Scanner(Settings(**overrides), store, vt, tmp_path / "data")

    return make


@pytest.fixture
def downloads(tmp_path) -> Path:
    d = tmp_path / "Downloads"
    d.mkdir()
    return d
