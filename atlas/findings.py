"""A single result from Atlas's system checks (Defender, browser hijacks, proxy, hosts file, DNS)."""

from __future__ import annotations

from dataclasses import dataclass, field

OK, NOTE, WARN = "ok", "note", "warn"  # fine / worth knowing / needs a look


@dataclass
class Finding:
    area: str  # e.g. "Defender", "Chrome (Profile 2)", "Proxy", "Hosts file", "DNS"
    title: str  # one line, e.g. "Real-time protection is off"
    level: str = NOTE
    details: list[str] = field(default_factory=list)
    key: str = ""  # stable id: the tray alerts once when a new "warn" key appears
    fix: str | None = None  # what the Fix button does (see atlas.protection.apply_fix)
    fix_label: str | None = None  # e.g. "Turn the proxy off..."
    data: dict = field(default_factory=dict)  # whatever the fix needs
    vt_link: str | None = None

    @property
    def needs_look(self) -> bool:
        return self.level == WARN
