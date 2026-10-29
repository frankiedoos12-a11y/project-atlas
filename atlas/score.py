"""One number for "how is this PC doing?": the health score, 0 to 100, from the Protection and threat hunt
findings. Each day's score is kept (in the database) for the weekly report.

Things that need a look cost the most, more so for the protections that matter most (Defender, remote access,
the threat hunt). More of them in the same area cost less each (three overdue updates are one problem, not
three). Notes cost a little, and together never more than NOTE_CAP.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta

from atlas.findings import NOTE, WARN, Finding

SERIOUS_AREAS = {"Defender", "Remote access", "Threat intel", "Command lines", "Certificates", "Drivers", "WMI",
                 "Registry", "Accounts"}
SERIOUS_WARN, WARN_COST, SAME_AREA_COST, NOTE_COST, NOTE_CAP = 15, 8, 3, 1, 10
GOOD, FAIR = 90, 60
KEEP_DAYS = 60


@dataclass
class Score:
    value: int
    label: str
    warn: list[str]  # titles of what needs a look, worst first
    notes: int

    @property
    def text(self) -> str:
        return f"{self.value}/100 ({self.label})"


def label_for(value: int) -> str:
    return "Good" if value >= GOOD else "Fair" if value >= FAIR else "Needs attention"


def health_score(findings: list[Finding]) -> Score:
    warns = [f for f in findings if f.level == WARN]
    notes = [f for f in findings if f.level == NOTE]
    serious = [f for f in warns if f.area in SERIOUS_AREAS]
    cost, seen = 0, set()
    for f in serious + [f for f in warns if f not in serious]:
        cost += SAME_AREA_COST if f.area in seen else SERIOUS_WARN if f.area in SERIOUS_AREAS else WARN_COST
        seen.add(f.area)
    cost += min(NOTE_CAP, NOTE_COST * len(notes))
    value = max(0, 100 - cost)
    titles = [f"{f.area}: {f.title}" for f in serious + [f for f in warns if f not in serious]]
    return Score(value, label_for(value), titles, len(notes))


def record(store, score: Score, day: date | None = None) -> None:
    """Keep today's score (the last check of the day wins)."""
    day = day or date.today()
    store.cache_extra("health", day.isoformat(), {"value": score.value, "warn": score.warn, "notes": score.notes})


def recorded(store, day: date) -> dict | None:
    return store.cached_extra("health", day.isoformat(), KEEP_DAYS * 24)


def history(store, days: int = 7, today: date | None = None) -> list[tuple[date, dict]]:
    today = today or date.today()
    found = []
    for back in range(days - 1, -1, -1):
        day = today - timedelta(days=back)
        row = recorded(store, day)
        if row:
            found.append((day, row))
    return found
