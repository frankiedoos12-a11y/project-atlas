"""The weekly report: how the PC's health score moved, what got fixed, what's new, and what Atlas did.

The tray writes it once a week (`weekly_report` in the settings) as a page in the data folder's
`reports` folder and pops up a short summary; `atlas report` writes one now. It stays on the PC.
"""

from __future__ import annotations

import html
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from pathlib import Path

from atlas import __version__, score
from atlas.cleanup import human_size

EVERY_DAYS = 7


@dataclass
class Weekly:
    today: date
    now: score.Score
    before: int | None  # the score a week ago (or the oldest within the week)
    fixed: list[str] = field(default_factory=list)
    new: list[str] = field(default_factory=list)
    activity: dict = field(default_factory=dict)
    lookups: int = 0

    @property
    def change(self) -> str:
        if self.before is None:
            return "first report"
        diff = self.now.value - self.before
        return "no change" if diff == 0 else f"up {diff}" if diff > 0 else f"down {-diff}"

    @property
    def summary(self) -> str:
        look = len(self.now.warn)
        moved = "" if self.before is None else f", {self.change} on last week"
        return (f"Health {self.now.text}{moved}. " +
                (f"{look} thing{'s' if look != 1 else ''} need{'s' if look == 1 else ''} a look." if look
                 else "Nothing needs a look."))


def build(store, now: score.Score, today: date | None = None) -> Weekly:
    today = today or date.today()
    week = score.history(store, EVERY_DAYS + 1, today)
    earlier = [(d, row) for d, row in week if d < today]
    before = earlier[0][1] if earlier else None
    old_warn = set(before["warn"]) if before else set()
    since = datetime.combine(today - timedelta(days=EVERY_DAYS), datetime.min.time()).astimezone()
    usage = store.vt_usage((today - timedelta(days=EVERY_DAYS - 1)).isoformat())
    return Weekly(today, now, before["value"] if before else None,
                  fixed=sorted(old_warn - set(now.warn)), new=[w for w in now.warn if before and w not in old_warn],
                  activity=store.activity_since(since), lookups=sum(r for r, _ in usage.values()))


def _list(items: list[str], empty: str) -> str:
    if not items:
        return f"<p class=muted>{html.escape(empty)}</p>"
    return "<ul>" + "".join(f"<li>{html.escape(i)}</li>" for i in items) + "</ul>"


def to_html(w: Weekly) -> str:
    scans = w.activity.get("scans", {})
    flagged = scans.get("malicious", 0) + scans.get("suspicious", 0)
    color = "#2e7d32" if w.now.value >= score.GOOD else "#9a7400" if w.now.value >= score.FAIR else "#c62828"
    rows = [("Files checked", sum(scans.values())), ("Flagged as malicious or suspicious", flagged),
            ("Moved to quarantine", w.activity.get("quarantined", 0)), ("VirusTotal lookups", w.lookups),
            ("Cleaned up", f"{w.activity.get('cleaned_items', 0)} items, "
                           f"{human_size(w.activity.get('cleaned_bytes', 0))}")]
    return f"""<!doctype html>
<html lang=en><head><meta charset=utf-8><meta name=viewport content="width=device-width, initial-scale=1">
<title>Atlas weekly report</title>
<style>
body {{ font: 15px/1.5 "Segoe UI", system-ui, sans-serif; color: #222; background: #f7f7f9; margin: 0; padding: 24px 16px; }}
main {{ max-width: 720px; margin: 0 auto; background: #fff; border-radius: 10px; padding: 24px 28px; }}
h1 {{ font-size: 22px; margin: 0 0 4px; }} h2 {{ font-size: 16px; margin: 24px 0 6px; }}
.score {{ font-size: 44px; font-weight: 600; color: {color}; margin: 12px 0 0; }}
.muted {{ color: #666; }} table {{ border-collapse: collapse; width: 100%; }}
td {{ padding: 6px 0; border-bottom: 1px solid #eee; }} td:last-child {{ text-align: right; font-weight: 600; }}
</style></head><body><main>
<h1>Project Atlas weekly report</h1>
<p class=muted>Week ending {w.today:%A %d %B %Y}</p>
<p class=score>{w.now.value}<span class=muted style="font-size:18px">/100</span></p>
<p><b>{html.escape(w.now.label)}</b>{"" if w.before is None else ", " + html.escape(w.change) + " on last week"}.</p>
<h2>Needs a look</h2>{_list(w.now.warn, "Nothing. Well done.")}
<h2>New this week</h2>{_list(w.new, "Nothing new.")}
<h2>Fixed this week</h2>{_list(w.fixed, "Nothing was fixed this week.")}
<h2>What Atlas did</h2>
<table>{"".join(f"<tr><td>{html.escape(k)}</td><td>{html.escape(str(v))}</td></tr>" for k, v in rows)}</table>
<p class=muted style="margin-top:24px">Open the Atlas window's Protection tab for details and fixes. This report
stays on this PC. Project Atlas {__version__}.</p>
</main></body></html>
"""


def save(w: Weekly, folder: Path) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"atlas-week-{w.today.isoformat()}.html"
    path.write_text(to_html(w), encoding="utf-8")
    return path


def due(store, today: date | None = None) -> bool:
    """A week since the last report? The first report waits a week too, so it has something to compare."""
    today = today or date.today()
    last = store.cached_extra("report", "last", 10 * 365 * 24)
    if last is None:
        store.cache_extra("report", "last", today.isoformat())
        return False
    return (today - date.fromisoformat(last)).days >= EVERY_DAYS


def mark_sent(store, today: date | None = None) -> None:
    store.cache_extra("report", "last", (today or date.today()).isoformat())
