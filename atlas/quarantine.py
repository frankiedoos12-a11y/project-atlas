"""Move dangerous files somewhere they can't be opened by accident, and back again."""

from __future__ import annotations

import shutil
from pathlib import Path

from atlas.db import Store

SUFFIX = ".atlas-quarantine"


def quarantine_dir(data_dir: Path) -> Path:
    path = data_dir / "quarantine"
    path.mkdir(parents=True, exist_ok=True)
    return path


def quarantine_file(path: Path, sha256: str, reason: str, store: Store, data_dir: Path) -> int:
    """Move a file into quarantine. The new name has no runnable extension."""
    target = quarantine_dir(data_dir) / f"{sha256[:16]}_{path.name}{SUFFIX}"
    n = 1
    while target.exists():
        target = target.with_name(f"{sha256[:16]}_{n}_{path.name}{SUFFIX}")
        n += 1
    shutil.move(str(path), str(target))
    return store.add_quarantine(str(path), str(target), sha256, reason)


def restore_file(qid: int, store: Store) -> Path:
    row = store.get_quarantine(qid)
    if row is None:
        raise KeyError(f"No quarantine entry with id {qid}")
    if row["restored_at"]:
        raise ValueError(f"Entry {qid} was already restored")
    stored = Path(row["stored_path"])
    if not stored.exists():
        raise FileNotFoundError(f"Quarantined file is missing: {stored}")
    dest = Path(row["original_path"])
    n = 1
    while dest.exists():
        dest = dest.with_name(f"{Path(row['original_path']).stem} (restored {n}){dest.suffix}")
        n += 1
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(stored), str(dest))
    store.mark_restored(qid)
    return dest
