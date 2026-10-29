"""Disk health: drives Windows says are failing or worn out, before they lose your files.

Windows reads each drive's own health report (SMART). The basic status needs no administrator;
the deep check adds wear, temperature and read errors, which Windows only shows an administrator.
"""

from __future__ import annotations

import logging

from atlas.findings import NOTE, OK, WARN, Finding

log = logging.getLogger(__name__)

DISK_SCRIPT = ("ConvertTo-Json -Compress -InputObject @(Get-PhysicalDisk | ForEach-Object { [pscustomobject]@{"
               " name=$_.FriendlyName; media=[string]$_.MediaType; health=[string]$_.HealthStatus;"
               " status=@($_.OperationalStatus | ForEach-Object { [string]$_ }) -join ', ';"
               " size=[math]::Round($_.Size / 1GB) } })")
# Administrator only; part of the deep check.
RELIABILITY_SCRIPT = ("ConvertTo-Json -Compress -InputObject @(Get-PhysicalDisk | ForEach-Object { $d = $_;"
                      " $r = $d | Get-StorageReliabilityCounter -ErrorAction SilentlyContinue; [pscustomobject]@{"
                      " name=$d.FriendlyName; wear=$r.Wear; temperature=$r.Temperature;"
                      " read_errors=$r.ReadErrorsUncorrected; hours=$r.PowerOnHours } })")
WEAR_WARN = 90  # percent of the drive's rated life used
WEAR_NOTE = 70
HOT = 70  # degrees C


def disks() -> list[dict]:
    from atlas.local_checks import run_powershell_json

    try:
        return run_powershell_json(DISK_SCRIPT, timeout=60)
    except Exception:
        log.exception("Couldn't read disk health")
        return []


def disk_findings(rows: list[dict], reliability: list[dict] | None = None) -> list[Finding]:
    found = []
    extra = {r.get("name"): r for r in reliability or []}
    backup = "Copy anything you can't lose to another drive or OneDrive now."
    for d in rows:
        name, health = d.get("name") or "A drive", (d.get("health") or "").lower()
        label = f"{name} ({d.get('size')} GB {d.get('media') or 'drive'})".replace(" Unspecified", "")
        if health in ("unhealthy", "warning"):
            found.append(Finding("Disk health", f"Windows says {name} is {'failing' if health == 'unhealthy' else 'wearing out'}",
                                 WARN, [f"{label}: {d.get('health')} ({d.get('status')}).", backup],
                                 key=f"disk:{name}:{health}"))
            continue
        r = extra.get(name) or {}
        wear, temp, errors = r.get("wear"), r.get("temperature"), r.get("read_errors")
        if isinstance(wear, int) and wear >= WEAR_NOTE:
            found.append(Finding("Disk health", f"{name} has used {wear}% of its rated life",
                                 WARN if wear >= WEAR_WARN else NOTE,
                                 [f"{label}. SSDs wear out with use and fail without much warning near the end.",
                                  backup], key=f"disk:{name}:wear:{wear // 10}"))
        elif isinstance(errors, int) and errors > 0:
            found.append(Finding("Disk health", f"{name} has had {errors} read error(s) it couldn't correct", WARN,
                                 [f"{label}. That often comes before a drive fails.", backup],
                                 key=f"disk:{name}:errors"))
        elif isinstance(temp, int) and temp >= HOT:
            found.append(Finding("Disk health", f"{name} is running hot ({temp} °C)", NOTE,
                                 [f"{label}. Heat shortens a drive's life. Check the vents aren't blocked."],
                                 key=f"disk:{name}:hot"))
        else:
            details = [label + (f", {wear}% of rated life used" if isinstance(wear, int) else "")]
            if reliability is None:
                details.append("The deep check (administrator) adds wear, temperature and read errors.")
            found.append(Finding("Disk health", f"{name} is healthy", OK, details, key=f"disk:{name}:ok"))
    return found


def check_disks(reliability: list[dict] | None = None) -> list[Finding]:
    return disk_findings(disks(), reliability)
