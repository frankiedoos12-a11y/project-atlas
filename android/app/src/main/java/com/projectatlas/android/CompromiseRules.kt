package com.projectatlas.android

/**
 * The compromise check's rules, apart from the phone so they're tested on the PC. Each layer looks where spyware has
 * to show itself: how the phone started (Attestation.kt), what it does (microphone, camera, settings that changed,
 * uploads by Android itself), what it talks to (the threat data and link protection), and decoy files it might steal.
 */

/** One stretch of microphone or camera use, as Android reported it. */
data class SensorUse(val what: String, val start: Long, val end: Long, val screenOff: Boolean, val inCall: Boolean) {
    val minutes get() = (end - start) / 60_000
}

private const val MIC_OFF_MS = 2 * 60_000L // a voice note or a quick check takes less
private const val CAMERA_OFF_MS = 30_000L // face unlock takes a moment as the screen turns on

fun sensorFindings(uses: List<SensorUse>, watching: Boolean, now: Long): List<Finding> {
    val area = "Microphone and camera"
    if (!watching) {
        return listOf(Finding(area, "Microphone and camera aren't watched", Level.NOTE, listOf(
            "Atlas notes when the microphone or camera is in use while Scam alerts for texts or Link protection is " +
                "on (Android keeps Atlas running for those). Switch one on to watch them too."), "sensors:off"))
    }
    val week = uses.filter { it.end > now - 7 * DAY_MS }
    val odd = week.filter {
        it.screenOff && !it.inCall && it.end - it.start >= if (it.what == "Camera") CAMERA_OFF_MS else MIC_OFF_MS
    }
    if (odd.isEmpty()) {
        val mic = week.count { it.what == "Microphone" }
        val camera = week.count { it.what == "Camera" }
        return listOf(Finding(area, "Used only while you were using the phone", Level.OK, listOf(
            "In the last 7 days: the microphone $mic time${if (mic == 1) "" else "s"}, the camera $camera " +
                "time${if (camera == 1) "" else "s"}, none of them with the screen off."), "sensors:ok"))
    }
    return odd.groupBy { it.what }.map { (what, list) ->
        val longest = list.maxBy { it.end - it.start }
        Finding(area, "$what used with the screen off", Level.WARN, listOf(
            "The $what was in use ${list.size} time${if (list.size == 1) "" else "s"} in the last 7 days while the " +
                "screen was off and you weren't on a call, the longest for ${maxOf(1, longest.minutes)} minute" +
                (if (longest.minutes > 1) "s" else "") + ", ${ago(now - longest.start)}.",
            "A recorder, a navigation app or a smart-home app can do this. If none of yours should, someone may be " +
                "listening: open the app check for apps you don't know."), "sensors:${what.lowercase()}")
    }
}

/** The settings that let an app watch you, as one line each, so two days can be compared. */
fun watchSnapshot(f: PhoneFacts): Set<String> =
    f.accessibilityApps.map { "Accessibility: $it" }.toSet() +
        f.adminApps.map { "Device administrator: $it" } +
        f.addedCertificates.map { "Added certificate: $it" } +
        listOfNotNull(if (f.usbDebugging) "USB debugging on" else null,
            if (f.bootloaderUnlocked) "Bootloader unlocked" else null) +
        f.rootFound.map { "Root: $it" }

/** "time \t added|removed \t what" lines for what changed between two snapshots. */
fun snapshotChanges(old: Set<String>, new: Set<String>, now: Long): List<String> =
    (new - old).map { "$now\tadded\t$it" } + (old - new).map { "$now\tremoved\t$it" }

fun changeFindings(timeline: List<String>, now: Long): List<Finding> {
    val area = "What changed"
    val added = timeline.mapNotNull { line ->
        val p = line.split('\t')
        if (p.size == 3 && p[1] == "added") (p[0].toLongOrNull() ?: 0) to p[2] else null
    }.filter { it.first > now - 14 * DAY_MS }
    if (added.isEmpty()) {
        return listOf(Finding(area, "No new watching powers in 14 days", Level.OK, listOf(
            "No app gained accessibility or device administrator access, and no certificate was added."), "changes:ok"))
    }
    return added.map { (time, what) ->
        Finding(area, "New ${ago(now - time)}: $what", Level.WARN, listOf(
            "Spyware needs powers like this one. If you didn't give it, open the app check and look at the app, or " +
                "remove the certificate in Security settings."), "changes:$what")
    }
}

/** Android's own uploads (system and root), one day at a time, oldest first, today last. */
fun uploadFinding(daily: List<Long>): Finding? {
    if (daily.size < 6) return null // not enough days to know what's normal
    val before = daily.dropLast(1).sorted()
    val normal = before[before.size / 2]
    val today = daily.last()
    if (today < maxOf(5 * normal, 200L * 1024 * 1024)) {
        return Finding("Uploads", "Android's own uploads look normal", Level.OK, listOf(
            "Today ${humanSize(today)}; usually about ${humanSize(normal)} a day."), "uploads:ok")
    }
    return Finding("Uploads", "Android itself uploaded far more than usual", Level.WARN, listOf(
        "${humanSize(today)} in the last day, against about ${humanSize(normal)} usually. A cloud photo backup can " +
            "do this; spyware hiding inside Android would too. If nothing was backing up, look closer."), "uploads:high")
}

fun restartFinding(upMs: Long): Finding {
    val days = upMs / DAY_MS
    return if (days >= 3) {
        Finding("Hardening", "Last restart $days days ago", Level.NOTE, listOf(
            "Most commercial spyware lives only in memory: a restart wipes it, and attackers then have to break in " +
                "again. Restart the phone every few days."), "restart")
    } else {
        Finding("Hardening", "Restarted recently", Level.OK, listOf(
            "A restart wipes spyware that lives only in memory, which most does."), "restart:ok")
    }
}

/** Spyware usually gets in through the browser engine or a messaging app: each one left without updates. */
fun freshnessFindings(apps: List<Pair<String, Long>>, now: Long): List<Finding> {
    val stale = apps.filter { now - it.second > 45 * DAY_MS }
    if (stale.isEmpty()) {
        return listOf(Finding("Hardening", "Browser engine and messaging apps are up to date", Level.OK, listOf(
            "Each was updated in the last 45 days."), "fresh"))
    }
    return stale.map { (label, updated) ->
        Finding("Hardening", "$label hasn't updated in ${(now - updated) / DAY_MS} days", Level.NOTE, listOf(
            "Attacks often come in through the browser engine or a messaging app, and updates close the holes they " +
                "use. Update it in the Play Store."), "stale:$label")
    }
}
