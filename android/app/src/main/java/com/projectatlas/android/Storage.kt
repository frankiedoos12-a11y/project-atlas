package com.projectatlas.android

/** Space, duplicates and risky files: plain logic, tested on the PC (the phone-side reading is in Media.kt). */

const val DAY_MS = 24L * 3600 * 1000

fun humanSize(bytes: Long): String {
    var size = bytes.toDouble()
    for (unit in listOf("bytes", "KB", "MB", "GB")) {
        if (size < 1024 || unit == "GB") return if (unit == "bytes") "${size.toLong()} bytes" else "%.1f %s".format(size, unit)
        size /= 1024
    }
    return "%.1f TB".format(size)
}

// --- Apps and space ------------------------------------------------------------------------------------------

data class AppUse(
    val label: String,
    val packageName: String,
    val system: Boolean, // came with the phone
    val hasIcon: Boolean,
    val appBytes: Long,
    val dataBytes: Long,
    val cacheBytes: Long,
    val lastUsed: Long, // 0: not since Android started keeping track
    val installed: Long,
) {
    val total get() = appBytes + dataBytes + cacheBytes
}

const val UNUSED_DAYS = 90

/** Apps you can open but haven't for 3 months (and didn't just install), biggest first. */
fun unusedApps(apps: List<AppUse>, now: Long, days: Int = UNUSED_DAYS): List<AppUse> = apps.filter {
    it.hasIcon && now - it.installed > days * DAY_MS && (it.lastUsed == 0L || now - it.lastUsed > days * DAY_MS)
}.sortedByDescending { it.total }

fun lastUsedText(app: AppUse, now: Long): String {
    if (app.lastUsed == 0L) return "Not opened in a long time (or ever)"
    val days = ((now - app.lastUsed) / DAY_MS).toInt()
    return when {
        days <= 0 -> "Opened today"
        days == 1 -> "Opened yesterday"
        days < 60 -> "Opened $days days ago"
        else -> "Not opened in ${days / 30} months"
    }
}

fun spaceText(app: AppUse): String =
    "${humanSize(app.total)}: app ${humanSize(app.appBytes)}, data ${humanSize(app.dataBytes)}, cache ${humanSize(app.cacheBytes)}"

// --- Files and duplicates --------------------------------------------------------------------------------------

data class FileItem(
    val uri: String, // a content:// address Android gives out
    val path: String, // folder and name, e.g. "DCIM/Camera/IMG_1.jpg"
    val name: String,
    val size: Long,
    val modified: Long, // milliseconds
    val mime: String,
)

class DuplicateGroup(val files: List<FileItem>) {
    val keep get() = files.first()
    val extras get() = files.drop(1)
    val wasted get() = keep.size * extras.size
}

/** Which copy to keep: the camera's own, then the oldest, then the shortest path (the others are copies of it). */
val KEEP_FIRST = compareBy<FileItem>({ if (it.path.startsWith("DCIM/", true)) 0 else 1 }, { it.modified }, { it.path.length })

/**
 * Identical files, most space wasted first. Only files of exactly the same size are read at all: first their start and
 * end (quick), then, for those that still match, in full. A null fingerprint (unreadable) leaves a file out.
 */
fun duplicateGroups(items: List<FileItem>, quick: (FileItem) -> String?, full: (FileItem) -> String?,
                    minSize: Long = 1): List<DuplicateGroup> {
    val groups = mutableListOf<DuplicateGroup>()
    for (sameSize in items.filter { it.size >= minSize }.groupBy { it.size }.values) {
        if (sameSize.size < 2) continue
        for (sameStart in sameSize.groupBy(quick).filterKeys { it != null }.values) {
            if (sameStart.size < 2) continue
            for (same in sameStart.groupBy(full).filterKeys { it != null }.values) {
                if (same.size > 1) groups += DuplicateGroup(same.sortedWith(KEEP_FIRST))
            }
        }
    }
    return groups.sortedByDescending { it.wasted }
}

fun biggest(items: List<FileItem>, count: Int = 25, atLeast: Long = 10L shl 20): List<FileItem> =
    items.filter { it.size >= atLeast }.sortedByDescending { it.size }.take(count)

// --- Files worth checking for malware --------------------------------------------------------------------------

/** What a file could do, riskiest kinds first: 0 installs apps, 1 runs code (here or on a PC), 2 documents. */
data class Risk(val rank: Int, val kind: String)

private val RISKY = buildMap {
    for (e in listOf("apk", "apks", "xapk", "apkm")) put(e, Risk(0, "an Android app"))
    for (e in listOf("exe", "msi", "scr", "bat", "cmd", "ps1", "vbs", "js", "jar", "dll", "lnk", "hta")) {
        put(e, Risk(1, "a program or script (for a PC)"))
    }
    for (e in listOf("zip", "rar", "7z", "iso", "img")) put(e, Risk(1, "an archive or disk image"))
    for (e in listOf("pdf", "doc", "docm", "docx", "xls", "xlsm", "xlsx", "ppt", "pptm", "pptx", "rtf", "html", "htm",
        "svg")) put(e, Risk(2, "a document"))
}

fun riskOf(name: String): Risk? = RISKY[name.substringAfterLast('.', "").lowercase()]

/** What VirusTotal's answer means for one of your files. */
fun riskyFileText(item: FileItem, report: VtReport?): String = when {
    report == null -> "Not checked yet"
    report.found -> "VirusTotal: ${report.detail}"
    (riskOf(item.name)?.rank ?: 2) == 0 -> "VirusTotal doesn't know this app: only install it if you trust where it came from"
    else -> "VirusTotal doesn't know this file (normal for your own documents)"
}
