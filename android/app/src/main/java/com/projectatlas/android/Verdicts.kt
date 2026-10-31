package com.projectatlas.android

/** The same verdicts, and the same VirusTotal rules, as Project Atlas on Windows. */
enum class Verdict(val rank: Int, val label: String, val color: Int) {
    CLEAN(0, "Looks safe", 0xFF2E7D32.toInt()),
    UNKNOWN(1, "Unknown", 0xFF9A7400.toInt()),
    SUSPICIOUS(2, "Needs a look", 0xFFD84315.toInt()),
    MALICIOUS(3, "Dangerous", 0xFFC62828.toInt());

    fun atLeast(other: Verdict) = if (other.rank > rank) other else this
}

/** Engines that call a file malicious before Atlas does too (fewer: "needs a look"). */
const val MALICIOUS_THRESHOLD = 3

data class VtReport(
    val found: Boolean,
    val malicious: Int = 0,
    val suspicious: Int = 0,
    val total: Int = 0,
    val label: String = "",
) {
    val detail: String
        get() = "$malicious malicious / $suspicious suspicious of $total engines" +
            if (label.isNotEmpty()) " ($label)" else ""

    /** Saved on the phone so the same app or file isn't looked up again for a while. */
    fun encode(now: Long): String = listOf(now, found, malicious, suspicious, total, label).joinToString("|")

    companion object {
        const val KEEP_FOUND_MS = 30L * 24 * 3600 * 1000 // a verdict seldom changes
        const val KEEP_UNKNOWN_MS = 3L * 24 * 3600 * 1000 // VirusTotal may learn about it soon

        /** null when it's unreadable or too old. */
        fun decode(text: String?, now: Long): VtReport? {
            val parts = text?.split("|", limit = 6) ?: return null
            if (parts.size != 6) return null
            return try {
                val report = VtReport(parts[1].toBooleanStrict(), parts[2].toInt(), parts[3].toInt(), parts[4].toInt(),
                    parts[5])
                val age = now - parts[0].toLong()
                if (age < 0 || age > (if (report.found) KEEP_FOUND_MS else KEEP_UNKNOWN_MS)) null else report
            } catch (e: IllegalArgumentException) {
                null
            }
        }
    }
}

/** A file or an app. */
fun fileVerdict(report: VtReport, threshold: Int = MALICIOUS_THRESHOLD): Verdict = when {
    !report.found -> Verdict.UNKNOWN
    report.malicious >= threshold -> Verdict.MALICIOUS
    report.malicious > 0 || report.suspicious > 0 -> Verdict.SUSPICIOUS
    else -> Verdict.CLEAN
}

/** A website: one or two engines often flag busy sites by mistake, so only many make it "needs a look". */
fun siteVerdict(report: VtReport, threshold: Int = MALICIOUS_THRESHOLD): Verdict = when {
    !report.found -> Verdict.UNKNOWN
    report.malicious >= threshold -> Verdict.SUSPICIOUS
    else -> Verdict.CLEAN
}
