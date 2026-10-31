package com.projectatlas.android

/** What the phone says about one installed app (gathered in Device.kt; plain data, so it's tested on the PC). */
data class AppFacts(
    val label: String,
    val packageName: String,
    val installer: String?, // the app that installed it, or null
    val granted: Set<String>, // permissions it has been given
    val accessibilityOn: Boolean = false,
    val deviceAdmin: Boolean = false,
    val notificationAccess: Boolean = false,
    val hasIcon: Boolean = true, // shows in the app list
    val version: String = "",
    val installed: Long = 0,
    val updated: Long = 0,
    val apkPath: String? = null,
    val signers: List<String> = emptyList(), // SHA-1 of its signing certificates
)

data class Assessment(val verdict: Verdict, val reasons: List<String>) {
    val needsLook get() = verdict.rank >= Verdict.SUSPICIOUS.rank
}

/** App stores that check apps before offering them. */
val STORES = mapOf(
    "com.android.vending" to "Google Play",
    "com.sec.android.app.samsungapps" to "Galaxy Store",
    "com.amazon.venezia" to "Amazon Appstore",
    "com.huawei.appmarket" to "Huawei AppGallery",
    "org.fdroid.fdroid" to "F-Droid",
)
private val FILE_INSTALLERS = setOf("com.google.android.packageinstaller", "com.android.packageinstaller")

fun fromStore(installer: String?) = installer in STORES

fun source(installer: String?): String = STORES[installer]?.let { "Installed from $it" } ?: when (installer) {
    null -> "Not from an app store: installed from a file or a computer"
    in FILE_INSTALLERS -> "Not from an app store: installed from a downloaded file"
    else -> "Not from an app store: installed by $installer"
}

/** Permissions that matter most when an app didn't come from a store: what scams and spyware ask for. */
val POWERS = linkedMapOf(
    "android.permission.READ_SMS" to "read your text messages, including the codes banks send",
    "android.permission.RECEIVE_SMS" to "see text messages as they arrive",
    "android.permission.SEND_SMS" to "send text messages",
    "android.permission.SYSTEM_ALERT_WINDOW" to "draw over other apps (fake sign-in screens use this)",
    "android.permission.REQUEST_INSTALL_PACKAGES" to "install other apps",
    "android.permission.READ_CALL_LOG" to "read your call history",
    "android.permission.ACCESS_BACKGROUND_LOCATION" to "see where you are all the time",
    "android.permission.RECORD_AUDIO" to "use the microphone",
    "android.permission.CAMERA" to "use the camera",
    "android.permission.READ_CONTACTS" to "read your contacts",
)
/** The ones that alone make an app from outside a store worth a look. */
private val STRONG = setOf("android.permission.READ_SMS", "android.permission.RECEIVE_SMS",
    "android.permission.SYSTEM_ALERT_WINDOW", "android.permission.REQUEST_INSTALL_PACKAGES")

/**
 * Atlas's verdict on an app: what the phone shows about it, plus VirusTotal's answer when there is one, plus the
 * threat data that came with Atlas (known stalkerware and monitoring apps), which needs no key.
 */
fun assess(app: AppFacts, vt: VtReport?, intel: IntelHit? = null): Assessment {
    val store = fromStore(app.installer)
    var verdict = Verdict.CLEAN
    val reasons = mutableListOf<String>()
    if (intel != null) {
        val (level, why) = intelReason(intel)
        verdict = level
        reasons += why
    }
    if (vt != null && vt.found) {
        verdict = verdict.atLeast(fileVerdict(vt))
        if (fileVerdict(vt) != Verdict.CLEAN) reasons += "VirusTotal: ${vt.detail}"
    }
    if (app.accessibilityOn) {
        reasons += "Accessibility access is on: it can see and tap everything on the screen"
        if (!store) verdict = verdict.atLeast(Verdict.SUSPICIOUS) // how banking trojans take over phones
    }
    if (app.deviceAdmin) {
        reasons += "It's a device administrator: it can lock the phone, and you must switch that off to uninstall it"
        if (!store) verdict = verdict.atLeast(Verdict.SUSPICIOUS)
    }
    if (app.notificationAccess) {
        reasons += "It reads your notifications, including messages and sign-in codes"
        if (!store) verdict = verdict.atLeast(Verdict.UNKNOWN)
    }
    val powers = POWERS.filterKeys { it in app.granted }
    if (!store) {
        if (!app.hasIcon) {
            reasons += "It has no icon in the app list, so it's easy to miss"
            verdict = verdict.atLeast(if (powers.isNotEmpty() || app.accessibilityOn) Verdict.SUSPICIOUS else Verdict.UNKNOWN)
        }
        if (powers.keys.any { it in STRONG }) verdict = verdict.atLeast(Verdict.UNKNOWN)
        if (vt != null && !vt.found) {
            reasons += "VirusTotal doesn't know this exact app"
            verdict = verdict.atLeast(Verdict.UNKNOWN)
        }
    }
    if (powers.isNotEmpty()) reasons += "It can " + powers.values.joinToString("; ")
    if (vt != null && vt.found && fileVerdict(vt) == Verdict.CLEAN) reasons += "VirusTotal: no engine flags it"
    reasons += source(app.installer)
    return Assessment(verdict, reasons)
}

fun summary(assessments: List<Assessment>, looked: Int): String {
    val look = assessments.count { it.needsLook }
    val unknown = assessments.count { it.verdict == Verdict.UNKNOWN }
    val parts = mutableListOf("${assessments.size} app${if (assessments.size == 1) "" else "s"} checked")
    parts += if (look == 0) "none needs a look" else "$look need${if (look == 1) "s" else ""} a look"
    if (unknown > 0) parts += "$unknown unknown"
    if (looked > 0) parts += "$looked looked up on VirusTotal"
    return parts.joinToString(", ") + "."
}

/** Like the Windows scam check: full links, and the bare ones scam texts use ("usps-redelivery.top/a1"). */
private val LINK = Regex("""(?i)(?:https?://|www\.)[^\s<>"'`)\]]+|(?<![@\w.])(?:[a-z0-9-]+\.)+(?:com|net|org|""" +
    """info|xyz|top|live|online|site|shop|click|app|io|co|me|us|cc|biz|link)(?![\w-])(?:/[^\s<>"'`)\]]*)?""")

/** The links in a shared message, in order, without repeats (and without trailing punctuation). */
fun extractLinks(text: String): List<String> = LINK.findAll(text)
    .map { it.value.trimEnd('.', ',', ';', ':', '!', '?', ')', ']', '}', '\'', '"') }
    .map { if (it.startsWith("http://", true) || it.startsWith("https://", true)) it else "https://$it" }
    .distinctBy { it.lowercase() }.toList()

fun hostOf(url: String): String =
    url.substringAfter("://").substringBefore('/').substringBefore('?').substringBefore('#')
        .substringAfterLast('@').substringBefore(':').lowercase().removePrefix("www.")

/** The quiet note after a new app is checked: "MyBoy!: checked, looks safe" and the reasons. */
fun checkedNote(label: String, a: Assessment): Pair<String, String> =
    "$label: checked, ${a.verdict.label.lowercase()}" to a.reasons.joinToString(" · ").ifEmpty { "Nothing to report." }
