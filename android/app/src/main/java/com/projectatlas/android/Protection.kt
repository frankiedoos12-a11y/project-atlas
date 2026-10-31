package com.projectatlas.android

/** The phone's Protection checks and health score: plain logic, tested on the PC (the reading is in Phone.kt). */

enum class Level { OK, NOTE, WARN } // fine / worth knowing / needs a look

data class Finding(
    val area: String,
    val title: String,
    val level: Level = Level.NOTE,
    val details: List<String> = emptyList(),
    val key: String = "", // stable: the daily check alerts once when a new WARN key appears
    val settings: String? = null, // an Android settings page that fixes it (an Intent action)
)

/** What the phone says about itself. */
data class PhoneFacts(
    val screenLock: Boolean,
    val securityPatch: String, // "2026-10-05"
    val androidVersion: String,
    val usbDebugging: Boolean,
    val privateDns: String?, // "off", "opportunistic", "hostname", or null when Android won't say
    val privateDnsHost: String? = null,
    val addedCertificates: List<String> = emptyList(), // who each one says it belongs to
    val bootloaderUnlocked: Boolean = false,
    val rootFound: List<String> = emptyList(), // what gave it away
    val accessibilityApps: List<String> = emptyList(),
    val adminApps: List<String> = emptyList(),
    val appsNeedingLook: List<String> = emptyList(), // from the app check
)

const val SECURITY_SETTINGS = "android.settings.SECURITY_SETTINGS"
const val SYSTEM_UPDATE = "android.settings.SYSTEM_UPDATE_SETTINGS"
const val DEVELOPER_SETTINGS = "android.settings.APPLICATION_DEVELOPMENT_SETTINGS"
const val NETWORK_SETTINGS = "android.settings.WIRELESS_SETTINGS"
const val ACCESSIBILITY_SETTINGS = "android.settings.ACCESSIBILITY_SETTINGS"
const val SET_LOCK = "android.app.action.SET_NEW_PASSWORD"

/** Days since the security patch, or null when the date can't be read. */
fun patchAgeDays(patch: String, today: java.time.LocalDate): Long? = try {
    java.time.temporal.ChronoUnit.DAYS.between(java.time.LocalDate.parse(patch), today)
} catch (e: Exception) {
    null
}

fun phoneFindings(f: PhoneFacts, today: java.time.LocalDate): List<Finding> {
    val found = mutableListOf<Finding>()
    found += if (f.screenLock) {
        Finding("Screen lock", "A screen lock is set", Level.OK, key = "lock")
    } else {
        Finding("Screen lock", "No screen lock", Level.WARN, listOf("Anyone who picks up the phone can open your " +
            "email, banking apps and photos. Set a PIN, pattern or password; a fingerprint or face unlock can go " +
            "with it."), "lock:none", SET_LOCK)
    }
    val age = patchAgeDays(f.securityPatch, today)
    found += when {
        age == null -> Finding("Security updates", "Android ${f.androidVersion}", Level.NOTE,
            listOf("The date of the last security update couldn't be read."), "patch:unknown", SYSTEM_UPDATE)
        age <= 90 -> Finding("Security updates", "Security update from ${f.securityPatch}", Level.OK, key = "patch")
        age <= 180 -> Finding("Security updates", "The last security update is ${age / 30} months old", Level.NOTE,
            listOf("Check for a system update. Phones get one about every month while the maker supports them."),
            "patch:old", SYSTEM_UPDATE)
        else -> Finding("Security updates", "No security update for ${age / 30} months", Level.WARN,
            listOf("Check for a system update. If there's none, the maker has probably stopped supporting this " +
                "phone: flaws found from now on won't be fixed. Be extra careful with links and apps, and think " +
                "about a newer phone for banking."), "patch:stale", SYSTEM_UPDATE)
    }
    if (f.usbDebugging) {
        found += Finding("Developer options", "USB debugging is on", Level.NOTE, listOf("A computer you plug into can " +
            "install apps and read data. Fine while you use it; switch it off afterwards."), "adb", DEVELOPER_SETTINGS)
    }
    when (f.privateDns) {
        "off" -> found += Finding("Private DNS", "Private DNS is off", Level.NOTE, listOf("Website lookups go out " +
            "unprotected, so on public Wi-Fi they can be seen or changed. Set Private DNS to Automatic (or a provider " +
            "such as Cloudflare: one.one.one.one) in Network settings."), "dns:off", NETWORK_SETTINGS)
        "hostname" -> found += Finding("Private DNS", "Private DNS: ${f.privateDnsHost ?: "your chosen provider"}",
            Level.OK, key = "dns")
        "opportunistic" -> found += Finding("Private DNS", "Private DNS: Automatic", Level.OK, key = "dns")
    }
    for (name in f.addedCertificates) {
        found += Finding("Certificates", "An added security certificate: $name", Level.WARN, listOf("A certificate " +
            "you (or an app) added lets whoever owns it read your encrypted traffic. A work or school setup, or a " +
            "VPN or ad blocker you chose, may need one. If you don't know it, remove it: Settings > Security > More " +
            "security > Encryption and credentials > Trusted credentials > User."), "cert:$name", SECURITY_SETTINGS)
    }
    if (f.rootFound.isNotEmpty()) {
        found += Finding("Root", "The phone is rooted", Level.WARN, listOf("Apps can get full control of a rooted " +
            "phone, and banking apps may refuse to run. If you didn't root it, someone else did: ask for help, or " +
            "reset the phone.", "Found: ${f.rootFound.joinToString()}"), "root")
    }
    if (f.bootloaderUnlocked) {
        found += Finding("Bootloader", "The bootloader is unlocked", Level.WARN, listOf("Android can't check that " +
            "its own system hasn't been changed. That's expected only if you install your own system on purpose."),
            "bootloader")
    }
    if (f.appsNeedingLook.isNotEmpty()) {
        found += Finding("Apps", "${f.appsNeedingLook.size} app${if (f.appsNeedingLook.size == 1) "" else "s"} need" +
            "${if (f.appsNeedingLook.size == 1) "s" else ""} a look: ${f.appsNeedingLook.joinToString()}", Level.WARN,
            listOf("See the app check on the main screen for why."), "apps:" + f.appsNeedingLook.sorted().joinToString(","))
    }
    if (f.accessibilityApps.isNotEmpty()) {
        found += Finding("Accessibility", "Accessibility access: ${f.accessibilityApps.joinToString()}", Level.NOTE,
            listOf("These apps can see and tap everything on screen. Screen readers and password managers need it; " +
                "anything else, switch off."), "a11y:" + f.accessibilityApps.sorted().joinToString(","), ACCESSIBILITY_SETTINGS)
    }
    if (f.adminApps.isNotEmpty()) {
        found += Finding("Device admin", "Device administrators: ${f.adminApps.joinToString()}", Level.NOTE,
            listOf("They can lock or wipe the phone. Find My Device and work apps use it; switch off any you don't " +
                "recognise (Settings > Security > Device admin apps)."), "admin:" + f.adminApps.sorted().joinToString(","),
            SECURITY_SETTINGS)
    }
    return found.sortedBy { -it.level.ordinal }
}

// --- The health score, as on Windows -----------------------------------------------------------------------

val SERIOUS_AREAS = setOf("Screen lock", "Certificates", "Root", "Bootloader", "Apps")
const val SERIOUS_WARN = 15
const val WARN_COST = 8
const val SAME_AREA_COST = 3
const val NOTE_COST = 1
const val NOTE_CAP = 10

data class Score(val value: Int, val label: String, val warn: List<String>, val notes: Int) {
    val text get() = "$value/100 ($label)"
}

fun labelFor(value: Int) = if (value >= 90) "Good" else if (value >= 60) "Fair" else "Needs attention"

fun healthScore(findings: List<Finding>): Score {
    val warns = findings.filter { it.level == Level.WARN }
    val serious = warns.filter { it.area in SERIOUS_AREAS }
    val ordered = serious + warns.filter { it !in serious }
    var cost = 0
    val seen = mutableSetOf<String>()
    for (f in ordered) {
        cost += if (f.area in seen) SAME_AREA_COST else if (f.area in SERIOUS_AREAS) SERIOUS_WARN else WARN_COST
        seen += f.area
    }
    val notes = findings.count { it.level == Level.NOTE }
    cost += minOf(NOTE_CAP, NOTE_COST * notes)
    val value = maxOf(0, 100 - cost)
    return Score(value, labelFor(value), ordered.map { "${it.area}: ${it.title}" }, notes)
}

// --- Data use per app ------------------------------------------------------------------------------------------

data class DataUse(val label: String, val packageName: String, val sent: Long, val received: Long,
                   val backgroundSent: Long, val trusted: Boolean, val lastUsed: Long) // trusted: from a store, or the phone's own

/** Apps that sent a lot in the background without being opened: what spyware looks like (or a backup app). */
fun quietUploaders(uses: List<DataUse>, now: Long, atLeast: Long = 100L shl 20): List<Finding> = uses
    .filter { it.backgroundSent >= atLeast && (it.lastUsed == 0L || now - it.lastUsed > 7 * DAY_MS) }
    .map {
        Finding("Data use", "${it.label} sent ${humanSize(it.backgroundSent)} in the background this week, unopened",
            if (it.trusted) Level.NOTE else Level.WARN, listOf("Backup and sync apps do this. If ${it.label} " +
                "isn't one, find out why, or uninstall it."), "upload:${it.packageName}")
    }

// --- What the daily check tells you about ---------------------------------------------------------------------

/** Serious findings that weren't there last time (each is told once, until it goes away and comes back). */
fun newWarnings(findings: List<Finding>, remembered: Set<String>): List<Finding> =
    findings.filter { it.level == Level.WARN && it.key.isNotEmpty() && it.key !in remembered }
