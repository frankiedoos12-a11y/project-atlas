package com.projectatlas.android

import android.app.KeyguardManager
import android.app.admin.DevicePolicyManager
import android.app.usage.NetworkStats
import android.app.usage.NetworkStatsManager
import android.app.usage.UsageStatsManager
import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.os.Build
import android.os.Process
import android.provider.Settings
import java.io.File
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.util.concurrent.TimeUnit

/** Reads the facts the Protection checks need. Only looks: every fix is the person's, in Android's own settings. */
object Phone {
    fun facts(context: Context): PhoneFacts {
        val resolver = context.contentResolver
        val pm = context.packageManager
        fun label(pkg: String) = try {
            pm.getApplicationInfo(pkg, 0).loadLabel(pm).toString()
        } catch (e: Exception) {
            pkg
        }
        val (dnsMode, dnsHost) = privateDns(context)
        val admins = (context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager)
            .activeAdmins.orEmpty().map { it.packageName }.distinct()
        return PhoneFacts(
            screenLock = context.getSystemService(KeyguardManager::class.java).isDeviceSecure,
            securityPatch = Build.VERSION.SECURITY_PATCH.orEmpty(),
            androidVersion = Build.VERSION.RELEASE.orEmpty(),
            usbDebugging = Settings.Global.getInt(resolver, Settings.Global.ADB_ENABLED, 0) == 1,
            privateDns = dnsMode,
            privateDnsHost = dnsHost,
            addedCertificates = addedCertificates(),
            bootloaderUnlocked = prop("ro.boot.verifiedbootstate") == "orange",
            rootFound = rootSigns(pm),
            accessibilityApps = Device.packagesIn(Settings.Secure.getString(resolver, "enabled_accessibility_services"))
                .map(::label),
            adminApps = admins.map(::label),
            appsNeedingLook = AppCheck.rows.filter { it.assessment.needsLook }.map { it.facts.label },
        )
    }

    /** Private DNS as the current network uses it; the setting itself when there's no network. */
    private fun privateDns(context: Context): Pair<String?, String?> {
        if (Build.VERSION.SDK_INT < 28) return null to null // Android 8 has no Private DNS
        val links = context.getSystemService(ConnectivityManager::class.java).let { it.getLinkProperties(it.activeNetwork) }
        links?.privateDnsServerName?.let { return "hostname" to it }
        if (links?.isPrivateDnsActive == true) return "opportunistic" to null
        val mode = Settings.Global.getString(context.contentResolver, "private_dns_mode")
        return when (mode) {
            "off" -> "off" to null
            "hostname" -> "hostname" to Settings.Global.getString(context.contentResolver, "private_dns_specifier")
            else -> if (links == null) null to null else "opportunistic" to null // Automatic, the network has none
        }
    }

    /** Certificates a person or an app added (Android's own start "system:"). */
    private fun addedCertificates(): List<String> = try {
        val store = KeyStore.getInstance("AndroidCAStore").apply { load(null) }
        store.aliases().toList().filter { it.startsWith("user:") }.map { alias ->
            val subject = (store.getCertificate(alias) as? X509Certificate)?.subjectX500Principal?.name.orEmpty()
            Regex("(?:^|,)CN=([^,]+)").find(subject)?.groupValues?.get(1) ?: Regex("(?:^|,)O=([^,]+)").find(subject)
                ?.groupValues?.get(1) ?: subject.ifEmpty { alias }
        }
    } catch (e: Exception) {
        emptyList()
    }

    private val SU_PATHS = listOf("/system/bin/su", "/system/xbin/su", "/sbin/su", "/system/sbin/su", "/vendor/bin/su",
        "/su/bin/su", "/data/local/xbin/su", "/data/local/bin/su", "/system/app/Superuser.apk")
    private val ROOT_APPS = mapOf("com.topjohnwu.magisk" to "Magisk", "eu.chainfire.supersu" to "SuperSU",
        "me.weishu.kernelsu" to "KernelSU", "com.kingroot.kinguser" to "KingRoot", "io.github.huskydg.magisk" to "Magisk Delta")

    private fun rootSigns(pm: PackageManager): List<String> {
        val signs = SU_PATHS.filter { File(it).exists() }.toMutableList()
        for ((pkg, name) in ROOT_APPS) {
            try {
                pm.getPackageInfo(pkg, 0)
                signs += "the $name app"
            } catch (e: PackageManager.NameNotFoundException) {
            }
        }
        return signs
    }

    /** A system property, read the way any app may (getprop), with a short time limit. */
    private fun prop(name: String): String = try {
        val p = ProcessBuilder("getprop", name).redirectErrorStream(true).start()
        val text = p.inputStream.bufferedReader().readText().trim()
        if (!p.waitFor(2, TimeUnit.SECONDS)) p.destroy()
        text
    } catch (e: Exception) {
        ""
    }

    // --- Data use per app (needs Usage access) -----------------------------------------------------------

    /** The last 7 days on Wi-Fi and mobile data, per app. Empty without Usage access. */
    fun dataUse(context: Context, now: Long = System.currentTimeMillis()): List<DataUse> {
        if (!Media.usageAccess(context)) return emptyList()
        val pm = context.packageManager
        val stats = context.getSystemService(NetworkStatsManager::class.java)
        val start = now - 7 * DAY_MS
        class Sum { var sent = 0L; var received = 0L; var background = 0L }
        val byUid = mutableMapOf<Int, Sum>()
        @Suppress("DEPRECATION")
        for (type in listOf(ConnectivityManager.TYPE_WIFI, ConnectivityManager.TYPE_MOBILE)) {
            val summary = try {
                stats.querySummary(type, null, start, now)
            } catch (e: Exception) {
                continue // no SIM, or Android won't say
            }
            val bucket = NetworkStats.Bucket()
            summary.use {
                while (it.hasNextBucket()) {
                    it.getNextBucket(bucket)
                    if (bucket.uid < Process.FIRST_APPLICATION_UID) continue // Android itself
                    val sum = byUid.getOrPut(bucket.uid, ::Sum)
                    sum.sent += bucket.txBytes
                    sum.received += bucket.rxBytes
                    if (bucket.state != NetworkStats.Bucket.STATE_FOREGROUND) sum.background += bucket.txBytes
                }
            }
        }
        val used = context.getSystemService(UsageStatsManager::class.java).queryAndAggregateUsageStats(start - 30 * DAY_MS, now)
        return byUid.mapNotNull { (uid, sum) ->
            val pkg = pm.getPackagesForUid(uid)?.firstOrNull() ?: return@mapNotNull null
            val info = try {
                pm.getApplicationInfo(pkg, 0)
            } catch (e: Exception) {
                null
            }
            val label = info?.loadLabel(pm)?.toString() ?: pkg
            // The phone's own apps (Google services, the maker's) count as trusted, like store apps.
            val trusted = info == null || info.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM != 0 ||
                fromStore(Device.installer(pm, pkg))
            val use = used[pkg]
            val last = maxOf(use?.lastTimeUsed ?: 0, if (Build.VERSION.SDK_INT >= 29) use?.lastTimeVisible ?: 0 else 0)
            DataUse(label, pkg, sum.sent, sum.received, sum.background, trusted, last)
        }.sortedByDescending { it.sent + it.received }
    }
}
