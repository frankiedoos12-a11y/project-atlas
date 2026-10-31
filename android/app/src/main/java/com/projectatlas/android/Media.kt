package com.projectatlas.android

import android.Manifest
import android.app.Activity
import android.app.AppOpsManager
import android.app.usage.StorageStatsManager
import android.app.usage.UsageStatsManager
import android.content.ContentUris
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.os.Process
import android.os.storage.StorageManager
import android.provider.MediaStore
import android.provider.Settings
import java.io.FileInputStream
import java.nio.ByteBuffer
import java.security.MessageDigest

/** Reading files through Android's media index, and the switches each screen needs. Only reads: removing files
 * always goes through Android's own "Move to trash?" question, which the person answers. */
object Media {
    val IMAGES: Uri = MediaStore.Images.Media.EXTERNAL_CONTENT_URI
    val VIDEOS: Uri = MediaStore.Video.Media.EXTERNAL_CONTENT_URI
    val FILES: Uri = MediaStore.Files.getContentUri("external")

    /** addedAfter: only files added since then (seconds, as Android counts), for the downloads watch. */
    fun list(context: Context, collection: Uri, addedAfter: Long = 0): List<FileItem> {
        val modern = Build.VERSION.SDK_INT >= 29
        val folder = if (modern) MediaStore.MediaColumns.RELATIVE_PATH else MediaStore.MediaColumns.DATA
        val projection = arrayOf(MediaStore.MediaColumns._ID, MediaStore.MediaColumns.DISPLAY_NAME,
            MediaStore.MediaColumns.SIZE, MediaStore.MediaColumns.DATE_MODIFIED, MediaStore.MediaColumns.MIME_TYPE, folder)
        val found = mutableListOf<FileItem>()
        val selection = "${MediaStore.MediaColumns.SIZE} > 0 AND ${MediaStore.MediaColumns.MIME_TYPE} IS NOT NULL" +
            if (addedAfter > 0) " AND ${MediaStore.MediaColumns.DATE_ADDED} > $addedAfter" else ""
        context.contentResolver.query(collection, projection, selection, null, null)?.use { c ->
            while (c.moveToNext()) {
                val name = c.getString(1) ?: continue
                val place = c.getString(5) ?: ""
                val root = Environment.getExternalStorageDirectory().path + "/"
                found += FileItem(
                    uri = ContentUris.withAppendedId(collection, c.getLong(0)).toString(),
                    path = if (modern) place + name else place.removePrefix(root),
                    name = name,
                    size = c.getLong(2),
                    modified = c.getLong(3) * 1000,
                    mime = c.getString(4) ?: "",
                )
            }
        }
        return found
    }

    /** The first and last 64 KB: tells most different files apart without reading them in full. */
    fun quickHash(context: Context, item: FileItem): String? = try {
        context.contentResolver.openFileDescriptor(Uri.parse(item.uri), "r")?.use { fd ->
            FileInputStream(fd.fileDescriptor).channel.use { channel ->
                val digest = MessageDigest.getInstance("SHA-256")
                val part = 64 * 1024
                val head = ByteBuffer.allocate(part)
                channel.read(head, 0)
                digest.update(head.array(), 0, head.position())
                if (item.size > part) {
                    val tail = ByteBuffer.allocate(part)
                    channel.read(tail, maxOf(0, item.size - part))
                    digest.update(tail.array(), 0, tail.position())
                }
                digest.digest().joinToString("") { "%02x".format(it) }
            }
        }
    } catch (e: Exception) {
        null
    }

    fun fullHash(context: Context, item: FileItem): String? {
        val prefs = context.getSharedPreferences("hashes", Context.MODE_PRIVATE)
        val key = "${item.uri}|${item.size}|${item.modified}"
        prefs.getString(key, null)?.let { return it }
        val hash = try {
            context.contentResolver.openInputStream(Uri.parse(item.uri))?.let(::sha256)
        } catch (e: Exception) {
            null
        } ?: return null
        prefs.edit().putString(key, hash).apply()
        return hash
    }

    /** Android asks "Move to trash?" (30 days to change your mind). False: this Android can't, or refused. */
    fun askToTrash(activity: Activity, items: List<FileItem>, request: Int): Boolean {
        if (Build.VERSION.SDK_INT < 30 || items.isEmpty()) return false
        return try {
            val pending = MediaStore.createTrashRequest(activity.contentResolver, items.map { Uri.parse(it.uri) }, true)
            activity.startIntentSenderForResult(pending.intentSender, request, null, 0, 0, 0)
            true
        } catch (e: Exception) {
            false
        }
    }

    fun open(activity: Activity, item: FileItem) {
        try {
            activity.startActivity(Intent(Intent.ACTION_VIEW).setDataAndType(Uri.parse(item.uri), item.mime)
                .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION))
        } catch (e: Exception) {
            // nothing on the phone opens it
        }
    }

    // --- Switches --------------------------------------------------------------------------------------------

    fun mediaPermissions(): Array<String> = when {
        Build.VERSION.SDK_INT >= 34 -> arrayOf(Manifest.permission.READ_MEDIA_IMAGES, Manifest.permission.READ_MEDIA_VIDEO,
            Manifest.permission.READ_MEDIA_VISUAL_USER_SELECTED)
        Build.VERSION.SDK_INT >= 33 -> arrayOf(Manifest.permission.READ_MEDIA_IMAGES, Manifest.permission.READ_MEDIA_VIDEO)
        else -> arrayOf(Manifest.permission.READ_EXTERNAL_STORAGE)
    }

    /** "all", "some" (Android 14's "only the photos I pick") or "none". */
    fun mediaAccess(context: Context): String {
        fun has(p: String) = context.checkSelfPermission(p) == PackageManager.PERMISSION_GRANTED
        return when {
            Build.VERSION.SDK_INT >= 33 && has(Manifest.permission.READ_MEDIA_IMAGES) -> "all"
            Build.VERSION.SDK_INT < 33 && has(Manifest.permission.READ_EXTERNAL_STORAGE) -> "all"
            Build.VERSION.SDK_INT >= 34 && has(Manifest.permission.READ_MEDIA_VISUAL_USER_SELECTED) -> "some"
            else -> "none"
        }
    }

    fun allFilesAccess(context: Context): Boolean = if (Build.VERSION.SDK_INT >= 30) {
        Environment.isExternalStorageManager()
    } else {
        context.checkSelfPermission(Manifest.permission.READ_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED
    }

    /** The settings page where the person switches on All files access for Atlas (Android 11 and later). */
    @android.annotation.TargetApi(30)
    fun allFilesSettings(context: Context): Intent =
        Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION, Uri.parse("package:${context.packageName}"))

    fun usageAccess(context: Context): Boolean {
        val ops = context.getSystemService(AppOpsManager::class.java)
        val mode = if (Build.VERSION.SDK_INT >= 29) {
            ops.unsafeCheckOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), context.packageName)
        } else {
            @Suppress("DEPRECATION") ops.checkOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), context.packageName)
        }
        return mode == AppOpsManager.MODE_ALLOWED
    }

    fun usageSettings(context: Context): Intent =
        Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS, Uri.parse("package:${context.packageName}"))

    // --- Space per app (needs Usage access) ------------------------------------------------------------------

    fun appUse(context: Context): List<AppUse> {
        val pm = context.packageManager
        val storage = context.getSystemService(StorageStatsManager::class.java)
        val now = System.currentTimeMillis()
        val used = context.getSystemService(UsageStatsManager::class.java)
            .queryAndAggregateUsageStats(now - 2 * 365 * DAY_MS, now)
        val withIcons = pm.queryIntentActivities(Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER), 0)
            .map { it.activityInfo.packageName }.toSet()
        val apps = if (Build.VERSION.SDK_INT >= 33) {
            pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(0))
        } else {
            @Suppress("DEPRECATION") pm.getInstalledPackages(0)
        }
        return apps.mapNotNull { info ->
            val app = info.applicationInfo ?: return@mapNotNull null
            val system = app.flags and ApplicationInfo.FLAG_SYSTEM != 0
            if (system && (info.packageName !in withIcons || !app.enabled)) return@mapNotNull null // Android's own parts
            val stats = try {
                storage.queryStatsForPackage(StorageManager.UUID_DEFAULT, info.packageName, Process.myUserHandle())
            } catch (e: Exception) {
                return@mapNotNull null
            }
            val use = used[info.packageName]
            val last = maxOf(use?.lastTimeUsed ?: 0, if (Build.VERSION.SDK_INT >= 29) use?.lastTimeVisible ?: 0 else 0)
            AppUse(app.loadLabel(pm).toString(), info.packageName, system, info.packageName in withIcons,
                stats.appBytes, stats.dataBytes, stats.cacheBytes, last, info.firstInstallTime)
        }
    }

    /** Without Usage access: each app you installed, with the size of its own files only (data and cache need
     * Usage access). Biggest first. */
    fun appFileSizes(context: Context): List<Pair<String, Long>> {
        val pm = context.packageManager
        val apps = if (Build.VERSION.SDK_INT >= 33) {
            pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(0))
        } else {
            @Suppress("DEPRECATION") pm.getInstalledPackages(0)
        }
        return apps.mapNotNull { info ->
            val app = info.applicationInfo ?: return@mapNotNull null
            if (app.flags and ApplicationInfo.FLAG_SYSTEM != 0) return@mapNotNull null
            val files = listOfNotNull(app.sourceDir) + app.splitSourceDirs.orEmpty()
            app.loadLabel(pm).toString() to files.sumOf { java.io.File(it).length() }
        }.sortedByDescending { it.second }
    }

    fun phoneSpace(context: Context): Pair<Long, Long> {
        val storage = context.getSystemService(StorageStatsManager::class.java)
        return storage.getTotalBytes(StorageManager.UUID_DEFAULT) to storage.getFreeBytes(StorageManager.UUID_DEFAULT)
    }
}

/** Lookups a minute: a ticked Paid key is at least 120, whatever VirusTotal reports for the key itself. */
fun speed(keyLimit: Int, paidTicked: Boolean): Int = when {
    paidTicked -> maxOf(keyLimit, 120)
    keyLimit > 0 -> keyLimit
    else -> VirusTotal.LOOKUPS_PER_MINUTE
}

/** Milliseconds between lookups; a free key gets half a second to spare. */
fun spacing(perMinute: Int): Long = 60_000L / perMinute + if (perMinute > VirusTotal.LOOKUPS_PER_MINUTE) 0 else 500

/** Settings of the phone app itself. */
object Prefs {
    private fun prefs(context: Context) = context.getSharedPreferences("settings", Context.MODE_PRIVATE)

    /** What VirusTotal says the key allows, in lookups a minute (0: not known yet). It decides the speed. */
    fun keyLimit(context: Context) = prefs(context).getInt("key_limit", 0)
    fun setKeyLimit(context: Context, perMinute: Int) = prefs(context).edit().putInt("key_limit", perMinute).apply()

    /** Ticked by hand when VirusTotal won't say: a free key allows 4 lookups a minute, paid keys far more. */
    fun paidTicked(context: Context) = prefs(context).getBoolean("paid_key", false)
    fun setPaidKey(context: Context, paid: Boolean) = prefs(context).edit().putBoolean("paid_key", paid).apply()

    fun lookupsPerMinute(context: Context) =
        speed(keyLimit(context), paidTicked(context))
    fun paidKey(context: Context) = lookupsPerMinute(context) > VirusTotal.LOOKUPS_PER_MINUTE
    fun spacingMs(context: Context) = spacing(lookupsPerMinute(context))

    /** Where the speed comes from, for the main screen. */
    fun speedText(context: Context): String {
        val limit = keyLimit(context)
        val ticked = paidTicked(context)
        val now = lookupsPerMinute(context)
        return when {
            ticked && limit in 1 until now -> "$now lookups a minute (Paid key is ticked; VirusTotal reports $limit for " +
                "the key itself, so your company's allowance is likely kept elsewhere)"
            limit > 0 -> "$now lookups a minute (what VirusTotal says your key allows)"
            ticked -> "$now lookups a minute (Paid key is ticked)"
            else -> "$now lookups a minute (a free key's limit; tick Paid key for a Premium or Enterprise key)"
        }
    }

    /**
     * Wait until the next lookup may start, `since` being when the last one did. The speed is read again while waiting,
     * so ticking Paid key (or a newly learnt limit) speeds up a check that's already running.
     */
    fun waitTurn(context: Context, since: Long) {
        while (System.currentTimeMillis() - since < spacingMs(context)) Thread.sleep(250)
    }

    /** Ask VirusTotal what the key allows, and remember it. */
    fun learnKeyLimit(context: Context, key: String) {
        try {
            VirusTotal(key).lookupsPerMinute()?.let { setKeyLimit(context, it) }
        } catch (e: Exception) {
            // offline, or it didn't say: the ticked box (or the free speed) stays in charge
        }
    }
}
