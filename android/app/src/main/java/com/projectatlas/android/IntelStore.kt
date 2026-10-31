package com.projectatlas.android

import android.content.Context
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

/** The threat data on this phone: the copy that came with the app, or a newer one fetched from Atlas's repository. */
object IntelStore {
    /** Rebuilt each week from the public lists by the repository's own workflow. */
    const val UPDATE_URL = "https://raw.githubusercontent.com/frankiedoos12-a11y/project-atlas/main/android/app/src/main/assets/intel.txt"
    private const val WEEK_MS = 7 * DAY_MS
    private const val MIN_FAMILIES = 100 // fewer means a broken list: keep what we have

    @Volatile private var loaded: Intel? = null

    private fun saved(context: Context) = File(context.filesDir, "intel.txt")

    fun get(context: Context): Intel {
        loaded?.let { return it }
        synchronized(this) {
            loaded?.let { return it }
            val shipped = context.assets.open("intel.txt").bufferedReader().use { Intel.parse(it.readText()) }
                ?: error("the threat data that came with the app can't be read")
            val fetched = try {
                saved(context).takeIf { it.exists() }?.let { Intel.parse(it.readText()) }
            } catch (e: Exception) {
                null
            }
            return (if (fetched != null && fetched.version > shipped.version) fetched else shipped).also { loaded = it }
        }
    }

    /** Once a week, from the daily check. Quietly keeps the current data when anything is off. */
    fun updateIfDue(context: Context) {
        val prefs = context.getSharedPreferences("watch", Context.MODE_PRIVATE)
        val now = System.currentTimeMillis()
        if (now - prefs.getLong("intel_checked", 0) < WEEK_MS) return
        prefs.edit().putLong("intel_checked", now).apply()
        val text = try {
            val connection = URL(UPDATE_URL).openConnection() as HttpURLConnection
            try {
                connection.connectTimeout = 20_000
                connection.readTimeout = 30_000
                if (connection.responseCode != 200) return
                connection.inputStream.bufferedReader().use { it.readText() }
            } finally {
                connection.disconnect()
            }
        } catch (e: Exception) {
            return
        }
        val fresh = Intel.parse(text) ?: return
        if (fresh.size < MIN_FAMILIES || fresh.version <= get(context).version) return
        val file = saved(context)
        val temp = File(file.path + ".new")
        temp.writeText(text)
        if (temp.renameTo(file)) loaded = fresh
    }
}
