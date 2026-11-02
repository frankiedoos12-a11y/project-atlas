package com.projectatlas.android

import android.content.Context
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/** The threat data on this phone: the copy that came with the app, or a newer one fetched from Atlas's repository. */
object IntelStore {
    /** Rebuilt each week from the public lists by the repository's own workflow. */
    const val UPDATE_URL = "https://raw.githubusercontent.com/frankiedoos12-a11y/project-atlas/main/android/app/src/main/assets/intel.txt"
    private const val WEEK_MS = 7 * DAY_MS
    private const val MIN_FAMILIES = 100 // fewer means a broken list: keep what we have

    /**
     * The public half of the key the weekly workflow signs the threat data with (ECDSA P-256). A list that isn't
     * signed by it is never used, so even someone who could change the repository can't send phones a list of
     * their own. The private half is the repository's INTEL_SIGNING_KEY secret.
     */
    const val SIGNING_KEY = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhOus1C9712WbNcbJF8GylVP6IpwwaG8gFsF82i2LsFTIDVIPsCC+jPwY2Yuk" +
        "CSGHSAYBoi6d4Po7vbgAzSbMfg=="

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
        val bytes = fetch(UPDATE_URL) ?: return
        val signature = fetch("$UPDATE_URL.sig")
        if (signature == null || !signed(bytes, String(signature).trim())) {
            // The list and its signature may be mid-update on GitHub: try again tomorrow, not next week.
            prefs.edit().putLong("intel_checked", now - WEEK_MS + DAY_MS).apply()
            return
        }
        val text = String(bytes, Charsets.UTF_8)
        val fresh = Intel.parse(text) ?: return
        if (fresh.size < MIN_FAMILIES || fresh.version <= get(context).version) return
        val file = saved(context)
        val temp = File(file.path + ".new")
        temp.writeText(text)
        if (temp.renameTo(file)) loaded = fresh
    }

    /** Whether [signature] (base64, as openssl writes it) is the signing key's signature of [data]. */
    fun signed(data: ByteArray, signature: String, key: String = SIGNING_KEY): Boolean = try {
        val publicKey = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(Base64.getDecoder().decode(key)))
        Signature.getInstance("SHA256withECDSA").run {
            initVerify(publicKey)
            update(data)
            verify(Base64.getDecoder().decode(signature))
        }
    } catch (e: Exception) {
        false
    }

    private fun fetch(url: String): ByteArray? = try {
        val connection = URL(url).openConnection() as HttpURLConnection
        try {
            connection.connectTimeout = 20_000
            connection.readTimeout = 30_000
            if (connection.responseCode == 200) connection.inputStream.use { it.readBytes() } else null
        } finally {
            connection.disconnect()
        }
    } catch (e: Exception) {
        null
    }
}
