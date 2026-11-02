package com.projectatlas.android

import android.app.usage.NetworkStats
import android.app.usage.NetworkStatsManager
import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.hardware.camera2.CameraManager
import android.media.AudioManager
import android.media.AudioRecordingConfiguration
import android.net.ConnectivityManager
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.os.Handler
import android.os.Looper
import android.os.PowerManager
import android.os.Process
import android.os.SystemClock
import android.provider.MediaStore
import android.provider.Telephony
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.webkit.WebView
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.X509Certificate

/** The compromise check on the phone: gathers each layer's facts and hands them to the rules in CompromiseRules.kt. */
object Compromise {
    private const val KEY = "atlas_boot_proof"
    private const val STATUS_URL = "https://android.googleapis.com/attestation/status"

    fun prefs(context: Context) = context.getSharedPreferences("compromise", Context.MODE_PRIVATE)

    /** Every layer, in order. [online]: also fetch Google's revoked-key list (about 180 KB, at most once a week). */
    fun run(context: Context, online: Boolean): List<Finding> {
        val now = System.currentTimeMillis()
        val facts = Phone.facts(context)
        updateChanges(context, facts, now)
        recordUploads(context)
        return bootCheck(context, online) +
            restartFinding(SystemClock.elapsedRealtime()) +
            freshnessFindings(engines(context), now) +
            sensorFindings(Sensors.uses(context), Sensors.watching(context), now) +
            changeFindings(changes(context), now) +
            listOfNotNull(uploadFinding(uploads(context))) +
            spywareFindings(context) +
            canaryFinding(context)
    }

    /** From the daily job: the light layers only, with an alert for anything new and serious. */
    fun daily(context: Context) {
        val now = System.currentTimeMillis()
        updateChanges(context, Phone.facts(context), now)
        recordUploads(context)
        val findings = bootCheck(context, online = true) + changeFindings(changes(context), now) +
            sensorFindings(Sensors.uses(context), Sensors.watching(context), now) +
            listOfNotNull(uploadFinding(uploads(context)))
        val p = prefs(context)
        for (f in newWarnings(findings, p.getStringSet("warned", emptySet()).orEmpty())) {
            Watch.notify(context, "compromise:${f.key}", f.title, f.details.first() + " Open the compromise check.",
                Intent(context, CompromiseActivity::class.java))
        }
        p.edit().putStringSet("warned", findings.filter { it.level == Level.WARN }.map { it.key }.toSet()).apply()
    }

    // --- Start-up proof ----------------------------------------------------------------------------------

    private fun bootCheck(context: Context, online: Boolean): List<Finding> {
        val challenge = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val proof = try {
            proofFor(challenge)
        } catch (e: Exception) {
            null
        }?.let { if (it.challenge == Attestation.hex(challenge)) it else it.copy(chainTrusted = false) }
        val p = prefs(context)
        val found = bootFindings(proof, proof != null && revoked(context, proof.serials, online),
            p.getString("boot_key", null), p.getString("boot_hash", null), p.getInt("boot_patch", 0))
        if (proof != null && proof.chainTrusted && proof.locked && proof.state <= 1) {
            val edit = p.edit().putString("boot_hash", proof.bootHash).putInt("boot_patch", proof.osPatch)
            if (!p.contains("boot_key")) edit.putString("boot_key", proof.bootKey) // the first clean proof is kept
            edit.apply()
        }
        return found
    }

    private fun proofFor(challenge: ByteArray): BootProof? {
        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        generator.initialize(KeyGenParameterSpec.Builder(KEY, KeyProperties.PURPOSE_SIGN)
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setAttestationChallenge(challenge)
            .build())
        generator.generateKeyPair()
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        try {
            val chain = store.getCertificateChain(KEY)?.map { it as X509Certificate } ?: return null
            return Attestation.read(chain)
        } finally {
            store.deleteEntry(KEY)
        }
    }

    /** Whether Google revoked a certificate in the chain. Unknown (no copy, offline) counts as not revoked. */
    private fun revoked(context: Context, serials: List<String>, online: Boolean): Boolean {
        val file = File(context.cacheDir, "attestation-status.json")
        if (online && System.currentTimeMillis() - file.lastModified() > 7 * DAY_MS) {
            try {
                val connection = URL(STATUS_URL).openConnection() as HttpURLConnection
                try {
                    connection.connectTimeout = 20_000
                    connection.readTimeout = 30_000
                    if (connection.responseCode == 200) {
                        val text = connection.inputStream.bufferedReader().use { it.readText() }
                        JSONObject(text) // only a list that reads is kept
                        file.writeText(text)
                    }
                } finally {
                    connection.disconnect()
                }
            } catch (e: Exception) {
            }
        }
        return try {
            val entries = JSONObject(file.readText()).getJSONObject("entries")
            serials.any { entries.optJSONObject(it)?.optString("status") == "REVOKED" }
        } catch (e: Exception) {
            false
        }
    }

    // --- Hardening -----------------------------------------------------------------------------------------

    /** The browser engine, Chrome and the messaging apps that are installed, with when each last updated. */
    private fun engines(context: Context): List<Pair<String, Long>> {
        val pm = context.packageManager
        val names = listOfNotNull(
            try { WebView.getCurrentWebViewPackage()?.packageName } catch (e: Exception) { null },
            "com.android.chrome", "com.whatsapp", "org.thoughtcrime.securesms", "org.telegram.messenger",
            "com.facebook.orca", "com.google.android.apps.messaging", Telephony.Sms.getDefaultSmsPackage(context),
        ).distinct()
        return names.mapNotNull { name ->
            try {
                val info = pm.getPackageInfo(name, 0)
                val label = info.applicationInfo?.loadLabel(pm)?.toString() ?: name
                (if (name == names.first() && "webview" in name.lowercase()) "Android System WebView" else label) to
                    info.lastUpdateTime
            } catch (e: Exception) {
                null
            }
        }
    }

    // --- What changed --------------------------------------------------------------------------------------

    private fun updateChanges(context: Context, facts: PhoneFacts, now: Long) {
        val p = prefs(context)
        val now_ = watchSnapshot(facts)
        val old = p.getStringSet("snapshot", null)
        val edit = p.edit().putStringSet("snapshot", now_)
        if (old != null) {
            val lines = snapshotChanges(old, now_, now) + changes(context)
            edit.putString("changes", lines.take(50).joinToString("\n"))
        }
        edit.apply()
    }

    private fun changes(context: Context) =
        prefs(context).getString("changes", "").orEmpty().lines().filter { it.isNotBlank() }

    // --- Android's own uploads -------------------------------------------------------------------------------

    /** Today's uploads by Android itself (system and root), kept per day for two weeks. Needs Usage access. */
    private fun recordUploads(context: Context) {
        if (!Media.usageAccess(context)) return
        val now = System.currentTimeMillis()
        val stats = context.getSystemService(NetworkStatsManager::class.java)
        var sent = 0L
        @Suppress("DEPRECATION")
        for (type in listOf(ConnectivityManager.TYPE_WIFI, ConnectivityManager.TYPE_MOBILE)) {
            val summary = try {
                stats.querySummary(type, null, now - DAY_MS, now)
            } catch (e: Exception) {
                continue
            }
            val bucket = NetworkStats.Bucket()
            summary.use {
                while (it.hasNextBucket()) {
                    it.getNextBucket(bucket)
                    if (bucket.uid == Process.SYSTEM_UID || bucket.uid == 0) sent += bucket.txBytes
                }
            }
        }
        val today = java.time.LocalDate.now().toString()
        val days = prefs(context).getString("uploads", "").orEmpty().lines().filter { it.isNotBlank() && !it.startsWith(today) }
        prefs(context).edit().putString("uploads", (days.takeLast(14) + "$today\t$sent").joinToString("\n")).apply()
    }

    private fun uploads(context: Context): List<Long> = prefs(context).getString("uploads", "").orEmpty().lines()
        .mapNotNull { it.substringAfter('\t', "").toLongOrNull() }

    // --- Known spyware ---------------------------------------------------------------------------------------

    private fun spywareFindings(context: Context): List<Finding> {
        val area = "Known spyware"
        val hits = Device.installedApps(context).mapNotNull { app ->
            Device.intel(context, app, null)?.takeIf { !it.family.watchware }?.let { app to it }
        }
        val blocked = LinkGuard.recent(context).filter { it.family.spyware || it.family.stalkerware }
        val out = hits.map { (app, hit) ->
            Finding(area, "${app.label}: ${hit.family.what} (${hit.family.name})", Level.WARN,
                listOf(intelReason(hit).second), "spyware:${app.packageName}")
        } + blocked.distinctBy { it.host }.map {
            Finding(area, "Something on the phone tried to reach ${it.host}", Level.WARN, listOf(
                "Link protection blocked it ${ago(System.currentTimeMillis() - it.time)}: a site ${it.family.name} " +
                    "(${it.family.what}) uses. If you didn't tap a link to it, an app or spyware asked for it."),
                "reached:${it.host}")
        }
        return out.ifEmpty {
            listOf(Finding(area, "No known spyware or stalkerware", Level.OK, listOf(
                "No installed app matches the threat data" + if (LinkGuard.enabled(context)) ", and link " +
                    "protection hasn't blocked a spyware site." else ". Switch on link protection to also catch " +
                    "spyware calling home."), "spyware:ok"))
        }
    }

    // --- Decoy file ------------------------------------------------------------------------------------------

    private fun canaryFinding(context: Context): List<Finding> {
        val since = prefs(context).getLong("canary_since", 0)
        return listOf(if (since > 0) {
            Finding("Decoy file", "Decoy file in place since ${java.text.DateFormat.getDateInstance().format(since)}",
                Level.OK, listOf("If canarytokens.org ever emails you about it, someone took files off this phone."),
                "canary")
        } else {
            Finding("Decoy file", "No decoy file yet", Level.NOTE, listOf(
                "A decoy \"Passwords backup\" file with a link only you know. Spyware that steals files will take " +
                    "it, and opening the link tells you, whatever way it got in. Tap to set one up."), "canary:off")
        })
    }

    fun canarySupported() = Build.VERSION.SDK_INT >= 29

    /** Writes the decoy to Documents, holding the canarytokens.org link the person made. */
    fun plantCanary(context: Context, link: String): Boolean {
        removeCanary(context)
        val values = ContentValues().apply {
            put(MediaStore.MediaColumns.DISPLAY_NAME, "Passwords backup.txt")
            put(MediaStore.MediaColumns.MIME_TYPE, "text/plain")
            put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOCUMENTS + "/")
        }
        val resolver = context.contentResolver
        val uri = resolver.insert(MediaStore.Files.getContentUri("external"), values) ?: return false
        resolver.openOutputStream(uri)?.use {
            it.write(("Password backup - keep private\n\nEmail and bank logins are saved on the recovery page:\n" +
                "$link\n").toByteArray())
        } ?: return false
        prefs(context).edit().putString("canary_uri", uri.toString())
            .putLong("canary_since", System.currentTimeMillis()).apply()
        return true
    }

    /** Removes Atlas's own decoy (never anything else). */
    fun removeCanary(context: Context) {
        prefs(context).getString("canary_uri", null)?.let {
            try {
                context.contentResolver.delete(Uri.parse(it), null, null)
            } catch (e: Exception) {
            }
        }
        prefs(context).edit().remove("canary_uri").remove("canary_since").apply()
    }

    fun hasCanary(context: Context) = prefs(context).contains("canary_uri")
}

/**
 * Notes when the microphone or camera is in use, and whether the screen was off. Android tells any app that they're
 * in use (not by whom), so it's cheap: no polling, only Android's own callbacks, while Atlas's text alerts or link
 * protection keep it running.
 */
object Sensors {
    private const val HOTWORD = 1999 // "Hey Google" listening, which is always on
    @Volatile private var started = false

    fun watching(context: Context) = TextWatch.on(context) || LinkGuard.enabled(context)

    fun start(context: Context) {
        if (started) return
        started = true
        val app = context.applicationContext
        val power = app.getSystemService(PowerManager::class.java)
        val audio = app.getSystemService(AudioManager::class.java)
        val handler = Handler(Looper.getMainLooper())
        fun calling() = audio.mode == AudioManager.MODE_IN_CALL || audio.mode == AudioManager.MODE_IN_COMMUNICATION
        var micStart = 0L
        var micOff = false
        var micCall = false
        audio.registerAudioRecordingCallback(object : AudioManager.AudioRecordingCallback() {
            override fun onRecordingConfigChanged(configs: MutableList<AudioRecordingConfiguration>) {
                val active = configs.any { it.clientAudioSource != HOTWORD }
                val now = System.currentTimeMillis()
                if (active && micStart == 0L) {
                    micStart = now
                    micOff = !power.isInteractive
                    micCall = calling()
                } else if (!active && micStart != 0L) {
                    record(app, SensorUse("Microphone", micStart, now, micOff, micCall || calling()))
                    micStart = 0L
                }
            }
        }, handler)
        val open = HashMap<String, Pair<Long, Boolean>>()
        app.getSystemService(CameraManager::class.java).registerAvailabilityCallback(
            object : CameraManager.AvailabilityCallback() {
                override fun onCameraUnavailable(id: String) {
                    open.getOrPut(id) { System.currentTimeMillis() to !power.isInteractive }
                }

                override fun onCameraAvailable(id: String) {
                    open.remove(id)?.let { (start, off) ->
                        record(app, SensorUse("Camera", start, System.currentTimeMillis(), off, calling()))
                    }
                }
            }, handler)
    }

    private fun prefs(context: Context) = context.getSharedPreferences("sensors", Context.MODE_PRIVATE)

    private fun record(context: Context, use: SensorUse) {
        val cutoff = System.currentTimeMillis() - 14 * DAY_MS
        val lines = listOf("${use.what}\t${use.start}\t${use.end}\t${use.screenOff}\t${use.inCall}") +
            prefs(context).getString("uses", "").orEmpty().lines().filter { it.isNotBlank() }
        val kept = lines.filter { (it.split('\t').getOrNull(2)?.toLongOrNull() ?: 0) > cutoff }.take(300)
        prefs(context).edit().putString("uses", kept.joinToString("\n")).apply()
    }

    fun uses(context: Context): List<SensorUse> = prefs(context).getString("uses", "").orEmpty().lines().mapNotNull {
        val p = it.split('\t')
        if (p.size != 5) return@mapNotNull null
        SensorUse(p[0], p[1].toLongOrNull() ?: return@mapNotNull null, p[2].toLongOrNull() ?: return@mapNotNull null,
            p[3] == "true", p[4] == "true")
    }
}
