package com.projectatlas.android

import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.OpenableColumns
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import java.io.File
import kotlin.concurrent.thread

/** Something shared to Atlas from another app: the links in a message, or a file. */
class ShareActivity : Activity() {
    private lateinit var results: LinearLayout

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        results = column()
        val root = column().apply {
            addView(text("Project Atlas", 22f, bold = true))
            addView(ScrollView(this@ShareActivity).apply { addView(results) }, LinearLayout.LayoutParams(-1, 0, 1f))
            addView(Button(this@ShareActivity).apply { text = "Done"; setOnClickListener { finish() } })
        }
        showEdgeToEdge(root, dp(16))
        val shared = streamOf(intent)
        val message = sharedText(intent)
        val textFile = shared != null && intent.type.orEmpty().startsWith("text/")
        when {
            shared != null && !textFile -> checkFile(shared)
            message != null -> checkLinks(message)
            shared != null -> readText(shared)?.let(::checkLinks) ?: checkFile(shared)
            else -> {
                line("Nothing to check arrived. Copy the message, then use \"Check a message\" in Project Atlas.")
                line("What arrived: ${intent.action}, ${intent.type}, ${intent.extras?.keySet()?.joinToString()}", 12f)
            }
        }
    }

    /** Apps share text as plain text or with formatting (getStringExtra misses that), or select it ("Check..."). */
    private fun sharedText(intent: Intent): String? = listOf(
        intent.getCharSequenceExtra(Intent.EXTRA_PROCESS_TEXT),
        intent.getCharSequenceExtra(Intent.EXTRA_TEXT),
        intent.getStringExtra(Intent.EXTRA_HTML_TEXT)?.replace(Regex("<[^>]+>"), " "),
    ).firstOrNull { !it.isNullOrBlank() }?.toString()

    /** A shared text file (some apps share a message that way): its first 64 KB. */
    private fun readText(uri: Uri): String? = try {
        contentResolver.openInputStream(uri)?.use { String(it.readNBytesCompat(64 * 1024)) }?.takeIf { it.isNotBlank() }
    } catch (e: Exception) {
        null
    }

    private fun java.io.InputStream.readNBytesCompat(limit: Int): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        val buffer = ByteArray(8192)
        while (out.size() < limit) {
            val read = read(buffer, 0, minOf(buffer.size, limit - out.size()))
            if (read < 0) break
            out.write(buffer, 0, read)
        }
        return out.toByteArray()
    }

    private fun streamOf(intent: Intent): Uri? = if (Build.VERSION.SDK_INT >= 33) {
        intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)
    } else {
        @Suppress("DEPRECATION") intent.getParcelableExtra(Intent.EXTRA_STREAM)
    }

    private fun line(value: String, size: Float = 15f, bold: Boolean = false, color: Int? = null) {
        results.addView(text(value, size, bold, color), LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(6) })
    }

    private fun verdictLine(verdict: Verdict, what: String) = line("${verdict.label}: $what", 18f, true, verdict.color)

    private fun webButton(label: String, address: String) {
        results.addView(Button(this).apply { text = label; setOnClickListener { openWeb(address) } })
    }

    /** The scam rules first (instant, on the phone), then each link with VirusTotal, which can raise the verdict. */
    private fun checkLinks(message: String) {
        val intel = try {
            IntelStore.get(this)
        } catch (e: Exception) {
            null
        }
        val reasons = wordReasons(message) + siteReasons(extractLinks(message)) { intel?.site(it) }
        var score = reasons.sumOf { it.weight }
        val verdict = text("", 20f, bold = true)
        val about = text("", 14f)
        results.addView(verdict)
        results.addView(about)
        fun showVerdict(note: String = "") {
            val name = scamVerdict(score)
            verdict.text = name
            verdict.setTextColor(scamColor(name))
            about.text = scamSummary(name) + note
        }
        showVerdict()
        for (r in reasons) {
            line("• ${r.title}", 15f, bold = true)
            line(r.why, 14f)
            line("“${r.quote}”", 13f)
        }
        val links = extractLinks(message)
        if (links.isEmpty()) {
            if (reasons.isEmpty()) line("“${message.trim().take(300)}”", 13f)
            return
        }
        val key = ApiKey.load(this)
        if (key == null) {
            showVerdict(" The links weren't checked: add a VirusTotal key in Project Atlas. Meanwhile you can look them up yourself:")
            links.take(5).forEach { webButton("Look up ${hostOf(it)}", guiLink("domain", hostOf(it))) }
            return
        }
        line("Links", 17f, bold = true)
        line("Checking ${links.size} link${if (links.size == 1) "" else "s"} with VirusTotal...", 14f)
        showVerdict(" Still checking the links...")
        thread(isDaemon = true) {
            val vt = VirusTotal(key)
            val most = if (Prefs.paidKey(this)) 20 else VirusTotal.LOOKUPS_PER_MINUTE
            for (link in links.take(most)) {
                val host = hostOf(link)
                val (site, detail) = try {
                    val report = patiently { vt.url(link) }
                    if (report.found) {
                        siteVerdict(report) to "VirusTotal: ${report.detail}"
                    } else { // a link nobody has checked yet: what's known about the site
                        val known = patiently { vt.domain(host) }
                        siteVerdict(known) to if (known.found) "This exact link isn't known; the site: ${known.detail}"
                        else "VirusTotal doesn't know this site"
                    }
                } catch (e: Exception) {
                    Verdict.UNKNOWN to "The check didn't finish: ${e.message}"
                }
                runOnUiThread {
                    score += linkPoints(site)
                    verdictLine(site, host)
                    line(link, 13f)
                    line(detail, 14f)
                    webButton("Open on VirusTotal", guiLink("url", link))
                }
            }
            runOnUiThread {
                showVerdict(if (links.size > most) " Only the first $most links were checked." else "")
            }
        }
    }

    private fun checkFile(uri: Uri) {
        val name = displayName(uri)
        line(name, 16f, bold = true)
        line("Fingerprinting the file...")
        thread(isDaemon = true) {
            try {
                val hash = contentResolver.openInputStream(uri)?.let(::sha256) ?: throw IllegalStateException("can't open it")
                val apk = if (name.endsWith(".apk", true) || contentResolver.getType(uri) == APK) readApk(uri) else null
                val key = ApiKey.load(this)
                val report = key?.let {
                    Answers(this).report(hash) ?: patiently { VirusTotal(it).file(hash) }.also { r -> Answers(this).save(hash, r) }
                }
                val intel = try {
                    IntelStore.get(this)
                } catch (e: Exception) {
                    null
                }
                val hit = intel?.app(apk?.packageName, apk?.signers.orEmpty(), hash)
                runOnUiThread { showFile(hash, apk, report, key != null, hit) }
            } catch (e: Exception) {
                runOnUiThread { line("The check didn't finish: ${e.message}") }
            }
        }
    }

    private fun showFile(hash: String, apk: AppFacts?, report: VtReport?, haveKey: Boolean, hit: IntelHit?) {
        if (apk == null && hit != null) {
            val (verdict, why) = intelReason(hit)
            verdictLine(verdict, hit.family.name)
            line(why, 14f)
        }
        if (apk != null) {
            // An app that isn't installed: judged as if it came from outside a store, with everything it asks for.
            val assessment = assess(apk, report, hit)
            verdictLine(assessment.verdict, "${apk.label} (an app to install)")
            assessment.reasons.filterNot { it.startsWith("Not from an app store") }.forEach { line("• $it", 14f) }
            line("An app file from outside an app store: only install it if you trust where it came from.", 14f)
        } else if (report != null) {
            verdictLine(fileVerdict(report), if (report.found) "VirusTotal: ${report.detail}" else "VirusTotal doesn't know this file")
        }
        if (!haveKey) line("Add a VirusTotal key in Project Atlas to check files with about 70 antivirus engines.", 14f)
        line("Fingerprint (SHA-256): $hash", 12f)
        webButton("Open on VirusTotal", guiLink("file", hash))
    }

    private fun readApk(uri: Uri): AppFacts? {
        val copy = File(cacheDir, "shared.apk")
        return try {
            contentResolver.openInputStream(uri)?.use { input -> copy.outputStream().use { input.copyTo(it) } }
            val pm = packageManager
            val flags = PackageManager.GET_PERMISSIONS or if (Build.VERSION.SDK_INT >= 28) {
                PackageManager.GET_SIGNING_CERTIFICATES
            } else {
                @Suppress("DEPRECATION") PackageManager.GET_SIGNATURES
            }
            val found = if (Build.VERSION.SDK_INT >= 33) {
                pm.getPackageArchiveInfo(copy.path, PackageManager.PackageInfoFlags.of(flags.toLong()))
            } else {
                @Suppress("DEPRECATION") pm.getPackageArchiveInfo(copy.path, flags)
            }
            val info = found ?: return null
            val app = info.applicationInfo?.apply { sourceDir = copy.path; publicSourceDir = copy.path }
            AppFacts(
                label = app?.loadLabel(pm)?.toString() ?: info.packageName,
                packageName = info.packageName,
                installer = null,
                granted = info.requestedPermissions?.toSet() ?: emptySet(), // what it would ask for
                version = info.versionName ?: "",
                signers = Device.signers(info),
            )
        } catch (e: Exception) {
            null
        } finally {
            copy.delete()
        }
    }

    private fun displayName(uri: Uri): String = try {
        contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use {
            if (it.moveToFirst()) it.getString(0) else null
        }
    } catch (e: Exception) {
        null
    } ?: uri.lastPathSegment ?: "Shared file"

    companion object {
        const val APK = "application/vnd.android.package-archive"
    }
}
