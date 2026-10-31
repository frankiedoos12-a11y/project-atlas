package com.projectatlas.android

import android.app.Activity
import android.app.AlertDialog
import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.Settings
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ListView
import android.widget.TextView
import kotlin.concurrent.thread

/** Protection: the phone's settings that keep it safe, a health score as on Windows, and data use per app. */
class ProtectionActivity : Activity() {
    private lateinit var score: TextView
    private lateinit var summary: TextView
    private lateinit var automatic: Button
    private val adapter = LineAdapter(this)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val root = column()
        root.addView(text("Protection", 24f, bold = true))
        score = text("", 22f, bold = true)
        root.addView(score)
        summary = text("Looking at the phone...", 14f)
        root.addView(summary)
        root.addView(ListView(this).apply {
            adapter = this@ProtectionActivity.adapter
            setOnItemClickListener { _, _, position, _ -> this@ProtectionActivity.adapter.getItem(position).onTap?.invoke() }
        }, LinearLayout.LayoutParams(-1, 0, 1f))
        val buttons = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        buttons.addView(Button(this).apply { text = "Check again"; setOnClickListener { look() } },
            LinearLayout.LayoutParams(0, -2, 1f))
        automatic = Button(this).apply { setOnClickListener { toggleAutomatic() } }
        buttons.addView(automatic, LinearLayout.LayoutParams(0, -2, 1f))
        root.addView(buttons)
        showEdgeToEdge(root, dp(16))
    }

    override fun onResume() {
        super.onResume()
        look() // back from a settings page: show what changed
        showAutomatic()
    }

    private fun showAutomatic() {
        automatic.text = if (Watch.enabled(this)) "Automatic checks: on" else "Automatic checks: off"
    }

    private fun toggleAutomatic() {
        val on = !Watch.enabled(this)
        Watch.setEnabled(this, on)
        showAutomatic()
        val text = if (!on) "Atlas won't check in the background. The checks on each screen still work." else
            "Once a day Atlas checks new and updated apps and these settings, and it checks new downloads as they " +
                "arrive (with All files access). It tells you with a notification only when something needs a look." +
                if (Watch.canNotify(this)) "" else "\n\nAllow notifications for Project Atlas, or you won't see them."
        AlertDialog.Builder(this).setTitle(automatic.text).setMessage(text).setPositiveButton("OK") { _, _ ->
            if (on && !Watch.canNotify(this) && android.os.Build.VERSION.SDK_INT >= 33) {
                requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS), 1)
            }
        }.show()
    }

    private fun look() {
        thread(isDaemon = true) {
            val now = System.currentTimeMillis()
            val findings = phoneFindings(Phone.facts(this), java.time.LocalDate.now())
            val usage = Media.usageAccess(this)
            val uses = if (usage) Phone.dataUse(this, now) else emptyList()
            val all = findings + quietUploaders(uses, now)
            val result = healthScore(all)
            Watch.remember(this, all) // the daily check compares with this
            runOnUiThread { show(all, result, uses, usage) }
        }
    }

    private fun show(findings: List<Finding>, result: Score, uses: List<DataUse>, usage: Boolean) {
        score.text = "Health score ${result.text}"
        score.setTextColor(when (result.label) {
            "Good" -> Verdict.CLEAN.color
            "Fair" -> Verdict.SUSPICIOUS.color
            else -> Verdict.MALICIOUS.color
        })
        val warns = findings.count { it.level == Level.WARN }
        summary.text = when {
            warns == 0 && result.notes == 0 -> "Nothing needs a look."
            warns == 0 -> "Nothing serious; ${result.notes} thing${if (result.notes == 1) "" else "s"} worth knowing."
            else -> "$warns thing${if (warns == 1) " needs" else "s need"} a look. Tap one to see why and how to fix it."
        } + if (AppCheck.rows.isEmpty()) " (Open the app check once so apps count too.)" else ""
        val lines = mutableListOf<Line>()
        val texts = TextWatch.on(this)
        val seen = TextWatch.lastSeen(this)
        lines += Line("Scam alerts for texts: ${if (texts) "on" else "off"}", if (texts) (seen?.let { "$it. " } ?:
            "No message checked yet: one arrives as a notification. ") + "Tap to try a sample or change it." else
            "Tap to have Atlas warn you when a text, chat or email looks like a scam.", if (texts) Verdict.CLEAN.color else null,
            heading = true, onTap = { explainTextAlerts(texts) })
        lines += Line("Checks", "Tap one for details", heading = true)
        for (f in findings) {
            val color = when (f.level) {
                Level.WARN -> Verdict.MALICIOUS.color
                Level.NOTE -> Verdict.SUSPICIOUS.color
                Level.OK -> Verdict.CLEAN.color
            }
            val mark = when (f.level) { Level.WARN -> "Needs a look"; Level.NOTE -> "Worth knowing"; Level.OK -> "OK" }
            lines += Line(f.title, "$mark · ${f.area}", color, onTap = if (f.level == Level.OK) null else ({ showFinding(f) }))
        }
        lines += Line("Data use, last 7 days", if (usage) "Wi-Fi and mobile data together; tap an app for its settings"
            else "Switch on Usage access to see which apps send and receive the most. Tap here.", heading = true, onTap = if (usage) null else ({ startActivity(Media.usageSettings(this)) }))
        for (u in uses.take(15)) {
            lines += Line(u.label, "Sent ${humanSize(u.sent)} (${humanSize(u.backgroundSent)} in the background), " +
                "received ${humanSize(u.received)}", onTap = { appSettings(u.packageName) })
        }
        val intel = try {
            IntelStore.get(this).version.toString().let { "${it.take(4)}-${it.drop(4).take(2)}-${it.drop(6)}" }
        } catch (e: Exception) {
            "unavailable"
        }
        val sources = try {
            IntelStore.get(this).sources
        } catch (e: Exception) {
            emptyList()
        }
        val names = sources.map { it.substringBefore(", http") }
        lines += Line("Threat data", "Known stalkerware, monitoring apps" + (if (sources.size > 1) " and Android " +
            "malware" else "") + ", from $intel: ${names.joinToString("; ")}. Atlas fetches a newer copy once a week. " +
            "Tap for the sources.", heading = true, onTap = { showSources(sources) })
        adapter.lines = lines
    }

    private fun showSources(sources: List<String>) {
        val links = sources.mapNotNull { s -> s.substringAfterLast(", ").takeIf { it.startsWith("https://") } }
        if (links.size == 1) return openWeb(links.single())
        AlertDialog.Builder(this).setTitle("Threat data sources")
            .setItems(sources.map { it.substringBefore(", http") }.toTypedArray()) { _, i -> links.getOrNull(i)?.let(::openWeb) }
            .setNegativeButton("Close", null).show()
    }

    private fun explainTextAlerts(on: Boolean) {
        val message = "Atlas runs its scam rules on each new message from your texting, chat and email apps, right " +
            "on the phone, and warns you when one looks like a scam. Messages are never saved or sent anywhere; with " +
            "a VirusTotal key, only the links in a message that already looks wrong are looked up.\n\n" +
            (if (on) "Try a sample scam to see what an alert looks like. A text you send yourself may not show a " +
                "notification while that conversation is open, and Atlas only sees messages that do. To stop, switch " +
                "off Project Atlas in Settings." else "On the next screen, switch on " +
                "Project Atlas. If Android says it's a restricted setting: App info for Project Atlas, the ⋮ menu, " +
                "Allow restricted settings, then try again.")
        val dialog = AlertDialog.Builder(this).setTitle("Scam alerts for texts").setMessage(message)
        if (on) dialog.setNeutralButton("Try a sample scam") { _, _ -> trySample() }
        dialog.setPositiveButton(if (on) "Settings" else "Open settings") { _, _ ->
                try {
                    startActivity(TextWatch.settings(this))
                } catch (e: ActivityNotFoundException) {
                    startActivity(Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS))
                }
            }
            .setNegativeButton("Cancel", null).show()
    }

    /** Runs a made-up scam text through the same check a real one gets, so you see the alert without a real scam. */
    private fun trySample() {
        if (!Watch.canNotify(this)) {
            AlertDialog.Builder(this).setMessage("Allow notifications for Project Atlas first, or alerts can't show.")
                .setPositiveButton("OK") { _, _ ->
                    if (android.os.Build.VERSION.SDK_INT >= 33) {
                        requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS), 1)
                    }
                }.show()
            return
        }
        thread(isDaemon = true) {
            val alerted = TextWatch.check(this, "Sample (made up by Atlas)", TextWatch.SAMPLE)
            runOnUiThread {
                android.widget.Toast.makeText(this, if (alerted) "Sent: look for the alert in your notifications."
                    else "The sample didn't alert. Please tell the Atlas developer.", android.widget.Toast.LENGTH_LONG).show()
            }
        }
    }

    private fun showFinding(f: Finding) {
        val dialog = AlertDialog.Builder(this).setTitle(f.title).setMessage(f.details.joinToString("\n\n"))
            .setNegativeButton("Close", null)
        when {
            f.settings != null -> dialog.setPositiveButton("Open settings") { _, _ -> openSettings(f.settings) }
            f.key.startsWith("upload:") -> dialog.setPositiveButton("App settings") { _, _ -> appSettings(f.key.removePrefix("upload:")) }
        }
        dialog.show()
    }

    private fun openSettings(action: String) {
        try {
            startActivity(Intent(action))
        } catch (e: ActivityNotFoundException) {
            startActivity(Intent(Settings.ACTION_SETTINGS)) // this phone names the page differently
        }
    }

    private fun appSettings(pkg: String) =
        startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:$pkg")))
}
