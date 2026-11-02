package com.projectatlas.android

import android.app.Activity
import android.app.AlertDialog
import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import android.net.VpnService
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
        if (intent.getBooleanExtra(LinkGuard.SHOW, false)) showLinks()
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == VPN && resultCode == RESULT_OK) {
            LinkGuard.start(this)
            look()
        }
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
        val links = LinkGuard.enabled(this)
        val blocked = LinkGuard.count(this)
        lines += Line("Link protection: ${if (links) "on" else "off"}", (if (links) "Blocked $blocked " +
            "dangerous site${if (blocked == 1) "" else "s"} so far. Tap for recent blocks, allowed sites, or to " +
            "switch it off." else "Tap to block known malware and stalkerware sites in every app and browser.") +
            (if (links && LinkGuard.privateDnsBypasses(this)) " Private DNS is set to a provider, so Atlas can't " +
                "see lookups: tap to fix." else ""), if (links) Verdict.CLEAN.color else null, heading = true,
            onTap = { showLinks() })
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
        val kinds = listOfNotNull("stalkerware", if (sources.any { "spyware" in it }) "commercial spyware" else null,
            "monitoring apps", if (sources.any { "abuse.ch" in it }) "Android malware" else null)
        lines += Line("Threat data", "Known ${kinds.dropLast(1).joinToString(", ")} and ${kinds.last()}, from " +
            "$intel, by ${sources.size} sources. Atlas fetches a newer copy once a week. Tap for the sources.",
            heading = true, onTap = { showSources(sources) })
        adapter.lines = lines
    }

    private fun showLinks() {
        val bypass = if (LinkGuard.privateDnsBypasses(this)) "\n\nYour Private DNS is set to a provider's name, " +
            "which Android uses instead, so Atlas can't see lookups. Set Private DNS to Automatic for link " +
            "protection to work." else ""
        if (!LinkGuard.enabled(this)) {
            val dialog = AlertDialog.Builder(this).setTitle("Link protection").setMessage("Atlas looks at each site " +
                "name your apps look up, right on the phone, and answers \"no such site\" for the ones the threat " +
                "data lists as malware or stalkerware. Everything else goes on to your network's usual DNS, " +
                "unchanged.\n\nAndroid shows this as a VPN with a key icon, but only lookups go through it, never " +
                "your browsing, and nothing is sent anywhere else. Only one VPN can be on at a time." + bypass)
                .setPositiveButton("Switch on") { _, _ ->
                    val ask = VpnService.prepare(this)
                    if (ask == null) onActivityResult(VPN, RESULT_OK, null) else startActivityForResult(ask, VPN)
                }
                .setNegativeButton("Cancel", null)
            if (bypass.isNotEmpty()) dialog.setNeutralButton("Private DNS") { _, _ -> openSettings(PRIVATE_DNS) }
            dialog.show()
            return
        }
        val recent = LinkGuard.recent(this)
        val allowed = LinkGuard.allowed(this).sorted()
        val quad9 = LinkGuard.quad9(this)
        val choices = listOfNotNull(
            "Recently blocked (${recent.size})",
            "Allowed sites (${allowed.size})",
            if (quad9) "Look up sites with: Quad9" else "Look up sites with: this network's DNS",
            if (bypass.isNotEmpty()) "Fix Private DNS" else null,
            "Switch off",
        )
        AlertDialog.Builder(this).setTitle("Link protection: on").setItems(choices.toTypedArray()) { _, i ->
            when (choices[i]) {
                choices[0] -> showBlocked(recent)
                choices[1] -> showAllowed(allowed)
                choices[2] -> AlertDialog.Builder(this).setTitle("Look up sites with")
                    .setMessage("This network's DNS: whatever the Wi-Fi or mobile network uses, as without Atlas." +
                        "\n\nQuad9: a free, non-profit DNS service (quad9.net) that also blocks malicious sites " +
                        "itself. Your lookups go to Quad9 instead of the network.")
                    .setPositiveButton(if (quad9) "Use the network's" else "Use Quad9") { _, _ ->
                        LinkGuard.setQuad9(this, !quad9)
                    }.setNegativeButton("Cancel", null).show()
                "Fix Private DNS" -> openSettings(PRIVATE_DNS)
                else -> {
                    LinkGuard.stop(this)
                    look()
                }
            }
        }.setNegativeButton("Close", null).show()
    }

    private fun showBlocked(recent: List<LinkGuard.Blocked>) {
        if (recent.isEmpty()) {
            AlertDialog.Builder(this).setTitle("Recently blocked").setMessage("Nothing blocked yet.")
                .setPositiveButton("OK", null).show()
            return
        }
        val now = System.currentTimeMillis()
        val items = recent.map { "${it.host}\n${it.family.name} (${it.family.what}), ${ago(now - it.time)}" }
        AlertDialog.Builder(this).setTitle("Recently blocked: tap to allow").setItems(items.toTypedArray()) { _, i ->
            val b = recent[i]
            AlertDialog.Builder(this).setTitle("Allow ${b.host}?").setMessage("The threat data lists it as a site " +
                "${b.family.name} (${b.family.what}) uses. Allow it only if you're sure it's safe.")
                .setPositiveButton("Allow") { _, _ -> LinkGuard.allow(this, b.host, true) }
                .setNegativeButton("Cancel", null).show()
        }.setNegativeButton("Close", null).show()
    }

    private fun showAllowed(allowed: List<String>) {
        if (allowed.isEmpty()) {
            AlertDialog.Builder(this).setTitle("Allowed sites").setMessage("None: every listed site is blocked.")
                .setPositiveButton("OK", null).show()
            return
        }
        AlertDialog.Builder(this).setTitle("Allowed sites: tap to block again").setItems(allowed.toTypedArray()) { _, i ->
            LinkGuard.allow(this, allowed[i], false)
        }.setNegativeButton("Close", null).show()
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

    private companion object {
        const val VPN = 2
        const val PRIVATE_DNS = "android.settings.NETWORK_AND_INTERNET_SETTINGS" // Private DNS is on this page
    }

    private fun appSettings(pkg: String) =
        startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:$pkg")))
}
