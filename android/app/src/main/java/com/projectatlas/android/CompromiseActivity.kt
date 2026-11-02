package com.projectatlas.android

import android.app.Activity
import android.app.AlertDialog
import android.content.ActivityNotFoundException
import android.content.Intent
import android.os.Bundle
import android.provider.Settings
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ListView
import android.widget.TextView
import kotlin.concurrent.thread

/** "Is someone watching?": the layered compromise check, and what to do when it finds something. */
class CompromiseActivity : Activity() {
    private lateinit var summary: TextView
    private lateinit var again: Button
    private val adapter = LineAdapter(this)
    private var warned = false // the deep-check pop-up shows once per visit

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val root = column()
        root.addView(text("Is someone watching?", 24f, bold = true))
        summary = text("Checking the phone...", 14f)
        root.addView(summary)
        root.addView(ListView(this).apply {
            adapter = this@CompromiseActivity.adapter
            setOnItemClickListener { _, _, position, _ -> this@CompromiseActivity.adapter.getItem(position).onTap?.invoke() }
        }, LinearLayout.LayoutParams(-1, 0, 1f))
        again = Button(this).apply { text = "Check again"; setOnClickListener { look() } }
        root.addView(again)
        showEdgeToEdge(root, dp(16))
        look()
    }

    private fun look() {
        again.isEnabled = false
        summary.text = "Checking the phone... (asking its security chip takes a moment)"
        thread(isDaemon = true) {
            val findings = try {
                Compromise.run(this, online = true)
            } catch (e: Exception) {
                emptyList()
            }
            runOnUiThread { show(findings) }
        }
    }

    private fun show(findings: List<Finding>) {
        again.isEnabled = true
        val warns = findings.filter { it.level == Level.WARN }
        summary.text = if (warns.isEmpty()) "No sign of spyware. No app can prove a phone is clean, but each layer " +
            "below looks where spyware has to show itself." else "${warns.size} sign${if (warns.size == 1) "" else "s"} " +
            "worth a closer look. Tap one to see why."
        summary.setTextColor(if (warns.isEmpty()) Verdict.CLEAN.color else Verdict.MALICIOUS.color)
        val lines = mutableListOf<Line>()
        for ((area, list) in findings.groupBy { it.area }) {
            lines += Line(area, LAYERS[area].orEmpty(), heading = true)
            for (f in list) {
                val color = when (f.level) {
                    Level.WARN -> Verdict.MALICIOUS.color
                    Level.NOTE -> Verdict.SUSPICIOUS.color
                    Level.OK -> Verdict.CLEAN.color
                }
                val mark = when (f.level) { Level.WARN -> "Needs a look"; Level.NOTE -> "Worth knowing"; Level.OK -> "OK" }
                lines += Line(f.title, mark, color, onTap = {
                    if (f.key.startsWith("canary")) setUpCanary() else showFinding(f)
                })
            }
        }
        adapter.lines = lines
        if (warns.isNotEmpty() && !warned) {
            warned = true
            deepCheck(warns)
        }
    }

    /** What to do next: the deep check over USB, and, when you're sure, a clean start. */
    private fun deepCheck(warns: List<Finding>) {
        AlertDialog.Builder(this).setTitle("Take a closer look")
            .setMessage("Atlas found: ${warns.joinToString("; ") { it.title }}.\n\n" +
                "Deep check: connect this phone by USB to a computer with Atlas for Windows. Over the cable Atlas " +
                "can see what no app on the phone can (every app and process, and Android's own logs) and check them " +
                "against the same spyware lists. This is coming to Atlas for Windows.\n\n" +
                "If you're sure the phone is compromised: back up your photos and contacts (not apps), reset the " +
                "phone to factory settings or replace it, then change your important passwords from another device. " +
                "Until then, keep sensitive talks and accounts off this phone.")
            .setPositiveButton("OK", null).show()
    }

    private fun showFinding(f: Finding) {
        val dialog = AlertDialog.Builder(this).setTitle(f.title).setMessage(f.details.joinToString("\n\n"))
            .setNegativeButton("Close", null)
        f.settings?.let { action ->
            dialog.setPositiveButton("Open settings") { _, _ ->
                try {
                    startActivity(Intent(action))
                } catch (e: ActivityNotFoundException) {
                    startActivity(Intent(Settings.ACTION_SETTINGS))
                }
            }
        }
        if (f.key.startsWith("spyware:") || f.key == "sensors:microphone" || f.key == "sensors:camera") {
            dialog.setNeutralButton("App check") { _, _ -> startActivity(Intent(this, MainActivity::class.java)) }
        }
        dialog.show()
    }

    private fun setUpCanary() {
        if (!Compromise.canarySupported()) {
            AlertDialog.Builder(this).setMessage("Decoy files need Android 10 or later.").setPositiveButton("OK", null).show()
            return
        }
        if (Compromise.hasCanary(this)) {
            AlertDialog.Builder(this).setTitle("Decoy file")
                .setMessage("\"Passwords backup.txt\" is in Documents. If canarytokens.org ever emails you about its " +
                    "link, someone took files off this phone. Don't open it yourself: that sets it off too.")
                .setPositiveButton("Keep it", null)
                .setNegativeButton("Remove it") { _, _ -> Compromise.removeCanary(this); look() }.show()
            return
        }
        val link = EditText(this).apply { hint = "Paste the canarytokens.org link"; isSingleLine = true }
        val box = column().apply { setPadding(dp(20), 0, dp(20), 0); addView(link) }
        val dialog = AlertDialog.Builder(this).setTitle("Set a decoy file")
            .setMessage("1. Open canarytokens.org and make a \"Web bug / URL token\": enter your email and a note " +
                "like \"Atlas phone decoy\". It's free, and the link it makes is yours alone.\n" +
                "2. Copy that link and paste it here.\n\n" +
                "Atlas puts it in a decoy \"Passwords backup.txt\" in Documents. Spyware that steals files takes it, " +
                "and when the thief opens the link, canarytokens.org emails you, however they got in.")
            .setView(box)
            .setNeutralButton("Open canarytokens.org") { _, _ -> openWeb("https://canarytokens.org/nest/") }
            .setPositiveButton("Plant decoy", null)
            .setNegativeButton("Cancel", null)
            .show()
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
            val url = link.text.toString().trim()
            if (!url.startsWith("http://") && !url.startsWith("https://")) {
                link.error = "Paste the whole link, starting with http"
                return@setOnClickListener
            }
            val ok = try {
                Compromise.plantCanary(this, url)
            } catch (e: Exception) {
                false
            }
            dialog.dismiss()
            android.widget.Toast.makeText(this, if (ok) "Decoy planted in Documents." else "Couldn't write the decoy.",
                android.widget.Toast.LENGTH_LONG).show()
            look()
        }
    }

    private companion object {
        /** What each layer looks at, under its heading. */
        val LAYERS = mapOf(
            "Start-up proof" to "The security chip vouches for how the phone started",
            "Hardening" to "Harder to break into",
            "Microphone and camera" to "Use while the screen was off",
            "What changed" to "New powers that let an app watch you",
            "Uploads" to "Android's own uploads against its usual",
            "Known spyware" to "Commercial spyware and stalkerware, from the threat data",
            "Decoy file" to "Catches file theft, however it got in",
        )
    }
}
