package com.projectatlas.android

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.Settings
import android.text.InputType
import android.view.View
import android.view.ViewGroup
import android.widget.BaseAdapter
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ListView
import android.widget.TextView
import android.widget.Toast
import java.text.DateFormat
import java.util.Date
import kotlin.concurrent.thread

/** The app check: every app you've installed, riskiest first. */
class MainActivity : Activity() {
    private lateinit var status: TextView
    private lateinit var keyLine: TextView
    private lateinit var checkButton: Button
    private val adapter = AppAdapter()
    private var askedLimit = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val root = column()
        root.addView(text("Project Atlas", 26f, bold = true))
        keyLine = text("", 13f).apply { setOnClickListener { askForKey() } } // tap to add or change the key
        root.addView(keyLine)
        val buttons = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        checkButton = Button(this).apply {
            text = "Check my apps"
            setOnClickListener { AppCheck.start(this@MainActivity); refresh() }
        }
        buttons.addView(Button(this).apply {
            text = "Protection"
            setOnClickListener { startActivity(Intent(this@MainActivity, ProtectionActivity::class.java)) }
        }, LinearLayout.LayoutParams(0, -2, 1f))
        buttons.addView(Button(this).apply { text = "Check a message"; setOnClickListener { askForMessage() } },
            LinearLayout.LayoutParams(0, -2, 1f))
        buttons.addView(Button(this).apply { text = "Check a password"; setOnClickListener { askForPassword() } },
            LinearLayout.LayoutParams(0, -2, 1f))
        root.addView(buttons, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(8) })
        val screens = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        for ((label, open) in listOf<Pair<String, () -> Intent>>(
            "Storage" to { Intent(this, StorageActivity::class.java) },
            "Photos and videos" to { Intent(this, FilesActivity::class.java) },
            "Files and downloads" to { Intent(this, FilesActivity::class.java).putExtra(FilesActivity.MODE, FilesActivity.FILES_MODE) },
        )) {
            screens.addView(Button(this).apply { text = label; setOnClickListener { startActivity(open()) } },
                LinearLayout.LayoutParams(0, -2, 1f))
        }
        root.addView(screens)
        root.addView(text("You can also share a link, a message or a file to Project Atlas from any app, or select " +
            "text and choose \"Check with Project Atlas\".", 13f))
        root.addView(checkButton, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(8) })
        status = text("", 14f)
        root.addView(status, LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(10); bottomMargin = dp(6) })
        val list = ListView(this).apply {
            adapter = this@MainActivity.adapter
            setOnItemClickListener { _, _, position, _ -> showApp(this@MainActivity.adapter.getItem(position)) }
        }
        root.addView(list, LinearLayout.LayoutParams(-1, 0, 1f))
        showEdgeToEdge(root, dp(16))
        Watch.schedule(this)
        val prefs = getSharedPreferences("settings", MODE_PRIVATE)
        if (Watch.enabled(this) && !Watch.canNotify(this) && !prefs.getBoolean("asked_notifications", false) &&
            android.os.Build.VERSION.SDK_INT >= 33) {
            prefs.edit().putBoolean("asked_notifications", true).apply() // asked once; Protection can ask again
            requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS), 1)
        }
    }

    override fun onResume() {
        super.onResume()
        AppCheck.listener = ::refresh
        val key = ApiKey.load(this)
        keyLine.text = when {
            key == null -> "No VirusTotal key: Atlas checks what the phone shows. Tap to add one."
            else -> "VirusTotal key: connected, ${Prefs.speedText(this)}. Tap to change."
        }
        if (key != null && Prefs.keyLimit(this) == 0 && !askedLimit) { // keys saved before Atlas asked
            askedLimit = true
            thread(isDaemon = true) {
                Prefs.learnKeyLimit(this, key)
                if (Prefs.keyLimit(this) > 0) runOnUiThread { onResume() }
            }
        }
        if (AppCheck.rows.isEmpty() && !AppCheck.running) AppCheck.start(this)
        refresh()
    }

    override fun onPause() {
        super.onPause()
        AppCheck.listener = null
    }

    private fun refresh() {
        status.text = AppCheck.message
        checkButton.isEnabled = !AppCheck.running
        checkButton.text = if (AppCheck.running) "Checking your apps..." else "Check my apps again"
        adapter.show(AppCheck.rows)
    }

    private fun showApp(row: AppCheck.Row) {
        val facts = row.facts
        val dates = DateFormat.getDateInstance(DateFormat.MEDIUM)
        val lines = mutableListOf("${row.assessment.verdict.label}.", "")
        row.assessment.reasons.forEach { lines += "• $it" }
        lines += ""
        lines += "Package: ${facts.packageName}" + if (facts.version.isNotEmpty()) " (version ${facts.version})" else ""
        if (facts.installed > 0) lines += "Installed ${dates.format(Date(facts.installed))}, updated ${dates.format(Date(facts.updated))}"
        row.sha256?.let { lines += "Fingerprint (SHA-256): $it" }
        val dialog = AlertDialog.Builder(this)
            .setTitle(facts.label)
            .setMessage(lines.joinToString("\n"))
            // Uninstalling, or switching off its access, is yours to do from the app's own settings page.
            .setPositiveButton("App settings") { _, _ ->
                startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:${facts.packageName}")))
            }
            .setNegativeButton("Close", null)
        row.sha256?.let { hash -> dialog.setNeutralButton("VirusTotal") { _, _ -> openWeb(guiLink("file", hash)) } }
        dialog.show()
    }

    /** Paste a message (texts from Messages can be copied, even when an app won't share them). */
    private fun askForMessage() {
        val field = EditText(this).apply {
            hint = "Paste the message here"
            minLines = 3
        }
        val box = column().apply { setPadding(dp(20), dp(8), dp(20), 0); addView(field) }
        AlertDialog.Builder(this)
            .setTitle("Check a message")
            .setMessage("Atlas looks for the usual scam tricks on the phone, and checks the links with VirusTotal. Only " +
                "the links are sent, never the message.")
            .setView(box)
            .setPositiveButton("Check") { _, _ ->
                val message = field.text.toString()
                if (message.isNotBlank()) {
                    startActivity(Intent(this, ShareActivity::class.java).setAction(Intent.ACTION_SEND)
                        .setType("text/plain").putExtra(Intent.EXTRA_TEXT, message))
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    /** Has Have I Been Pwned seen this password? Only 5 characters of its fingerprint leave the phone. */
    private fun askForPassword() {
        val field = EditText(this).apply {
            hint = "The password to check"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        }
        val box = column().apply { setPadding(dp(20), dp(8), dp(20), 0); addView(field) }
        AlertDialog.Builder(this)
            .setTitle("Check a password")
            .setMessage("Has it appeared in a data leak? The password never leaves the phone: Atlas sends only the " +
                "first 5 characters of its fingerprint to Have I Been Pwned and compares the rest here. Nothing is saved.")
            .setView(box)
            .setPositiveButton("Check") { _, _ ->
                val password = field.text.toString()
                field.setText("")
                if (password.isEmpty()) return@setPositiveButton
                thread(isDaemon = true) {
                    val answer = try {
                        Pwned.verdict(Pwned.timesLeaked(password))
                    } catch (e: Exception) {
                        "Couldn't reach Have I Been Pwned (${e.message}). Try again when you're online."
                    }
                    runOnUiThread {
                        AlertDialog.Builder(this).setTitle("Password check").setMessage(answer).setPositiveButton("OK", null).show()
                    }
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun askForKey() {
        val field = EditText(this).apply {
            hint = "Paste your VirusTotal API key"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        }
        val paid = android.widget.CheckBox(this).apply {
            text = "Paid key (Premium or Enterprise): no 4-a-minute limit. Atlas also asks VirusTotal what your " +
                "key allows, and uses that when it says."
            isChecked = Prefs.paidTicked(this@MainActivity)
        }
        val box = column().apply { setPadding(dp(20), dp(8), dp(20), 0); addView(field); addView(paid) }
        AlertDialog.Builder(this)
            .setTitle("VirusTotal key")
            .setMessage("Free from virustotal.com (sign in, then API key). It stays on this phone, encrypted; Atlas " +
                "only sends it to VirusTotal. To change only the speed, leave the key empty.")
            .setView(box)
            .setPositiveButton("Save") { _, _ ->
                Prefs.setPaidKey(this, paid.isChecked)
                val key = field.text.toString().trim()
                if (key.isNotEmpty()) saveKey(key) else onResume() // only the speed changed
            }
            .setNeutralButton("Remove key") { _, _ -> ApiKey.save(this, null); Prefs.setKeyLimit(this, 0); onResume() }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun saveKey(key: String) {
        if (key.isEmpty()) return
        Toast.makeText(this, "Checking the key with VirusTotal...", Toast.LENGTH_SHORT).show()
        thread(isDaemon = true) {
            val problem = try {
                VirusTotal(key).file(VirusTotal.TEST_HASH)
                null
            } catch (e: BadKey) {
                "VirusTotal didn't accept that key."
            } catch (e: RateLimited) {
                null // it's a real key, just busy
            } catch (e: Exception) {
                "Couldn't reach VirusTotal (${e.message}). Try again when you're online."
            }
            if (problem == null) {
                Prefs.setKeyLimit(this, 0) // a new key: learn its own limit
                Prefs.learnKeyLimit(this, key)
            }
            runOnUiThread {
                if (problem != null) {
                    Toast.makeText(this, problem, Toast.LENGTH_LONG).show()
                } else {
                    ApiKey.save(this, key)
                    Toast.makeText(this, "Key saved.", Toast.LENGTH_SHORT).show()
                    onResume()
                    if (!AppCheck.running) AppCheck.start(this)
                }
            }
        }
    }

    private inner class AppAdapter : BaseAdapter() {
        private var rows: List<AppCheck.Row> = emptyList()

        fun show(all: List<AppCheck.Row>) {
            rows = all.sortedWith(compareByDescending<AppCheck.Row> { it.assessment.verdict.rank }
                .thenBy { it.facts.label.lowercase() })
            notifyDataSetChanged()
        }

        override fun getCount() = rows.size
        override fun getItem(position: Int) = rows[position]
        override fun getItemId(position: Int) = position.toLong()

        override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
            val row = rows[position]
            val view = (convertView as? LinearLayout) ?: column().apply {
                setPadding(0, dp(8), 0, dp(8))
                addView(text("", 16f, bold = true))
                addView(text("", 13f))
            }
            val verdict = row.assessment.verdict
            (view.getChildAt(0) as TextView).text = row.facts.label
            (view.getChildAt(1) as TextView).apply {
                text = verdict.label + " · " + (row.assessment.reasons.firstOrNull() ?: "")
                setTextColor(verdict.color)
            }
            return view
        }
    }
}
