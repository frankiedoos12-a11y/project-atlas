package com.projectatlas.android

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.Settings
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ListView
import android.widget.TextView
import kotlin.concurrent.thread

/** How the phone's space is used: each app's size, and the apps you haven't opened in months. */
class StorageActivity : Activity() {
    private lateinit var summary: TextView
    private lateinit var allow: Button
    private lateinit var appInfo: Button
    private val adapter = LineAdapter(this)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val root = column()
        root.addView(text("Storage", 24f, bold = true))
        summary = text("", 14f)
        root.addView(summary)
        allow = Button(this).apply {
            text = "Allow usage access"
            setOnClickListener { startActivity(Media.usageSettings(this@StorageActivity)) }
        }
        appInfo = Button(this).apply {
            text = "Open Atlas's App info"
            setOnClickListener {
                startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:$packageName")))
            }
        }
        val buttons = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        buttons.addView(allow, LinearLayout.LayoutParams(0, -2, 1f))
        buttons.addView(appInfo, LinearLayout.LayoutParams(0, -2, 1f))
        root.addView(buttons)
        root.addView(ListView(this).apply {
            adapter = this@StorageActivity.adapter
            setOnItemClickListener { _, _, position, _ -> this@StorageActivity.adapter.getItem(position).onTap?.invoke() }
        }, LinearLayout.LayoutParams(-1, 0, 1f))
        showEdgeToEdge(root, dp(16))
    }

    override fun onResume() {
        super.onResume()
        load()
    }

    private fun load() {
        val (total, free) = Media.phoneSpace(this)
        val space = "${humanSize(total - free)} used of ${humanSize(total)} (${humanSize(free)} free)."
        if (!Media.usageAccess(this)) {
            summary.text = "$space\n\nTo show each app's data and cache, and which apps you haven't opened in months, " +
                "Atlas needs Usage access: tap \"Allow usage access\", find Project Atlas and switch it on. Atlas only " +
                "reads sizes and when each app was last opened; nothing leaves the phone.\n\nIf Android says it's a " +
                "\"restricted setting\" (it does for apps installed from a file rather than a store): tap \"Open " +
                "Atlas's App info\", then the ⋮ menu at the top right, \"Allow restricted settings\", and confirm. " +
                "Then try \"Allow usage access\" again.\n\nMeanwhile, the size of each app you installed:"
            allow.visibility = Button.VISIBLE
            appInfo.visibility = Button.VISIBLE
            thread(isDaemon = true) {
                val sizes = try {
                    Media.appFileSizes(this)
                } catch (e: Exception) {
                    emptyList()
                }
                runOnUiThread {
                    adapter.lines = listOf(Line("Apps by size", "The apps' own files only, without data and cache",
                        heading = true)) + sizes.map { (label, size) -> Line(label, humanSize(size)) }
                }
            }
            return
        }
        allow.visibility = Button.GONE
        appInfo.visibility = Button.GONE
        summary.text = "$space\nLooking at your apps..."
        thread(isDaemon = true) {
            val apps = try {
                Media.appUse(this)
            } catch (e: Exception) {
                runOnUiThread { summary.text = "$space\nCouldn't read app sizes: ${e.message}" }
                return@thread
            }
            runOnUiThread { show(space, apps) }
        }
    }

    private fun show(space: String, apps: List<AppUse>) {
        val now = System.currentTimeMillis()
        val unused = unusedApps(apps, now)
        val cache = apps.sumOf { it.cacheBytes }
        summary.text = "$space\nApps take ${humanSize(apps.sumOf { it.total })}, including ${humanSize(cache)} of cache " +
            "(files apps keep to load faster, and download again if removed). Tap an app to open its settings, " +
            "where you can clear its cache or uninstall it."
        val lines = mutableListOf<Line>()
        lines += Line("Not opened in ${UNUSED_DAYS / 30} months", if (unused.isEmpty()) "None: you use all your apps."
            else "${unused.size} apps, ${humanSize(unused.sumOf { it.total })} in all", heading = true)
        unused.forEach { lines += row(it, now, unusedNote = true) }
        lines += Line("Apps by space", heading = true)
        apps.sortedByDescending { it.total }.forEach { lines += row(it, now, unusedNote = false) }
        adapter.lines = lines
    }

    private fun row(app: AppUse, now: Long, unusedNote: Boolean) = Line(
        app.label,
        "${humanSize(app.total)} · ${lastUsedText(app, now)}" + if (app.system && unusedNote) " · came with the phone" else "",
        color = if (unusedNote) Verdict.UNKNOWN.color else null,
        onTap = { showApp(app, now) },
    )

    private fun showApp(app: AppUse, now: Long) {
        val lines = mutableListOf(spaceText(app), lastUsedText(app, now) + ".")
        if (app.cacheBytes > 50L shl 20) lines += "Clearing its cache frees ${humanSize(app.cacheBytes)}; the app rebuilds " +
            "what it needs."
        lines += if (app.system) {
            "It came with the phone, so it can't be uninstalled; if you don't need it, its settings may let you " +
                "switch it off (Disable)."
        } else {
            "If you don't need it, uninstall it from its settings."
        }
        AlertDialog.Builder(this)
            .setTitle(app.label)
            .setMessage(lines.joinToString("\n\n"))
            // Clearing a cache, uninstalling or disabling is yours to do, on Android's own page.
            .setPositiveButton("App settings") { _, _ ->
                startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:${app.packageName}")))
            }
            .setNegativeButton("Close", null)
            .show()
    }
}
