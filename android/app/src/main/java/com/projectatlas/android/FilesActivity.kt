package com.projectatlas.android

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ListView
import android.widget.TextView
import kotlin.concurrent.thread

/**
 * Photos and videos (mode "media"): duplicates and the biggest files. Files and downloads (mode "files", with All
 * files access): the same for everything in the phone's shared storage, plus a malware check of app files, programs
 * and documents with VirusTotal. Atlas never removes a file itself: Android asks "Move to trash?" first.
 */
class FilesActivity : Activity() {
    private lateinit var summary: TextView
    private lateinit var allow: Button
    private lateinit var trashAll: Button
    private val adapter = LineAdapter(this)
    private val media get() = intent.getStringExtra(MODE) != FILES_MODE
    @Volatile private var generation = 0 // a newer look replaces an older one still running
    private var groups: List<DuplicateGroup> = emptyList()
    private var big: List<FileItem> = emptyList()
    private val risky = mutableListOf<Pair<FileItem, VtReport?>>()
    private val knownBad = mutableMapOf<String, Family>() // by uri: in the threat data, no key needed
    private var scanned = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val root = column()
        root.addView(text(if (media) "Photos and videos" else "Files and downloads", 24f, bold = true))
        summary = text("", 14f)
        root.addView(summary)
        allow = Button(this).apply { setOnClickListener { askForAccess() } }
        root.addView(allow)
        trashAll = Button(this).apply {
            setOnClickListener { trash(groups.flatMap { it.extras }) }
            visibility = Button.GONE
        }
        root.addView(trashAll)
        root.addView(ListView(this).apply {
            adapter = this@FilesActivity.adapter
            setOnItemClickListener { _, _, position, _ -> this@FilesActivity.adapter.getItem(position).onTap?.invoke() }
        }, LinearLayout.LayoutParams(-1, 0, 1f))
        showEdgeToEdge(root, dp(16))
    }

    override fun onResume() {
        super.onResume()
        val access = if (media) Media.mediaAccess(this) else if (Media.allFilesAccess(this)) "all" else "none"
        if (access == "none") {
            generation++
            allow.visibility = Button.VISIBLE
            trashAll.visibility = Button.GONE
            adapter.lines = emptyList()
            if (media) {
                allow.text = "Allow photos and videos"
                summary.text = "To find duplicate photos and videos and the biggest ones, Atlas needs to see them. " +
                    "It only reads them on this phone; nothing is uploaded."
            } else {
                allow.text = "Allow all files access"
                summary.text = "To check your downloads and documents for malware, and find duplicates among them, " +
                    "Atlas needs All files access: find Project Atlas and switch it on. Atlas sends VirusTotal only " +
                    "each file's fingerprint, never the file, and never removes anything itself."
            }
            return
        }
        allow.visibility = if (access == "some") Button.VISIBLE else Button.GONE
        allow.text = "Allow all photos"
        if (!scanned) look(access == "some")
    }

    override fun onDestroy() {
        super.onDestroy()
        generation++ // stops the look still running
    }

    private fun askForAccess() {
        if (media || Build.VERSION.SDK_INT < 30) {
            requestPermissions(Media.mediaPermissions(), ACCESS) // before Android 11, "read storage" covers both
        } else {
            startActivity(Media.allFilesSettings(this))
        }
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        scanned = false
        onResume()
    }

    @Deprecated("Activity's own API")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        if (requestCode == TRASH && resultCode == RESULT_OK) {
            scanned = false // look again: the trash changed what's there
            onResume()
        }
    }

    private fun look(partial: Boolean) {
        scanned = true
        val mine = ++generation
        risky.clear()
        knownBad.clear()
        fun say(text: String) = runOnUiThread { if (mine == generation) summary.text = text }
        say("Looking at your ${if (media) "photos and videos" else "files"}...")
        thread(isDaemon = true) {
            try {
                val items = if (media) Media.list(this, Media.IMAGES) + Media.list(this, Media.VIDEOS)
                else Media.list(this, Media.FILES)
                val note = if (partial) " Atlas can only see the photos you picked." else ""
                var done = 0
                val found = duplicateGroups(items, { Media.quickHash(this, it) }, {
                    if (++done % 10 == 0) say("Comparing look-alike files ($done)...")
                    Media.fullHash(this, it)
                }, minSize = if (media) 1 else 100L shl 10)
                if (mine != generation) return@thread
                runOnUiThread {
                    groups = found
                    big = biggest(items)
                    show("${items.size} ${if (media) "photos and videos" else "files"}, " +
                        humanSize(items.sumOf { it.size }) + "." + note)
                }
                if (!media) checkRisky(items, mine, "${items.size} files, ${humanSize(items.sumOf { it.size })}.")
            } catch (e: Exception) {
                say("The look stopped: ${e.message ?: e.javaClass.simpleName}")
            }
        }
    }

    /** App files first, then programs and archives, then documents; newest first in each. */
    private fun checkRisky(items: List<FileItem>, mine: Int, intro: String) {
        val todo = items.mapNotNull { item -> riskOf(item.name)?.let { item to it.rank } }
            .sortedWith(compareBy<Pair<FileItem, Int>> { it.second }.thenByDescending { it.first.modified })
            .take(MAX_RISKY).map { it.first }
        val answers = Answers(this)
        val key = ApiKey.load(this)
        val vt = key?.let { VirusTotal(it) }
        var looked = 0
        for ((i, item) in todo.withIndex()) {
            if (mine != generation) return
            val hash = Media.fullHash(this, item)
            val known = hash?.let { h ->
                try {
                    IntelStore.get(this).file(h)
                } catch (e: Exception) {
                    null
                }
            }
            if (known != null) {
                runOnUiThread { if (mine == generation) { knownBad[item.uri] = known; risky += item to null; show(intro) } }
                continue
            }
            var report = hash?.let(answers::report)
            if (report == null && hash != null && vt != null) {
                runOnUiThread { if (mine == generation) summary.text = "$intro Checking ${item.name} with VirusTotal " +
                    "(${i + 1} of ${todo.size})..." }
                val started = System.currentTimeMillis()
                report = try {
                    patiently { vt.file(hash) }.also { answers.save(hash, it) }
                } catch (e: RateLimited) {
                    runOnUiThread { summary.text = "$intro VirusTotal's limit for your key was reached: look again later." }
                    break
                } catch (e: BadKey) {
                    runOnUiThread { summary.text = "$intro VirusTotal didn't accept your key." }
                    break
                }
                looked++
                Prefs.waitTurn(this, started)
            }
            val pair = item to report
            runOnUiThread {
                if (mine == generation) {
                    risky += pair
                    show(intro)
                }
            }
        }
        runOnUiThread {
            if (mine == generation) {
                val look = risky.count { (item, r) -> item.uri in knownBad || r != null && fileVerdict(r).rank >= Verdict.SUSPICIOUS.rank }
                show("$intro ${risky.size} app files, programs and documents checked" +
                    (if (key == null) " against known threats (add a VirusTotal key to also check them with " +
                        "antivirus engines)" else "") +
                    if (look > 0) ": $look need a look." else ": none needs a look.")
            }
        }
    }

    private fun show(text: String) {
        summary.text = text
        val wasted = groups.sumOf { it.wasted }
        trashAll.visibility = if (groups.isEmpty()) Button.GONE else Button.VISIBLE
        trashAll.text = "Move all extra copies to trash (${humanSize(wasted)})"
        val lines = mutableListOf<Line>()
        if (!media) {
            lines += Line("Checked for malware", "App files, programs and documents, riskiest kinds first", heading = true)
            fun rank(item: FileItem, r: VtReport?) = if (item.uri in knownBad) 9 else r?.let { fileVerdict(it).rank } ?: -1
            risky.sortedByDescending { (item, r) -> rank(item, r) }.forEach { (item, report) ->
                val family = knownBad[item.uri]
                val verdict = if (family != null) Verdict.MALICIOUS else report?.takeIf { it.found }?.let(::fileVerdict)
                val text = if (family != null) knownText(family) else riskyFileText(item, report)
                lines += Line(item.name, text + " · " + item.path.substringBeforeLast('/', ""),
                    color = verdict?.color,
                    onTap = { showRisky(item, report) })
            }
        }
        lines += Line("Duplicates", if (groups.isEmpty()) "None found." else
            "${groups.size} sets of identical files; ${humanSize(wasted)} in extra copies", heading = true)
        groups.forEach { g ->
            lines += Line("${g.files.size} copies of ${g.keep.name}",
                "${humanSize(g.keep.size)} each · keeps ${g.keep.path}", onTap = { showGroup(g) })
        }
        lines += Line("Biggest files", if (big.isEmpty()) "Nothing over 10 MB." else "", heading = true)
        big.forEach { lines += Line(it.name, "${humanSize(it.size)} · ${it.path.substringBeforeLast('/', "")}",
            onTap = { showFile(it) }) }
        adapter.lines = lines
    }

    private fun showGroup(group: DuplicateGroup) {
        val text = "Identical files (${humanSize(group.keep.size)} each). Atlas keeps the first: the camera's own copy, " +
            "or the oldest.\n\nKeep: ${group.keep.path}\n\n" + group.extras.joinToString("\n") { "Extra: ${it.path}" }
        AlertDialog.Builder(this).setTitle(group.keep.name).setMessage(text)
            .setPositiveButton("Move extras to trash") { _, _ -> trash(group.extras) }
            .setNeutralButton("Open") { _, _ -> Media.open(this, group.keep) }
            .setNegativeButton("Close", null).show()
    }

    private fun showFile(item: FileItem) {
        AlertDialog.Builder(this).setTitle(item.name).setMessage("${humanSize(item.size)}\n${item.path}")
            .setPositiveButton("Move to trash") { _, _ -> trash(listOf(item)) }
            .setNeutralButton("Open") { _, _ -> Media.open(this, item) }
            .setNegativeButton("Close", null).show()
    }

    private fun showRisky(item: FileItem, report: VtReport?) {
        val hash = Media.fullHash(this, item)
        val first = knownBad[item.uri]?.let { knownText(it) + ". Don't install it" } ?: riskyFileText(item, report)
        val message = "$first.\n\nIt's ${riskOf(item.name)?.kind ?: "a file"}, " +
            "${humanSize(item.size)}.\n${item.path}" + (hash?.let { "\n\nFingerprint (SHA-256): $it" } ?: "")
        val dialog = AlertDialog.Builder(this).setTitle(item.name).setMessage(message)
            .setPositiveButton("Move to trash") { _, _ -> trash(listOf(item)) }
            .setNegativeButton("Close", null)
        hash?.let { dialog.setNeutralButton("VirusTotal") { _, _ -> openWeb(guiLink("file", it)) } }
        dialog.show()
    }

    private fun knownText(family: Family) =
        "Known ${family.what}: ${family.name}"

    private fun trash(items: List<FileItem>) {
        if (!Media.askToTrash(this, items, TRASH)) {
            AlertDialog.Builder(this).setMessage("Android didn't let Atlas offer to move ${if (items.size == 1) "this " +
                "file" else "these files"} to the trash. You can remove them in your Files or Photos app.")
                .setPositiveButton("OK", null).show()
        }
    }

    companion object {
        const val MODE = "mode"
        const val FILES_MODE = "files"
        private const val ACCESS = 1
        private const val TRASH = 2
        private const val MAX_RISKY = 500 // newest first: enough for a phone, without a day of lookups
    }
}
