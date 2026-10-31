package com.projectatlas.android

import android.content.Context
import android.os.Handler
import android.os.Looper
import kotlin.concurrent.thread

/**
 * Checks every installed app: first what the phone shows (instant), then each app's fingerprint against VirusTotal,
 * apps from outside the stores first. A free key allows 4 lookups a minute, so lookups are spaced out; answers are
 * kept, so the next check only looks up new and updated apps.
 */
object AppCheck {
    class Row(val facts: AppFacts) {
        @Volatile var sha256: String? = null
        @Volatile var vt: VtReport? = null
        @Volatile var intel: IntelHit? = null // known stalkerware or monitoring app
        @Volatile var assessment: Assessment = assess(facts, null)
    }

    @Volatile var rows: List<Row> = emptyList()
        private set
    @Volatile var message = "Not checked yet."
        private set
    @Volatile var running = false
        private set
    var listener: (() -> Unit)? = null // on the main thread

    private val main = Handler(Looper.getMainLooper())

    fun start(context: Context) {
        if (running) return
        running = true
        val app = context.applicationContext
        thread(name = "atlas-app-check", isDaemon = true) { run(app) }
    }

    private fun say(text: String) {
        message = text
        main.post { listener?.invoke() }
    }

    private fun run(context: Context) {
        var looked = 0
        try {
            say("Looking at your apps...")
            val found = Device.installedApps(context).map(::Row)
            rows = found
            val answers = Answers(context)
            found.forEachIndexed { i, row ->
                if (i % 5 == 0) say("Fingerprinting your apps (${i + 1} of ${found.size})...")
                row.sha256 = answers.fingerprint(row.facts)
                row.vt = row.sha256?.let(answers::report)
                row.intel = Device.intel(context, row.facts, row.sha256)
                row.assessment = assess(row.facts, row.vt, row.intel)
            }
            val key = ApiKey.load(context)
            if (key == null) {
                say(summary(found.map { it.assessment }, 0) + " Checked against known threats. Add a " +
                    "VirusTotal key to also check each app with about 70 antivirus engines.")
                return
            }
            val vt = VirusTotal(key)
            val todo = found.filter { it.vt == null && it.sha256 != null }.sortedBy { fromStore(it.facts.installer) }
            for ((i, row) in todo.withIndex()) {
                val started = System.currentTimeMillis()
                say("Checking ${row.facts.label} with VirusTotal (${i + 1} of ${todo.size})." +
                    if (Prefs.paidKey(context)) "" else " A free key allows ${VirusTotal.LOOKUPS_PER_MINUTE} a " +
                        "minute, so this takes a while; you can leave this screen.")
                val report = try {
                    patiently { vt.file(row.sha256!!) }
                } catch (e: RateLimited) {
                    say(summary(found.map { it.assessment }, looked) +
                        " VirusTotal's limit for your key was reached: check again later to finish.")
                    return
                }
                answers.save(row.sha256!!, report)
                row.vt = report
                row.assessment = assess(row.facts, report, row.intel)
                looked++
                if (i < todo.lastIndex) Prefs.waitTurn(context, started)
            }
            say(summary(found.map { it.assessment }, looked))
        } catch (e: BadKey) {
            say("VirusTotal didn't accept your key. Check it with \"VirusTotal key\".")
        } catch (e: Exception) {
            say("The check stopped: ${e.message ?: e.javaClass.simpleName}")
        } finally {
            running = false
            main.post { listener?.invoke() }
        }
    }
}
