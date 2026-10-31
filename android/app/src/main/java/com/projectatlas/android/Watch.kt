package com.projectatlas.android

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.app.job.JobService
import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import kotlin.concurrent.thread

/**
 * Automatic checks, kept light: Android wakes Atlas when a file lands in shared storage (new downloads); every 15
 * minutes Atlas asks Android which apps changed (usually none, so it's done at once); and once a day, on a battery
 * that isn't low, it runs the Protection checks and fetches newer threat data. Atlas tells you with a notification;
 * it never removes anything.
 */
object Watch {
    private const val DAILY = 1
    const val DOWNLOADS = 2
    const val APPS = 3 // new and changed apps
    private const val APPS_EVERY = 15 * 60_000L // the shortest Android allows
    private const val CHANNEL = "alerts"
    private const val QUIET = "checked" // no sound, no pop-up: "Atlas checked this new app"
    private const val MAX_NEW_FILES = 20 // a big copy to the phone shouldn't mean a hundred lookups

    private fun prefs(context: Context) = context.getSharedPreferences("watch", Context.MODE_PRIVATE)

    fun enabled(context: Context) = prefs(context).getBoolean("on", true)

    fun setEnabled(context: Context, on: Boolean) {
        prefs(context).edit().putBoolean("on", on).apply()
        schedule(context)
    }

    /** (Re)arms both jobs, or cancels them when automatic checks are off. Safe to call often. */
    fun schedule(context: Context) {
        val jobs = context.getSystemService(JobScheduler::class.java)
        if (!enabled(context)) {
            jobs.cancel(DAILY)
            jobs.cancel(DOWNLOADS)
            jobs.cancel(APPS)
            return
        }
        val service = ComponentName(context, WatchJob::class.java)
        // The first run also looks back 2 days, so an app installed just before the update to automatic checks counts.
        if (!prefs(context).contains("since")) prefs(context).edit().putLong("since", System.currentTimeMillis() - 2 * DAY_MS).apply()
        if (jobs.getPendingJob(APPS)?.isPeriodic != true) { // 0.3.1 used this number for a one-off run
            jobs.schedule(JobInfo.Builder(APPS, service).setPeriodic(APPS_EVERY).setPersisted(true).build())
        }
        if (jobs.getPendingJob(DAILY) == null) {
            jobs.schedule(JobInfo.Builder(DAILY, service).setPeriodic(DAY_MS).setRequiresBatteryNotLow(true)
                .setPersisted(true).build())
        }
        if (Media.allFilesAccess(context)) {
            if (prefs(context).getLong("files_since", 0) == 0L) markFilesSeen(context)
            if (jobs.getPendingJob(DOWNLOADS) == null) armDownloads(context)
        } else {
            jobs.cancel(DOWNLOADS)
        }
    }

    // A content trigger fires once, so the downloads job re-arms itself after each run (and BootReceiver after a restart).
    private fun armDownloads(context: Context) {
        context.getSystemService(JobScheduler::class.java).schedule(
            JobInfo.Builder(DOWNLOADS, ComponentName(context, WatchJob::class.java))
                .addTriggerContentUri(JobInfo.TriggerContentUri(Media.FILES, JobInfo.TriggerContentUri.FLAG_NOTIFY_FOR_DESCENDANTS))
                .setTriggerContentUpdateDelay(10_000) // let a download finish writing
                .setTriggerContentMaxDelay(60_000)
                .build())
    }

    private fun markFilesSeen(context: Context) =
        prefs(context).edit().putLong("files_since", System.currentTimeMillis() / 1000).apply()

    /** The Protection screen saves what it showed, so the daily check only tells you what's new. */
    fun remember(context: Context, findings: List<Finding>) {
        prefs(context).edit().putStringSet("warned", findings.filter { it.level == Level.WARN }.map { it.key }.toSet()).apply()
    }

    // --- The jobs --------------------------------------------------------------------------------------------

    fun runDownloads(context: Context) {
        try {
            val since = prefs(context).getLong("files_since", 0)
            val started = System.currentTimeMillis() / 1000
            val fresh = Media.list(context, Media.FILES, since).filter { riskOf(it.name) != null }
                .sortedBy { riskOf(it.name)!!.rank }.take(MAX_NEW_FILES)
            prefs(context).edit().putLong("files_since", started).apply()
            val answers = Answers(context)
            val vt = ApiKey.load(context)?.let { VirusTotal(it) }
            for (item in fresh) {
                val hash = Media.fullHash(context, item) ?: continue
                val known = try {
                    IntelStore.get(context).file(hash)
                } catch (e: Exception) {
                    null
                }
                if (known != null) {
                    notify(context, "file:$hash", "${item.name}: known ${known.what}",
                        "It's ${known.name}. Don't install it. Open Files and downloads to move it to the trash.",
                        Intent(context, FilesActivity::class.java).putExtra(FilesActivity.MODE, FilesActivity.FILES_MODE))
                    continue
                }
                val report = answers.report(hash) ?: vt?.let {
                    try {
                        it.file(hash).also { r -> answers.save(hash, r) }
                    } catch (e: Exception) {
                        null // busy or offline: the Files screen checks it next time
                    }
                } ?: continue
                val verdict = fileVerdict(report)
                if (verdict.rank >= Verdict.SUSPICIOUS.rank) {
                    notify(context, "file:$hash", "${item.name}: ${verdict.label.lowercase()}",
                        "${riskyFileText(item, report)}. Open Files and downloads to move it to the trash.",
                        Intent(context, FilesActivity::class.java).putExtra(FilesActivity.MODE, FilesActivity.FILES_MODE))
                }
            }
        } finally {
            if (enabled(context) && Media.allFilesAccess(context)) armDownloads(context)
        }
    }

    fun runDaily(context: Context) {
        IntelStore.updateIfDue(context)
        val now = System.currentTimeMillis()
        val findings = phoneFindings(Phone.facts(context), java.time.LocalDate.now()) +
            quietUploaders(Phone.dataUse(context, now), now)
        val remembered = prefs(context).getStringSet("warned", emptySet()).orEmpty()
        for (f in newWarnings(findings, remembered)) {
            notify(context, "warn:${f.key}", f.title, f.details.firstOrNull() ?: "Open Protection to see why.",
                Intent(context, ProtectionActivity::class.java))
        }
        remember(context, findings)
    }

    /**
     * Apps installed or updated since the last run: checked against the threat data and, with a key, VirusTotal.
     * One that needs a look gets an alert; a newly installed one that's fine gets a quiet "checked" note (updates stay
     * silent: Play updates apps every day). Most runs find nothing changed and stop after one question to Android.
     */
    fun runApps(context: Context) {
        val pm = context.packageManager
        val boot = Settings.Global.getInt(context.contentResolver, Settings.Global.BOOT_COUNT, 0)
        val p = prefs(context)
        val first = !p.contains("last_run")
        val since = p.getLong("last_run", p.getLong("since", System.currentTimeMillis()))
        val started = System.currentTimeMillis()
        // Android counts changes from each start, so after a restart Atlas asks from the beginning.
        val sequence = if (p.getInt("boot", -1) == boot) p.getInt("sequence", 0) else 0
        val changed = pm.getChangedPackages(sequence)
        p.edit().putInt("boot", boot).putInt("sequence", changed?.sequenceNumber ?: sequence).putLong("last_run", started).apply()
        val names = changed?.packageNames.orEmpty().toSet()
        val apps = when {
            first -> Device.installedApps(context).filter { it.updated >= since } // no list from Android yet
            names.isEmpty() -> return
            else -> Device.installedApps(context, names)
        }
        val answers = Answers(context)
        val vt = ApiKey.load(context)?.let { VirusTotal(it) }
        for (app in apps) {
            val hash = answers.fingerprint(app)
            val report = hash?.let { h ->
                answers.report(h) ?: vt?.let {
                    try {
                        it.file(h).also { r -> answers.save(h, r) }
                    } catch (e: Exception) {
                        null // busy or offline: the app check looks it up next time
                    }
                }
            }
            val assessment = assess(app, report, Device.intel(context, app, hash))
            val open = Intent(context, MainActivity::class.java)
            if (assessment.needsLook) {
                notify(context, "app:${app.packageName}:${hash ?: app.updated}", "${app.label} needs a look",
                    assessment.reasons.firstOrNull() ?: assessment.verdict.label, open)
            } else if (app.installed >= since) {
                val (title, text) = checkedNote(app.label, assessment)
                notify(context, "checked:${app.packageName}", title, text, open, quiet = true)
            }
        }
    }

    // --- Notifications ---------------------------------------------------------------------------------------

    fun canNotify(context: Context) = Build.VERSION.SDK_INT < 33 ||
        context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED

    fun notify(context: Context, key: String, title: String, text: String, open: Intent, quiet: Boolean = false) {
        if (!canNotify(context)) return
        val manager = context.getSystemService(NotificationManager::class.java)
        val channel = if (quiet) {
            NotificationChannel(QUIET, "New apps checked", NotificationManager.IMPORTANCE_LOW)
        } else {
            NotificationChannel(CHANNEL, "Security alerts", NotificationManager.IMPORTANCE_DEFAULT)
        }
        manager.createNotificationChannel(channel)
        val tap = PendingIntent.getActivity(context, key.hashCode(), open.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val notification = Notification.Builder(context, channel.id)
            .setSmallIcon(R.drawable.ic_globe)
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(Notification.BigTextStyle().bigText(text))
            .setContentIntent(tap)
            .setAutoCancel(true)
            .build()
        manager.notify(key.hashCode(), notification)
    }
}

class WatchJob : JobService() {
    override fun onStartJob(params: JobParameters): Boolean {
        val app = applicationContext
        thread(name = "atlas-watch", isDaemon = true) {
            try {
                when (params.jobId) {
                    Watch.DOWNLOADS -> Watch.runDownloads(app)
                    Watch.APPS -> Watch.runApps(app)
                    else -> Watch.runDaily(app)
                }
            } catch (e: Exception) {
                // the next run tries again
            } finally {
                jobFinished(params, false)
            }
        }
        return true
    }

    override fun onStopJob(params: JobParameters) = false
}

/** Content triggers don't survive a restart: arm the downloads watch again. */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED) Watch.schedule(context)
    }
}
