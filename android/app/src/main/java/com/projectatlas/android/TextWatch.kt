package com.projectatlas.android

import android.app.Notification
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.provider.Telephony
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import kotlin.concurrent.thread

/**
 * Scam alerts for texts: with notification access (which you switch on), Atlas runs the scam rules on each new
 * message from your texting, chat and email apps, on the phone. Messages are never saved or sent anywhere; with a
 * VirusTotal key, only the links in a message that already looks wrong are looked up.
 */
class TextWatch : NotificationListenerService() {
    private val seen = ArrayDeque<Int>() // recent messages, so an updated notification isn't checked twice

    override fun onNotificationPosted(sbn: StatusBarNotification) {
        val n = sbn.notification ?: return
        if (sbn.packageName !in messageApps(this) || sbn.isOngoing || n.flags and Notification.FLAG_GROUP_SUMMARY != 0) return
        val extras = n.extras ?: return
        val text = messageText(messagesIn(extras), extras.getCharSequence(Notification.EXTRA_BIG_TEXT)?.toString(),
            extras.getCharSequence(Notification.EXTRA_TEXT)?.toString()) ?: return
        val id = (sbn.packageName + text).hashCode()
        synchronized(seen) {
            if (id in seen) return
            seen.addLast(id)
            if (seen.size > 50) seen.removeFirst()
        }
        val sender = extras.getCharSequence(Notification.EXTRA_TITLE)?.toString().orEmpty()
        val app = applicationContext
        // Only when and from which app, never the message: so the Protection screen can show the alerts work.
        app.getSharedPreferences("watch", Context.MODE_PRIVATE).edit().putLong("text_seen", System.currentTimeMillis())
            .putString("text_app", appLabel(sbn.packageName)).apply()
        thread(name = "atlas-text", isDaemon = true) { check(app, sender, text) }
    }

    private fun appLabel(pkg: String) = try {
        packageManager.getApplicationInfo(pkg, 0).loadLabel(packageManager).toString()
    } catch (e: Exception) {
        pkg
    }

    companion object {
        /** A made-up scam text for "Try a sample scam". */
        const val SAMPLE = "USPS: Your package couldn't be delivered. Pay the redelivery fee within 24 hours: " +
            "usps-redelivery.top/a1"

        /** Texting, chat and email apps whose messages are checked; the phone's own texting app is added. */
        val MESSAGE_APPS = setOf(
            "com.google.android.apps.messaging", "com.samsung.android.messaging", "com.android.mms",
            "com.motorola.messaging", "com.oneplus.mms", "com.whatsapp", "com.whatsapp.w4b", "org.telegram.messenger",
            "org.thoughtcrime.securesms", "com.facebook.orca", "com.viber.voip", "com.google.android.gm",
            "com.microsoft.office.outlook", "com.yahoo.mobile.client.android.mail",
        )

        /** Runs the scam check on one message and alerts when it looks like a scam. True when it alerted. */
        fun check(context: Context, sender: String, text: String): Boolean {
            val links = extractLinks(text)
            val intel = try {
                IntelStore.get(context)
            } catch (e: Exception) {
                null
            }
            val reasons = wordReasons(text) + siteReasons(links) { intel?.site(it) }
            var score = reasons.sumOf { it.weight }
            var flagged = emptyList<String>()
            // Only messages that already show a sign (and aren't a scam already) are worth a lookup: most texts with a
            // link are from friends, and their links stay on the phone.
            val key = ApiKey.load(context)
            if (key != null && links.isNotEmpty() && score in 1 until SCAM_SCORE) {
                val vt = VirusTotal(key)
                flagged = links.take(2).mapNotNull { link ->
                    val verdict = try {
                        siteVerdict(vt.url(link))
                    } catch (e: Exception) {
                        Verdict.UNKNOWN // busy or offline: the rules still count
                    }
                    score += linkPoints(verdict)
                    if (linkPoints(verdict) > 0) hostOf(link) else null
                }
            }
            if (scamVerdict(score) != SCAM) return false
            val why = (reasons.map { it.title } + flagged.map { "a flagged link ($it)" }).joinToString(", ")
            val from = if (sender.isBlank()) "A message" else "The message from $sender"
            Watch.notify(context, "text:${text.hashCode()}", "This message looks like a scam",
                "$from: $why. Don't reply, call, click or pay. Tap to see why.",
                Intent(context, ShareActivity::class.java).setAction(Intent.ACTION_SEND).setType("text/plain")
                    .putExtra(Intent.EXTRA_TEXT, text))
            return true
        }

        /** "Last checked a message 2 minutes ago (Messages)", or null before the first. */
        fun lastSeen(context: Context, now: Long = System.currentTimeMillis()): String? {
            val prefs = context.getSharedPreferences("watch", Context.MODE_PRIVATE)
            val at = prefs.getLong("text_seen", 0).takeIf { it > 0 } ?: return null
            return "Last checked a message ${ago(now - at)} (${prefs.getString("text_app", "")})"
        }

        fun messageApps(context: Context): Set<String> =
            MESSAGE_APPS + listOfNotNull(Telephony.Sms.getDefaultSmsPackage(context))

        fun messagesIn(extras: Bundle): List<String> {
            val parcels = if (Build.VERSION.SDK_INT >= 33) {
                extras.getParcelableArray(Notification.EXTRA_MESSAGES, android.os.Parcelable::class.java)
            } else {
                @Suppress("DEPRECATION") extras.getParcelableArray(Notification.EXTRA_MESSAGES)
            }
            return parcels.orEmpty().mapNotNull { (it as? Bundle)?.getCharSequence("text")?.toString() }
        }

        /** True when you've given Atlas notification access in Android's settings. */
        fun on(context: Context): Boolean {
            val me = ComponentName(context, TextWatch::class.java).flattenToString()
            return Settings.Secure.getString(context.contentResolver, "enabled_notification_listeners").orEmpty()
                .split(':').any { it == me }
        }

        fun settings(context: Context): Intent = if (Build.VERSION.SDK_INT >= 30) {
            Intent(Settings.ACTION_NOTIFICATION_LISTENER_DETAIL_SETTINGS).putExtra(
                Settings.EXTRA_NOTIFICATION_LISTENER_COMPONENT_NAME, ComponentName(context, TextWatch::class.java).flattenToString())
        } else {
            Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS)
        }
    }
}
