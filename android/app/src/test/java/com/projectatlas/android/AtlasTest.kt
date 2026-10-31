package com.projectatlas.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

class VerdictTest {
    @Test
    fun filesAndSitesFollowTheWindowsRules() {
        assertEquals(Verdict.MALICIOUS, fileVerdict(VtReport(true, malicious = 3, total = 70)))
        assertEquals(Verdict.SUSPICIOUS, fileVerdict(VtReport(true, malicious = 1, total = 70)))
        assertEquals(Verdict.SUSPICIOUS, fileVerdict(VtReport(true, suspicious = 1, total = 70)))
        assertEquals(Verdict.CLEAN, fileVerdict(VtReport(true, total = 70)))
        assertEquals(Verdict.UNKNOWN, fileVerdict(VtReport(false)))
        assertEquals(Verdict.CLEAN, siteVerdict(VtReport(true, malicious = 2, total = 90)))
        assertEquals(Verdict.SUSPICIOUS, siteVerdict(VtReport(true, malicious = 5, total = 90)))
    }

    @Test
    fun savedAnswersExpire() {
        val day = 24 * 3600 * 1000L
        val found = VtReport(true, 4, 1, 70, "trojan.joker")
        assertEquals(found, VtReport.decode(found.encode(0), 29 * day))
        assertNull(VtReport.decode(found.encode(0), 31 * day))
        assertNull(VtReport.decode(VtReport(false).encode(0), 4 * day))
        assertNull(VtReport.decode("garbage", 0))
        assertNull(VtReport.decode(null, 0))
    }
}

class VirusTotalTest {
    private val body = """{"data": {"attributes": {"last_analysis_stats": {"malicious": 12, "suspicious": 1,
        "undetected": 50, "harmless": 0}, "popular_threat_classification": {"suggested_threat_label": "trojan.joker"}}}}"""

    @Test
    fun readsReportsAndStatusCodes() {
        val asked = mutableListOf<String>()
        val vt = VirusTotal("k") { address, key ->
            asked += address
            assertEquals("k", key)
            when {
                address.endsWith("/files/abc") -> 200 to body
                address.contains("/domains/") -> 404 to ""
                else -> 429 to ""
            }
        }
        val report = vt.file("ABC")
        assertEquals(VtReport(true, 12, 1, 63, "trojan.joker"), report)
        assertEquals(VtReport(false), vt.domain("Example.com"))
        assertTrue(asked[1].endsWith("/domains/example.com"))
        try {
            vt.url("https://example.com/")
            throw AssertionError("expected a rate limit")
        } catch (e: RateLimited) {
        }
        try {
            VirusTotal("bad") { _, _ -> 401 to "" }.file("abc")
            throw AssertionError("expected a bad key")
        } catch (e: BadKey) {
        }
        try {
            VirusTotal("k") { _, _ -> 500 to "" }.file("abc")
            throw AssertionError("expected an error")
        } catch (e: IOException) {
        }
    }

    @Test
    fun theKeysOwnLimitSetsTheSpeed() {
        fun user(hourly: Long, daily: Long, group: Long = 0) = """{"data": {"attributes": {"quotas": {
            "api_requests_hourly": {"user": {"used": 3, "allowed": $hourly}, "group": {"allowed": $group}},
            "api_requests_daily": {"user": {"used": 3, "allowed": $daily}}}}}}"""
        assertEquals(4, minuteLimit(user(240, 500))) // a free key
        assertEquals(500, minuteLimit(user(30_000, 1_000_000)))
        assertEquals(MAX_PER_MINUTE, minuteLimit(user(10_000_000, 0))) // Atlas stays light whatever the key allows
        assertEquals(100, minuteLimit(user(0, 0, group = 6_000))) // a company key's group allowance
        assertEquals(10, minuteLimit(user(0, 14_400)))
        assertNull(minuteLimit("""{"data": {"attributes": {}}}"""))
        assertEquals(500, VirusTotal("k") { address, _ ->
            assertTrue(address.endsWith("/users/k"))
            200 to user(30_000, 0)
        }.lookupsPerMinute())
        assertNull(VirusTotal("k") { _, _ -> 404 to "" }.lookupsPerMinute())
    }

    @Test
    fun aTickedPaidKeyIsNeverSlowerThanPaidSpeed() {
        assertEquals(4, speed(0, false))
        assertEquals(15_500L, spacing(4))
        assertEquals(120, speed(4, true)) // VirusTotal reports the key's own 4 a minute; the company pays for more
        assertEquals(500, speed(500, true))
        assertEquals(500, speed(500, false))
        assertEquals(500L, spacing(120))
    }

    @Test
    fun aBusyAnswerWaitsAMinuteAndTriesOnce() {
        val waits = mutableListOf<Long>()
        var calls = 0
        assertEquals("ok", patiently({ waits += it }) { if (calls++ == 0) throw RateLimited() else "ok" })
        assertEquals(listOf(60_000L), waits)
        try {
            patiently({ waits += it }) { throw RateLimited() }
            throw AssertionError("expected it to give up")
        } catch (e: RateLimited) {
        }
    }

    @Test
    fun linksUseVirusTotalsNames() {
        assertEquals("aHR0cDovL2V4YW1wbGUuY29tLw", urlId("http://example.com/"))
        assertEquals("https://www.virustotal.com/gui/url/aHR0cDovL2V4YW1wbGUuY29tLw", guiLink("url", "http://example.com/"))
        assertEquals("https://www.virustotal.com/gui/domain/example.com", guiLink("domain", "example.com"))
    }
}

class AppsTest {
    private val play = AppFacts("Maps", "com.maps", "com.android.vending", emptySet())

    @Test
    fun storeAppsWithNothingOddLookSafe() {
        val a = assess(play, null)
        assertEquals(Verdict.CLEAN, a.verdict)
        assertEquals(listOf("Installed from Google Play"), a.reasons)
        assertEquals(Verdict.CLEAN, assess(play, VtReport(false)).verdict) // VirusTotal not knowing a Play app is normal
    }

    @Test
    fun aSideloadedAppWithAccessibilityNeedsALook() {
        val banker = AppFacts("Flash Player", "com.flash.update", "com.google.android.packageinstaller",
            setOf("android.permission.READ_SMS", "android.permission.SYSTEM_ALERT_WINDOW"), accessibilityOn = true)
        val a = assess(banker, null)
        assertEquals(Verdict.SUSPICIOUS, a.verdict)
        assertTrue(a.needsLook)
        assertTrue(a.reasons.any { it.startsWith("Accessibility access is on") })
        assertTrue(a.reasons.any { "read your text messages" in it && "draw over other apps" in it })
        assertEquals("Not from an app store: installed from a downloaded file", a.reasons.last())
        // The same access from a store app is only mentioned.
        assertEquals(Verdict.CLEAN, assess(banker.copy(installer = "com.android.vending"), null).verdict)
    }

    @Test
    fun hiddenAndUnknownSideloadsAreCalledOut() {
        val hidden = AppFacts("Sync", "com.sys.sync", null, setOf("android.permission.RECORD_AUDIO"), hasIcon = false)
        assertEquals(Verdict.SUSPICIOUS, assess(hidden, null).verdict) // a hidden app that can listen: stalkerware's shape
        val quiet = hidden.copy(granted = emptySet())
        assertEquals(Verdict.UNKNOWN, assess(quiet, null).verdict)
        val plain = AppFacts("Game", "com.game", "org.example.store", emptySet())
        assertEquals(Verdict.CLEAN, assess(plain, null).verdict)
        assertEquals(Verdict.UNKNOWN, assess(plain, VtReport(false)).verdict)
        assertEquals("Not from an app store: installed by org.example.store", source("org.example.store"))
    }

    @Test
    fun virusTotalDecidesWhenEnginesFlagIt() {
        val a = assess(play, VtReport(true, malicious = 9, total = 70, label = "adware"))
        assertEquals(Verdict.MALICIOUS, a.verdict)
        assertEquals("VirusTotal: 9 malicious / 0 suspicious of 70 engines (adware)", a.reasons.first())
        assertTrue(assess(play, VtReport(true, total = 70)).reasons.contains("VirusTotal: no engine flags it"))
    }

    @Test
    fun summaryCountsWhatNeedsALook() {
        val list = listOf(Assessment(Verdict.SUSPICIOUS, emptyList()), Assessment(Verdict.CLEAN, emptyList()),
            Assessment(Verdict.UNKNOWN, emptyList()))
        assertEquals("3 apps checked, 1 needs a look, 1 unknown, 2 looked up on VirusTotal.", summary(list, 2))
        assertEquals("1 app checked, none needs a look.", summary(list.subList(1, 2), 0))
    }
}

class LinksTest {
    @Test
    fun findsLinksInAMessage() {
        val text = "Your parcel is waiting: https://bit.ly/3xYz. Or visit www.Post-Office.example/track?id=1, (https://a.example/x)"
        assertEquals(listOf("https://bit.ly/3xYz", "https://www.Post-Office.example/track?id=1", "https://a.example/x"),
            extractLinks(text))
        assertEquals(emptyList<String>(), extractLinks("no links here"))
        // Scam texts often leave out "https://".
        assertEquals(listOf("https://usps-redelivery.top/a1B2", "https://paypa1-secure.com"),
            extractLinks("USPS: your package is held. Update at usps-redelivery.top/a1B2 or paypa1-secure.com."))
        assertEquals(emptyList<String>(), extractLinks("Mail me at someone@example.com about the example.company plan"))
        assertEquals(listOf("https://Example.com/x"), extractLinks("https://Example.com/x and https://example.com/X"))
        assertEquals("post-office.example", hostOf("https://user@www.Post-Office.example:8080/track?id=1"))
    }

    @Test
    fun readsTheAccessibilitySetting() {
        assertEquals(setOf("com.a", "com.b"), Device.packagesIn("com.a/.Svc:com.b/com.b.Other"))
        assertEquals(emptySet<String>(), Device.packagesIn(null))
    }
}
