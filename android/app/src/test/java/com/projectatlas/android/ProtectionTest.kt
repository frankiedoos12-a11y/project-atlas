package com.projectatlas.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.LocalDate

class ProtectionTest {
    private val today = LocalDate.of(2026, 10, 30)
    private val safe = PhoneFacts(screenLock = true, securityPatch = "2026-10-05", androidVersion = "16",
        usbDebugging = false, privateDns = "opportunistic")

    @Test
    fun aWellSetUpPhoneScoresFull() {
        val found = phoneFindings(safe, today)
        assertTrue(found.all { it.level == Level.OK })
        assertEquals(Score(100, "Good", emptyList(), 0), healthScore(found))
    }

    @Test
    fun theScoreFollowsTheWindowsFormula() {
        val found = phoneFindings(safe.copy(screenLock = false, usbDebugging = true, privateDns = "off",
            addedCertificates = listOf("Corp CA", "Mitm Proxy")), today)
        // Screen lock 15, the first certificate 15, the second 3 (same area), two notes 2.
        val score = healthScore(found)
        assertEquals(65, score.value)
        assertEquals("Fair", score.label)
        assertEquals("Screen lock: No screen lock", score.warn.first())
        assertEquals(Level.WARN, found.first().level) // serious first
        assertEquals("Needs attention", healthScore(phoneFindings(safe.copy(screenLock = false, bootloaderUnlocked = true,
            rootFound = listOf("/system/xbin/su"), appsNeedingLook = listOf("Flash Player")), today)).label)
    }

    @Test
    fun oldSecurityUpdatesWarn() {
        fun patch(date: String) = phoneFindings(safe.copy(securityPatch = date), today).first { it.area == "Security updates" }
        assertEquals(Level.OK, patch("2026-08-01").level)
        assertEquals(Level.NOTE, patch("2026-06-01").level)
        assertEquals("No security update for 13 months", patch("2025-10-01").title)
        assertEquals(Level.WARN, patch("2025-10-01").level)
        assertEquals(Level.NOTE, patch("").level)
    }

    @Test
    fun notesAreCapped() {
        val notes = (1..20).map { Finding("Area $it", "note") }
        assertEquals(90, healthScore(notes).value)
    }

    @Test
    fun onlyNewWarningsAreTold() {
        val found = phoneFindings(safe.copy(addedCertificates = listOf("Corp CA", "New One")), today)
        assertEquals(listOf("cert:New One"), newWarnings(found, setOf("cert:Corp CA")).map { it.key })
    }

    @Test
    fun quietUploadsFromUnknownAppsWarn() {
        val now = 100 * DAY_MS
        val uses = listOf(
            DataUse("Spy", "com.spy", 300L shl 20, 0, 300L shl 20, trusted = false, lastUsed = 0),
            DataUse("Photos", "com.photos", 900L shl 20, 0, 900L shl 20, trusted = true, lastUsed = now - 30 * DAY_MS),
            DataUse("Chat", "com.chat", 500L shl 20, 0, 500L shl 20, trusted = false, lastUsed = now - DAY_MS), // opened
            DataUse("Tiny", "com.tiny", 1L shl 20, 0, 1L shl 20, trusted = false, lastUsed = 0),
        )
        val found = quietUploaders(uses, now)
        assertEquals(listOf("upload:com.spy" to Level.WARN, "upload:com.photos" to Level.NOTE), found.map { it.key to it.level })
    }
}

class ScamTest {
    @Test
    fun aTollTextLooksLikeAScam() {
        val text = "E-ZPass: You have an unpaid toll balance of \$4.15. Pay within 24 hours to avoid fees: ezpass-pay.top/x"
        val reasons = wordReasons(text)
        // Paying a toll through a link in a text is a scam on its own words: no lookup needed.
        assertEquals(listOf("Unpaid toll or parcel", "Pressure to act now", PAY_THROUGH_LINK), reasons.map { it.title })
        assertEquals(SCAM, scamVerdict(reasons.sumOf { it.weight }))
        assertEquals(4, linkPoints(Verdict.MALICIOUS))
    }

    @Test
    fun techSupportAndGiftCards() {
        val text = "Your phone has been hacked! Call Apple Support at (888) 555-0123 and buy Google Play cards to fix it. Don't tell anyone."
        val titles = wordReasons(text).map { it.title }
        assertTrue("Gift cards" in titles && "Virus scare" in titles && "Keep it secret" in titles)
        assertTrue(CALL_THIS_NUMBER in titles)
        assertEquals(SCAM, scamVerdict(wordReasons(text).sumOf { it.weight }))
    }

    @Test
    fun anOrdinaryMessageIsQuiet() {
        val reasons = wordReasons("See you at 7 for dinner? I'll bring the cake.")
        assertEquals(emptyList<Reason>(), reasons)
        assertEquals(NOTHING, scamVerdict(0))
        // Whole words only: "firs" in "first" and "court" in "courtyard" don't count.
        assertEquals(emptyList<Reason>(), wordReasons("Meet in the courtyard first"))
    }

    @Test
    fun quotesShowWhereItWasFound() {
        val reason = wordReasons("Hello. " + "x".repeat(50) + " send me the code now " + "y".repeat(50)).single()
        assertTrue(reason.quote.startsWith("...") && reason.quote.endsWith("...") && "send me the code" in reason.quote)
    }
}

class PwnedTest {
    @Test
    fun onlyTheFirstFiveCharactersAreSent() {
        // SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        var asked = ""
        val count = Pwned.timesLeaked("password") { address ->
            asked = address
            "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:9545824\r\nFFFF:0"
        }
        assertEquals("https://api.pwnedpasswords.com/range/5BAA6", asked)
        assertEquals(9545824, count)
        assertEquals(0, Pwned.timesLeaked("password") { "0018A45C4D1DEF81644B54AB7F969B88D65:1" })
        assertTrue(Pwned.verdict(9545824).contains("9,545,824 times"))
        assertTrue(Pwned.verdict(0).startsWith("Not found"))
    }
}

class CheckedNoteTest {
    @Test
    fun aCleanStoreAppGetsAQuietNote() {
        val app = AppFacts("My Boy!", "com.fastemulator.gba", "com.android.vending", emptySet())
        val (title, text) = checkedNote(app.label, assess(app, VtReport(true, total = 70)))
        assertEquals("My Boy!: checked, looks safe", title)
        assertEquals("VirusTotal: no engine flags it · Installed from Google Play", text)
    }
}
