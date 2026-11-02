package com.projectatlas.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class CompromiseTest {
    private val now = 1_800_000_000_000L
    private val min = 60_000L

    @Test
    fun microphoneWithTheScreenOffStandsOut() {
        val uses = listOf(
            SensorUse("Microphone", now - 3 * DAY_MS, now - 3 * DAY_MS + 40 * min, screenOff = true, inCall = false),
            SensorUse("Microphone", now - DAY_MS, now - DAY_MS + 30 * min, screenOff = true, inCall = true), // a call
            SensorUse("Microphone", now - DAY_MS, now - DAY_MS + min / 2, screenOff = true, inCall = false), // short
            SensorUse("Camera", now - DAY_MS, now - DAY_MS + 10 * min, screenOff = false, inCall = false),
        )
        val found = sensorFindings(uses, watching = true, now = now)
        assertEquals(listOf("sensors:microphone"), found.map { it.key })
        assertEquals(Level.WARN, found.single().level)
    }

    @Test
    fun ordinaryUseIsOkAndUnwatchedIsANote() {
        val uses = listOf(SensorUse("Camera", now - min, now, screenOff = false, inCall = false))
        assertEquals(Level.OK, sensorFindings(uses, true, now).single().level)
        assertEquals(Level.NOTE, sensorFindings(emptyList(), false, now).single().level)
    }

    @Test
    fun newWatchingPowersAreFlagged() {
        val before = watchSnapshot(PhoneFacts(true, "2026-10-05", "16", false, "off"))
        val after = watchSnapshot(PhoneFacts(true, "2026-10-05", "16", false, "off",
            accessibilityApps = listOf("Sync Service"), addedCertificates = listOf("Corp CA")))
        val timeline = snapshotChanges(before, after, now - DAY_MS)
        assertEquals(2, timeline.size)
        val found = changeFindings(timeline, now)
        assertTrue(found.all { it.level == Level.WARN })
        assertTrue(found.any { it.title.endsWith("Accessibility: Sync Service") })
        // Removing one isn't a warning, and old changes drop off.
        assertEquals(Level.OK, changeFindings(snapshotChanges(after, before, now), now).single().level)
        assertEquals(Level.OK, changeFindings(timeline, now + 20 * DAY_MS).single().level)
    }

    @Test
    fun uploadsFarAboveNormal() {
        val mb = 1024L * 1024
        assertNull(uploadFinding(listOf(1, 2, 3)))
        val normal = List(7) { 20 * mb }
        assertEquals(Level.OK, uploadFinding(normal + 30 * mb)!!.level)
        assertEquals(Level.WARN, uploadFinding(normal + 900 * mb)!!.level)
        assertEquals(Level.OK, uploadFinding(List(7) { mb } + 150 * mb)!!.level) // big jump, but small
    }

    @Test
    fun restartAndUpdates() {
        assertEquals(Level.NOTE, restartFinding(4 * DAY_MS).level)
        assertEquals(Level.OK, restartFinding(DAY_MS).level)
        val found = freshnessFindings(listOf("Chrome" to now - 5 * DAY_MS, "WhatsApp" to now - 90 * DAY_MS), now)
        assertEquals(listOf("stale:WhatsApp"), found.map { it.key })
        assertEquals(Level.OK, freshnessFindings(listOf("Chrome" to now), now).single().level)
    }

    @Test
    fun spywareIsNamedAndBlocked() {
        val intel = Intel.parse("# atlas-intel 1\nF\t0\tPegasus (NSO Group)\tspyware\nD\tfree247downloads.com\t0\n" +
            "P\tcom.spy.helper\t0\n")!!
        val hit = intel.app("com.spy.helper")!!
        assertEquals("commercial spyware", hit.family.what)
        assertEquals(Verdict.MALICIOUS, intelReason(hit).first)
        assertEquals("Pegasus (NSO Group)", blockFor("x.free247downloads.com", emptySet(), intel::site)?.name)
        assertEquals("Link to a spyware site", siteReasons(listOf("https://free247downloads.com/a"), intel::site).single().title)
    }
}
