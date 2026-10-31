package com.projectatlas.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class IntelTest {
    private val sample = """# atlas-intel 1
# version 20261030
# source: test
F	0	TheTruthSpy	stalkerware
F	1	FamiSafe	watchware
P	com.thetruth	0
P	com.wondershare.famisafe	1
C	31A6ECECD97CF39BC4126B8745CD94A7C30BF81C	0
H	2f3bc9ebe8c249f0416f5b0367f34b4b8f6aaa7d351dc5b4912fe2558491b6b7	0
D	thetruthspy.com	0
D	famisafe.wondershare.com	1
"""
    private val intel = Intel.parse(sample)!!

    @Test
    fun matchesByFileThenSignerThenName() {
        assertEquals(Match.FILE, intel.app("other", emptyList(), "2F3BC9EBE8C249F0416F5B0367F34B4B8F6AAA7D351DC5B4912FE2558491B6B7")?.match)
        assertEquals(Match.CERTIFICATE, intel.app("com.renamed", listOf("aa", "31a6ececd97cf39bc4126b8745cd94a7c30bf81c"))?.match)
        assertEquals(IntelHit(Family("TheTruthSpy", "stalkerware"), Match.PACKAGE), intel.app("com.thetruth"))
        assertNull(intel.app("com.thetruth.other"))
        assertEquals(20261030L, intel.version)
    }

    @Test
    fun websitesMatchTheirSubdomainsOnly() {
        assertEquals("TheTruthSpy", intel.site("my.TheTruthSpy.com")?.name)
        assertEquals("TheTruthSpy", intel.site("thetruthspy.com.")?.name)
        assertNull(intel.site("notthetruthspy.com"))
        assertNull(intel.site("wondershare.com")) // only the listed part of a shared domain
        assertEquals("FamiSafe", intel.site("famisafe.wondershare.com")?.name)
    }

    @Test
    fun brokenDataIsRefused() {
        assertNull(Intel.parse(""))
        assertNull(Intel.parse("<html>404</html>"))
        assertNull(Intel.parse("# atlas-intel 2\nF\t0\tX\tstalkerware\n")) // a format this app doesn't know
        assertNull(Intel.parse("# atlas-intel 1\nP\tcom.x\t0\n")) // points at a family that isn't there
    }

    @Test
    fun theShippedDataReadsAndKnowsTheBigFamilies() {
        val shipped = Intel.parse(File("src/main/assets/intel.txt").readText())!!
        assertTrue(shipped.size >= 100)
        assertEquals("TheTruthSpy", shipped.app("com.thetruth")?.family?.name)
        assertEquals(Match.CERTIFICATE, shipped.app("x", listOf("31A6ECECD97CF39BC4126B8745CD94A7C30BF81C"))?.match)
        assertNull(shipped.site("drive.google.com"))
        assertNull(shipped.site("firebaseio.com"))
    }

    @Test
    fun stalkerwareOutranksTheStore() {
        val play = AppFacts("System Service", "com.thetruth", "com.android.vending", emptySet())
        val strong = assess(play, null, IntelHit(Family("TheTruthSpy", "stalkerware"), Match.CERTIFICATE))
        assertEquals(Verdict.MALICIOUS, strong.verdict)
        assertTrue(strong.reasons.first().startsWith("Known stalkerware: TheTruthSpy (it's signed"))
        assertEquals(Verdict.SUSPICIOUS, assess(play, null, IntelHit(Family("X", "stalkerware"), Match.PACKAGE)).verdict)
        val watch = assess(play, null, IntelHit(Family("FamiSafe", "watchware"), Match.CERTIFICATE))
        assertEquals(Verdict.SUSPICIOUS, watch.verdict)
        assertTrue(watch.reasons.first().startsWith("A monitoring app: FamiSafe"))
        // A clean VirusTotal answer doesn't lower it.
        assertEquals(Verdict.MALICIOUS, assess(play, VtReport(true, total = 70),
            IntelHit(Family("TheTruthSpy", "stalkerware"), Match.FILE)).verdict)
    }

    @Test
    fun scamChecksKnowStalkerwareSites() {
        val text = "Install this to see who he's texting: https://thetruthspy.com/download"
        val reasons = siteReasons(extractLinks(text)) { intel.site(it) }
        assertEquals(listOf("Link to stalkerware" to 4), reasons.map { it.title to it.weight })
        assertEquals(SCAM, scamVerdict(reasons.sumOf { it.weight }))
        assertEquals(emptyList<Reason>(), siteReasons(listOf("https://example.com")) { intel.site(it) })
    }

    @Test
    fun theNewestMessageIsChecked() {
        assertEquals("second", messageText(listOf("first", "second", " "), "big", "short"))
        assertEquals("big", messageText(emptyList(), "big", "short"))
        assertEquals("short", messageText(emptyList(), "", "short"))
        assertNull(messageText(emptyList(), null, " "))
    }
}

class TextAlertTest {
    @Test
    fun theSampleTextIsAScamWithoutAKey() {
        val reasons = wordReasons(TextWatch.SAMPLE)
        assertEquals(listOf("Unpaid toll or parcel", "Pressure to act now", PAY_THROUGH_LINK), reasons.map { it.title })
        assertEquals(SCAM, scamVerdict(reasons.sumOf { it.weight }))
        // Without a link, the same words stay "Be careful".
        assertEquals(CAREFUL, scamVerdict(wordReasons("Your package couldn't be delivered. Call within 24 hours.")
            .sumOf { it.weight }))
    }

    @Test
    fun agoReadsNaturally() {
        assertEquals("just now", ago(30_000))
        assertEquals("1 minute ago", ago(60_000))
        assertEquals("3 hours ago", ago(3 * 3_600_000L))
        assertEquals("2 days ago", ago(2 * 86_400_000L))
    }
}

class MalwareTest {
    @Test
    fun malwareBazaarSamplesAreDangerousAndNamed() {
        val intel = Intel.parse("# atlas-intel 1\n# version 20261031\n# source: A, CC BY 4.0, https://a.example\n" +
            "# source: MalwareBazaar by abuse.ch, CC0, https://bazaar.abuse.ch\nF\t0\tSpyNote\tmalware\n" +
            "H\taaaa111111111111111111111111111111111111111111111111111111111111\t0\n")!!
        assertEquals(2, intel.sources.size)
        val hit = intel.app("com.any", emptyList(), "AAAA111111111111111111111111111111111111111111111111111111111111")!!
        assertEquals("Android malware", hit.family.what)
        val (verdict, why) = intelReason(hit)
        assertEquals(Verdict.MALICIOUS, verdict)
        assertTrue(why.startsWith("Known Android malware: SpyNote (the app file itself is a known sample)"))
        assertEquals("stalkerware", Family("X", "stalkerware").what)
        assertEquals("monitoring app", Family("X", "watchware").what)
    }
}
