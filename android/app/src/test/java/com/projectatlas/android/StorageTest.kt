package com.projectatlas.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class StorageTest {
    private val now = 400 * DAY_MS

    private fun app(label: String, used: Long, installed: Long = 0, size: Long = 100, icon: Boolean = true) =
        AppUse(label, "com.$label", false, icon, size, 0, 0, used, installed)

    @Test
    fun sizesReadLikeWindows() {
        assertEquals("512 bytes", humanSize(512))
        assertEquals("1.5 KB", humanSize(1536))
        assertEquals("2.0 GB", humanSize(2L shl 30))
    }

    @Test
    fun unusedAppsAreOldUnopenedAndBiggestFirst() {
        val apps = listOf(
            app("daily", now - DAY_MS),
            app("forgotten", now - 200 * DAY_MS, size = 10),
            app("never", 0, size = 500),
            app("new", 0, installed = now - 5 * DAY_MS), // just installed: not "unused" yet
            app("hidden", 0, icon = false), // no icon: can't be opened anyway
        )
        assertEquals(listOf("never", "forgotten"), unusedApps(apps, now).map { it.label })
        assertEquals("Opened yesterday", lastUsedText(apps[0], now))
        assertEquals("Not opened in 6 months", lastUsedText(apps[1], now))
        assertEquals("Not opened in a long time (or ever)", lastUsedText(apps[2], now))
    }

    private fun file(path: String, size: Long, modified: Long = 0, content: String = "same") =
        FileItem("content://$path#$content", path, path.substringAfterLast('/'), size, modified, "image/jpeg")

    @Test
    fun duplicatesKeepTheCamerasCopyAndOnlyReadSameSizes() {
        val read = mutableListOf<String>()
        val files = listOf(
            file("Download/IMG_1.jpg", 4000, modified = 1),
            file("DCIM/Camera/IMG_1.jpg", 4000, modified = 5),
            file("Pictures/WhatsApp/IMG_1.jpg", 4000, modified = 9),
            file("Download/other.jpg", 4000, content = "different"),
            file("Download/alone.jpg", 1234),
        )
        val content = { f: FileItem -> read += f.path; f.uri.substringAfter('#') }
        val groups = duplicateGroups(files, content, content)
        assertEquals(1, groups.size)
        assertEquals("DCIM/Camera/IMG_1.jpg", groups[0].keep.path)
        assertEquals(listOf("Download/IMG_1.jpg", "Pictures/WhatsApp/IMG_1.jpg"), groups[0].extras.map { it.path })
        assertEquals(8000L, groups[0].wasted)
        assertTrue("Download/alone.jpg" !in read) // a size nothing else has is never read
        // Unreadable files are left out, not grouped together.
        assertEquals(emptyList<DuplicateGroup>(), duplicateGroups(files, { null }, { null }))
    }

    @Test
    fun biggestFilesAndRiskyKinds() {
        val files = listOf(file("a.mp4", 900L shl 20), file("b.jpg", 1L shl 20), file("c.mp4", 50L shl 20))
        assertEquals(listOf("a.mp4", "c.mp4"), biggest(files).map { it.name })
        assertEquals(0, riskOf("Free-Netflix.APK")?.rank)
        assertEquals(1, riskOf("invoice.pdf.exe")?.rank)
        assertEquals(2, riskOf("invoice.pdf")?.rank)
        assertEquals(null, riskOf("holiday.jpg"))
        val apk = file("Download/game.apk", 10)
        assertTrue(riskyFileText(apk, VtReport(false)).startsWith("VirusTotal doesn't know this app"))
        assertTrue(riskyFileText(file("Documents/cv.pdf", 10), VtReport(false)).contains("normal for your own documents"))
        assertEquals("Not checked yet", riskyFileText(apk, null))
    }
}
