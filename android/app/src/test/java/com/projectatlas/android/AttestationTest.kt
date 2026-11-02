package com.projectatlas.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AttestationTest {
    private fun tlv(tag: Int, vararg parts: ByteArray): ByteArray {
        val body = parts.fold(ByteArray(0)) { a, b -> a + b }
        val len = if (body.size < 128) byteArrayOf(body.size.toByte())
            else byteArrayOf(0x82.toByte(), (body.size shr 8).toByte(), body.size.toByte())
        return byteArrayOf(tag.toByte()) + len + body
    }

    /** A context-specific, constructed field with a tag number above 30: [704] is BF 85 40. */
    private fun field(n: Int, inner: ByteArray): ByteArray {
        val body = inner
        return byteArrayOf(0xBF.toByte(), (0x80 or (n shr 7)).toByte(), (n and 0x7F).toByte(), body.size.toByte()) + body
    }

    private fun int(v: Int) = tlv(0x02, if (v < 128) byteArrayOf(v.toByte()) else
        byteArrayOf((v shr 16).toByte(), (v shr 8).toByte(), v.toByte()).dropWhile { it == 0.toByte() }.toByteArray())

    private fun description(level: Int, locked: Boolean, state: Int, patch: Int = 202610): ByteArray {
        val root = tlv(0x30, tlv(0x04, ByteArray(32) { 0x11 }), tlv(0x01, byteArrayOf(if (locked) -1 else 0)),
            tlv(0x0A, byteArrayOf(state.toByte())), tlv(0x04, ByteArray(32) { 0x22 }))
        val hardware = tlv(0x30, field(704, root), field(706, int(patch)))
        return tlv(0x30, int(4), tlv(0x0A, byteArrayOf(level.toByte())), int(4), tlv(0x0A, byteArrayOf(level.toByte())),
            tlv(0x04, byteArrayOf(1, 2, 3)), tlv(0x04), tlv(0x30), hardware)
    }

    @Test
    fun readsWhatTheChipSigned() {
        val proof = Attestation.parse(description(1, locked = true, state = 0), chainTrusted = true)!!
        assertTrue(proof.hardware)
        assertFalse(proof.strongBox)
        assertTrue(proof.locked)
        assertEquals(0, proof.state)
        assertEquals(202610, proof.osPatch)
        assertEquals("11".repeat(32), proof.bootKey)
        assertEquals("22".repeat(32), proof.bootHash)
    }

    @Test
    fun googleRootsAreBuiltIn() {
        assertEquals(2, Attestation.rootKeys().size) // both parse from the text in the app
        for (root in Attestation.rootCertificates) assertTrue(Attestation.trusted(listOf(root))) // and sign themselves
        assertFalse(Attestation.trusted(emptyList()))
    }

    @Test
    fun aCleanPhoneIsOk() {
        val proof = Attestation.parse(description(2, true, 0), true)!!
        val found = bootFindings(proof, false, null, null, 0)
        assertEquals(listOf(Level.OK), found.map { it.level })
    }

    @Test
    fun unlockedOrForgedIsSerious() {
        val unlocked = Attestation.parse(description(1, false, 2), true)!!
        assertEquals("boot:unlocked", bootFindings(unlocked, false, null, null, 0).single { it.level == Level.WARN }.key)
        val forged = Attestation.parse(description(1, true, 0), false)!!
        assertEquals("boot:forged", bootFindings(forged, false, null, null, 0).single().key)
        val revoked = Attestation.parse(description(1, true, 0), true)!!
        assertEquals("boot:forged", bootFindings(revoked, true, null, null, 0).single().key)
    }

    @Test
    fun aNewSigningKeyOrQuietChangeStandsOut() {
        val proof = Attestation.parse(description(1, true, 0), true)!!
        assertTrue(bootFindings(proof, false, "aa".repeat(32), null, 0).any { it.key == "boot:newkey" })
        assertTrue(bootFindings(proof, false, proof.bootKey, "33".repeat(32), 202610).any { it.key == "boot:changed" })
        // An update changes the patch too: expected, not flagged.
        assertFalse(bootFindings(proof, false, proof.bootKey, "33".repeat(32), 202609).any { it.key == "boot:changed" })
    }

    @Test
    fun noProofIsANoteNotAnAlarm() {
        assertEquals(Level.NOTE, bootFindings(null, false, null, null, 0).single().level)
        assertNull(Attestation.parse(byteArrayOf(1, 2, 3), true))
    }
}
