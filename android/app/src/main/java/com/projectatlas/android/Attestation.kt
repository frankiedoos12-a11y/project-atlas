package com.projectatlas.android

import java.io.ByteArrayInputStream
import java.security.PublicKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64

/**
 * Start-up proof: the phone's security chip vouches for how the phone started. Atlas asks Android's keystore for a
 * new key with an attestation; the chip signs a certificate saying whether the bootloader is locked, whether the
 * software it started was the maker's own and unchanged, and its security patch. The signatures lead back to
 * Google's root, built into the chip at the factory, so software on the phone (spyware included) can't forge it.
 * GrapheneOS's Auditor uses the same proof. What it can't show: spyware that broke in after the phone started.
 */
data class BootProof(
    val chainTrusted: Boolean, // the signatures lead to Google's root
    val hardware: Boolean, // signed by the security chip (TEE or StrongBox), not just software
    val strongBox: Boolean,
    val locked: Boolean, // bootloader locked
    val state: Int, // 0 verified (the maker's software), 1 self-signed (another OS, locked), 2 unverified, 3 failed
    val bootKey: String, // fingerprint of the key that signed the software the phone started
    val bootHash: String, // fingerprint of that software itself; changes with each system update
    val osPatch: Int, // 202610
    val serials: List<String> = emptyList(), // each certificate's serial, for Google's revoked list
    val challenge: String = "", // what Atlas asked the chip to sign, so an old proof can't be replayed
)

object Der {
    class Item(val tag: Int, val constructed: Boolean, val value: ByteArray) {
        fun children(): List<Item> = read(value)
        fun int(): Long = value.fold(if (value.isNotEmpty() && value[0] < 0) -1L else 0L) { a, b -> (a shl 8) or (b.toLong() and 0xFF) }
    }

    /** Every item in [data], one level deep. Tags keep their class bits: 0x30 SEQUENCE, 0xA0 + n context [n]. */
    fun read(data: ByteArray): List<Item> {
        val items = mutableListOf<Item>()
        var i = 0
        while (i < data.size) {
            val first = data[i++].toInt() and 0xFF
            var tag = first
            if (first and 0x1F == 0x1F) { // a high tag number, base 128
                var n = 0
                do {
                    val b = data[i++].toInt() and 0xFF
                    n = (n shl 7) or (b and 0x7F)
                } while (b and 0x80 != 0)
                tag = ((first and 0xE0) shl 24) or n // class bits on top, the number below
            }
            var length = data[i++].toInt() and 0xFF
            if (length and 0x80 != 0) {
                val bytes = length and 0x7F
                length = 0
                repeat(bytes) { length = (length shl 8) or (data[i++].toInt() and 0xFF) }
            }
            require(length >= 0 && i + length <= data.size) { "bad length" }
            items += Item(tag, first and 0x20 != 0, data.copyOfRange(i, i + length))
            i += length
        }
        return items
    }

    /** The tag a context-specific [n] field with a high number gets from [read]. */
    fun context(n: Int) = ((0xA0) shl 24) or n
}

object Attestation {
    const val OID = "1.3.6.1.4.1.11129.2.1.17"
    private const val ROOT_OF_TRUST = 704
    private const val OS_PATCH = 706

    /** Google's attestation roots: the RSA key every older root shares, and "Key Attestation CA1" (from 2026). */
    val rootCertificates = listOf(
        "MIIFHDCCAwSgAwIBAgIJAPHBcqaZ6vUdMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNVBAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMjIwMzIwMTgw" +
            "NzQ4WhcNNDIwMzE1MTgwNzQ4WjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA" +
            "r7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdSSxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7tv0S" +
            "k3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggjnar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyT" +
            "qRxB/M0n1n/W9nGqC4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQoVJYnFPlXTcHYvASLu+RhhsbDmxM" +
            "gJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+OJtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/EgsTUVi2gh" +
            "zq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRiigHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jh" +
            "O2B6tUXHI/+MRPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9EaDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2" +
            "QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5UmAGMCAwEAAaNjMGEwHQYDVR0OBBYEFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMB8GA1UdIwQYMBaAFDZh" +
            "4QB8iAUJUYtEbEf/GkzJ6k8SMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgIEMA0GCSqGSIb3DQEBCwUAA4ICAQB8cMqTllHc8U+q" +
            "CrOlg3H7174lmaCsbo/bJ0C17JEgMLb4kvrqsXZs01U3mB/qABg/1t5Pd5AORHARs1hhqGICW/nKMav574f9rZN4PC2ZlufGXb7sIdJpGiO9" +
            "ctRhiLuYuly10JccUZGEHpHSYM2GtkgYbZba6lsCPYAAP83cyDV+1aOkTf1RCp/lM0PKvmxYN10RYsK631jrleGdcdkxoSK//mSQbgcWnmAE" +
            "ZrzHoF1/0gso1HZgIn0YLzVhLSA/iXCX4QT2h3J5z3znluKG1nv8NQdxei2DIIhASWfu804CA96cQKTTlaae2fweqXjdN1/v2nqOhngNyz13" +
            "61mFmr4XmaKH/ItTwOe72NI9ZcwS1lVaCvsIkTDCEXdm9rCNPAY10iTunIHFXRh+7KPzlHGewCq/8TOohBRn0/NNfh7uRslOSZ/xKbN9tMBt" +
            "w37Z8d2vvnXq/YWdsm1+JLVwn6yYD/yacNJBlwpddla8eaVMjsF6nBnIgQOf9zKSe06nSTqvgwUHosgOECZJZ1EuzbH4yswbt02tKtKEFhx+" +
            "v+OTge/06V+jGsqTWLsfrOCNLuA8H++z+pUENmpqnnHovaI47gC+TNpkgYGkkBT6B/m/U01BuOBBTzhIlMEZq9qkDWuM2cA5kW5V3FJUcfHn" +
            "w1IdYIg2Wxg7yHcQZemFQg==",
        "MIICIjCCAaigAwIBAgIRAISp0Cl7DrWK5/8OgN52BgUwCgYIKoZIzj0EAwMwUjEcMBoGA1UEAwwTS2V5IEF0dGVzdGF0aW9uIENBMTEQMA4G" +
            "A1UECwwHQW5kcm9pZDETMBEGA1UECgwKR29vZ2xlIExMQzELMAkGA1UEBhMCVVMwHhcNMjUwNzE3MjIzMjE4WhcNMzUwNzE1MjIzMjE4WjBS" +
            "MRwwGgYDVQQDDBNLZXkgQXR0ZXN0YXRpb24gQ0ExMRAwDgYDVQQLDAdBbmRyb2lkMRMwEQYDVQQKDApHb29nbGUgTExDMQswCQYDVQQGEwJV" +
            "UzB2MBAGByqGSM49AgEGBSuBBAAiA2IABCPaI3FO3z5bBQo8cuiEas4HjqCtG/mLFfRT0MsIssPBEEU5Cfbt6sH5yOAxqEi5QagpU1yX4Hwn" +
            "Gb7OtBYpDTB57uH5Eczm34A5FNijV3s0/f0UPl7zbJcTx6xwqMIRq6NCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYD" +
            "VR0OBBYEFFIyuyz7RkOb3NaBqQ5lZuA0QepAMAoGCCqGSM49BAMDA2gAMGUCMETfjPO/HwqReR2CS7p0ZWoD/LHs6hDi422opifHEUaYLxwG" +
            "lT9SLdjkVpz0UUOR5wIxAIoGyxGKRHVTpqpGRFiJtQEOOTp/+s1GcxeYuR2zh/80lQyu9vAFCj6E4AXc+osmRg==",
    ).map { certificate(Base64.getDecoder().decode(it)) }
    private val ROOTS = rootCertificates.map { it.publicKey }

    fun certificate(der: ByteArray): X509Certificate =
        CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(der)) as X509Certificate

    fun rootKeys(): List<PublicKey> = ROOTS

    /** Each certificate signed by the next, and the last one a Google root. */
    fun trusted(chain: List<X509Certificate>, roots: List<PublicKey> = ROOTS): Boolean = try {
        chain.isNotEmpty() && chain.zipWithNext().all { (cert, issuer) -> cert.verify(issuer.publicKey); true } &&
            chain.last().publicKey.encoded.let { last -> roots.any { it.encoded.contentEquals(last) } } &&
            chain.last().let { it.verify(it.publicKey); true }
    } catch (e: Exception) {
        false
    }

    /** The proof in the first certificate that carries one, or null when there's none to read. */
    fun read(chain: List<X509Certificate>, roots: List<PublicKey> = ROOTS): BootProof? {
        val cert = chain.firstOrNull { it.getExtensionValue(OID) != null } ?: return null
        return parse(Der.read(cert.getExtensionValue(OID)).single().value, trusted(chain, roots),
            chain.map { it.serialNumber.toString(16).lowercase() })
    }

    /** The KeyDescription the chip signed (the extension's value). */
    fun parse(description: ByteArray, chainTrusted: Boolean, serials: List<String> = emptyList()): BootProof? = try {
        val fields = Der.read(description).single().children()
        val level = fields[1].int().toInt() // 0 software, 1 TEE, 2 StrongBox
        val hardware = fields[7].children()
        val root = hardware.firstOrNull { it.tag == Der.context(ROOT_OF_TRUST) }?.children()?.single()?.children()
        val patch = (hardware + fields[6].children()).firstOrNull { it.tag == Der.context(OS_PATCH) }
            ?.children()?.single()?.int()?.toInt() ?: 0
        if (root == null) {
            null
        } else {
            BootProof(chainTrusted, level >= 1, level == 2,
                locked = root[1].value.firstOrNull()?.toInt() != 0,
                state = root[2].int().toInt(),
                bootKey = hex(root[0].value),
                bootHash = root.getOrNull(3)?.value?.let(::hex).orEmpty(),
                osPatch = patch, serials = serials, challenge = hex(fields[4].value))
        }
    } catch (e: Exception) {
        null
    }

    fun hex(bytes: ByteArray) = bytes.joinToString("") { "%02x".format(it) }
}

/**
 * What the proof says, compared with what Atlas saw last time ([pinnedKey], [lastHash], [lastPatch]): the first
 * proof is remembered, as Auditor does, so a later change to the software the phone starts stands out.
 */
fun bootFindings(proof: BootProof?, revoked: Boolean, pinnedKey: String?, lastHash: String?, lastPatch: Int): List<Finding> {
    val area = "Start-up proof"
    if (proof == null) {
        return listOf(Finding(area, "This phone can't prove how it started", Level.NOTE, listOf(
            "Its security chip didn't give Atlas a start-up proof. Older and some budget phones can't; it isn't a " +
                "sign of spyware by itself."), "boot:none"))
    }
    val out = mutableListOf<Finding>()
    if (!proof.chainTrusted || revoked) {
        out += Finding(area, "The start-up proof is forged or revoked", Level.WARN, listOf(
            if (revoked) "Google has revoked a key in this phone's proof: leaked keys like it are used to fake a " +
                "clean phone." else "The proof isn't signed by Google's root, so something on the phone made it up.",
            "Phones aren't supposed to do this. Treat it as compromised until it's wiped."), "boot:forged")
        return out
    }
    if (!proof.hardware) {
        out += Finding(area, "Only software vouches for this phone", Level.NOTE, listOf(
            "The proof came from software, not a security chip, so it proves little. Emulators and some older " +
                "phones work this way."), "boot:software")
    }
    when {
        !proof.locked -> out += Finding(area, "The bootloader is unlocked", Level.WARN, listOf(
            "The chip says the phone can start any software, so someone could have changed Android itself. If you " +
                "didn't unlock it, treat the phone as compromised."), "boot:unlocked", DEVELOPER_SETTINGS)
        proof.state == 1 -> out += Finding(area, "Another operating system, locked", Level.OK, listOf(
            "The phone runs software signed by someone other than its maker (such as GrapheneOS), with the " +
                "bootloader locked again. That's fine if you installed it."), "boot:selfsigned")
        proof.state != 0 -> out += Finding(area, "Start-up checks failed", Level.WARN, listOf(
            "The chip says the software the phone started wasn't verified. Treat the phone as compromised."),
            "boot:unverified")
        else -> out += Finding(area, "Started the maker's own, unchanged software", Level.OK, listOf(
            "The security chip vouches that the bootloader is locked and the system wasn't changed."), "boot:ok")
    }
    if (pinnedKey != null && pinnedKey != proof.bootKey) {
        out += Finding(area, "The phone now starts software signed by someone else", Level.WARN, listOf(
            "The key that signs the system changed since Atlas first checked. That happens when you install another " +
                "operating system; if you didn't, someone replaced Android."), "boot:newkey")
    }
    if (lastHash != null && lastHash.isNotEmpty() && proof.bootHash.isNotEmpty() && lastHash != proof.bootHash &&
        proof.osPatch == lastPatch) {
        out += Finding(area, "The system changed without an update", Level.NOTE, listOf(
            "The software the phone starts is different from last time, but its security patch is the same. Some " +
                "makers ship small updates this way; if you didn't install one, look closer."), "boot:changed")
    }
    return out
}
