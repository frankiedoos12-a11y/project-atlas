package com.projectatlas.android

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class DnsTest {
    private val app = byteArrayOf(10, 111, 222.toByte(), 2)
    private val server = byteArrayOf(10, 111, 222.toByte(), 1)

    private fun lookup(name: String, type: Int = 1, port: Int = 53): ByteArray {
        val dns = mutableListOf<Byte>(0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0)
        for (label in name.split('.')) {
            dns += label.length.toByte()
            dns += label.toByteArray().toList()
        }
        dns += listOf<Byte>(0, 0, type.toByte(), 0, 1)
        val packet = ByteArray(28 + dns.size)
        packet[0] = 0x45
        packet[2] = (packet.size shr 8).toByte(); packet[3] = packet.size.toByte()
        packet[8] = 64
        packet[9] = 17
        app.copyInto(packet, 12)
        server.copyInto(packet, 16)
        packet[20] = 0xC3.toByte(); packet[21] = 0x50 // port 50000
        packet[22] = (port shr 8).toByte(); packet[23] = port.toByte()
        packet[24] = ((8 + dns.size) shr 8).toByte(); packet[25] = (8 + dns.size).toByte()
        dns.toByteArray().copyInto(packet, 28)
        return packet
    }

    @Test
    fun readsTheSiteName() {
        val q = Dns.parse(lookup("Evil.Example.com", type = 28))!!
        assertEquals("evil.example.com", q.name)
        assertEquals(28, q.type)
        assertEquals(50000, q.sourcePort)
        assertArrayEquals(app, q.source)
        assertArrayEquals(server, q.server)
    }

    @Test
    fun ignoresWhatIsNotALookup() {
        assertNull(Dns.parse(lookup("example.com", port = 443)))
        assertNull(Dns.parse(ByteArray(10)))
        val tcp = lookup("example.com").also { it[9] = 6 }
        assertNull(Dns.parse(tcp))
        val cut = lookup("example.com")
        assertNull(Dns.parse(cut, 35)) // the name runs past the end
    }

    @Test
    fun blockedAnswerSaysNoSuchSite() {
        val q = Dns.parse(lookup("evil.example.com"))!!
        val reply = Dns.blocked(q)
        assertEquals(0x12, reply[0].toInt())
        assertEquals(0x34, reply[1].toInt())
        assertEquals(0x81, reply[2].toInt() and 0xFF) // an answer, recursion asked
        assertEquals(3, reply[3].toInt() and 0x0F) // NXDOMAIN
        assertEquals(q.dns.size, reply.size) // the question, nothing more
    }

    @Test
    fun answerGoesBackToTheApp() {
        val q = Dns.parse(lookup("example.com"))!!
        val packet = Dns.answer(q, Dns.blocked(q))
        assertEquals(0, Dns.checksum(packet, 0, 20)) // a correct header sums to zero
        assertArrayEquals(server, packet.copyOfRange(12, 16))
        assertArrayEquals(app, packet.copyOfRange(16, 20))
        assertEquals(53, ((packet[20].toInt() and 0xFF) shl 8) or (packet[21].toInt() and 0xFF))
        assertEquals(50000, ((packet[22].toInt() and 0xFF) shl 8) or (packet[23].toInt() and 0xFF))
        // And it reads as an answer, not a lookup.
        assertNull(Dns.parse(packet))
    }

    @Test
    fun blocksStalkerwareAndMalwareButNotMonitoringApps() {
        val intel = Intel.parse(
            "# atlas-intel 1\nF\t0\tSpyX\tstalkerware\nF\t1\tKidWatch\twatchware\nF\t2\tHook\tmalware\n" +
                "D\tspyx.com\t0\nD\tkidwatch.com\t1\nD\tbad.example\t2\n"
        )!!
        assertEquals("SpyX", blockFor("panel.spyx.com", emptySet(), intel::site)?.name)
        assertEquals("Hook", blockFor("bad.example", emptySet(), intel::site)?.name)
        assertNull(blockFor("kidwatch.com", emptySet(), intel::site))
        assertNull(blockFor("panel.spyx.com", setOf("spyx.com"), intel::site))
        assertNull(blockFor("example.org", emptySet(), intel::site))
    }

    /** A TCP segment from the app to Atlas's DNS address. */
    private fun tcp(seq: Long, ack: Long, flags: Int, payload: ByteArray = ByteArray(0), mss: Int = 0): ByteArray {
        val header = if (mss > 0) 24 else 20
        val packet = ByteArray(20 + header + payload.size)
        packet[0] = 0x45
        packet[2] = (packet.size shr 8).toByte(); packet[3] = packet.size.toByte()
        packet[8] = 64
        packet[9] = 6
        app.copyInto(packet, 12)
        server.copyInto(packet, 16)
        packet[20] = 0xC3.toByte(); packet[21] = 0x50 // port 50000
        packet[23] = 53
        for (i in 0..3) {
            packet[24 + i] = (seq shr (24 - 8 * i)).toByte()
            packet[28 + i] = (ack shr (24 - 8 * i)).toByte()
        }
        packet[32] = ((header / 4) shl 4).toByte()
        packet[33] = flags.toByte()
        if (mss > 0) {
            packet[40] = 2; packet[41] = 4; packet[42] = (mss shr 8).toByte(); packet[43] = mss.toByte()
        }
        payload.copyInto(packet, 20 + header)
        return packet
    }

    private fun framed(dns: ByteArray) = byteArrayOf((dns.size shr 8).toByte(), dns.size.toByte()) + dns

    @Test
    fun answersALookupAskedAgainOverTcp() {
        val conversation = TcpDns(isn = { 1000L })
        val now = 0L
        // Hello: the app's first segment, and Atlas's answer with its own sequence number.
        val syn = Tcp.parse(tcp(0xFFFFFFF0L, 0, Tcp.SYN, mss = 100))!!
        assertEquals(100, syn.mss)
        val synAck = Tcp.parse(conversation.receive(syn, now).send.single().also {
            assertEquals(0, Dns.checksum(it, 0, 20))
        }.let { it.copyOf().also { p -> p[22] = 0; p[23] = 53 } })!! // read it back as if sent to port 53
        assertEquals(Tcp.SYN or Tcp.ACK, synAck.flags)
        assertEquals(1000L, synAck.seq)
        assertEquals(0xFFFFFFF1L, synAck.ack)

        // The lookup arrives in two pieces, across the sequence number's wrap.
        val dns = lookup("big.example.com").copyOfRange(28, lookup("big.example.com").size)
        val whole = framed(dns)
        val first = conversation.receive(Tcp.parse(tcp(0xFFFFFFF1L, 1001, Tcp.ACK, whole.copyOf(5)))!!, now)
        assertEquals(0, first.lookups.size)
        val second = conversation.receive(
            Tcp.parse(tcp(0xFFFFFFF6L, 1001, Tcp.ACK or Tcp.PSH, whole.copyOfRange(5, whole.size)))!!, now)
        assertArrayEquals(dns, second.lookups.single())
        assertEquals("big.example.com", Dns.question(second.lookups.single())!!.first)

        // A big answer goes back in pieces that fit what the app said it takes.
        val answer = ByteArray(250) { it.toByte() }.also { dns.copyOf(12).copyInto(it) }
        val pieces = conversation.reply(syn.key, answer)
        assertEquals(3, pieces.size) // 252 bytes with the length, 100 at a time
        val got = pieces.flatMap { p ->
            val header = ((p[32].toInt() and 0xFF) shr 4) * 4
            p.copyOfRange(20 + header, p.size).toList()
        }.toByteArray()
        assertArrayEquals(framed(answer), got)
        // TCP's checksum, with the addresses, sums to zero on each piece.
        for (p in pieces) {
            val sum = ByteArray(12 + p.size - 20)
            p.copyInto(sum, 0, 12, 20)
            sum[9] = 6
            sum[10] = ((p.size - 20) shr 8).toByte(); sum[11] = (p.size - 20).toByte()
            p.copyInto(sum, 12, 20, p.size)
            assertEquals(0, Dns.checksum(sum, 0, sum.size))
        }

        // The app closes; Atlas closes too, then forgets the connection.
        val end = 0xFFFFFFF1L + whole.size
        val bye = conversation.receive(Tcp.parse(tcp(end and 0xFFFFFFFFL, 1001L + 252, Tcp.FIN or Tcp.ACK))!!, now)
        assertEquals(2, bye.send.size)
        assertEquals(Tcp.FIN or Tcp.ACK, bye.send.last()[33].toInt())
        assertEquals(0, conversation.reply(syn.key, answer).size)
    }

    @Test
    fun strayTcpIsReset() {
        val conversation = TcpDns()
        val stray = conversation.receive(Tcp.parse(tcp(5, 77, Tcp.ACK, byteArrayOf(0, 1, 2)))!!, 0)
        assertEquals(Tcp.RST, stray.send.single()[33].toInt())
        assertEquals(0, stray.lookups.size)
        assertNull(Tcp.parse(tcp(5, 77, Tcp.SYN).also { it[23] = 80 })) // not DNS
    }

    @Test
    fun malwareLinkInAMessageIsAScam() {
        val intel = Intel.parse("# atlas-intel 1\nF\t0\tHook\tmalware\nD\tbad.example\t0\n")!!
        val reasons = siteReasons(listOf("https://bad.example/pay"), intel::site)
        assertEquals("Link to a malware site", reasons.single().title)
        assertEquals(4, reasons.single().weight)
    }
}
