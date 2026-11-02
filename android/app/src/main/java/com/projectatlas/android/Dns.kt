package com.projectatlas.android

import java.io.ByteArrayOutputStream
import kotlin.random.Random

/**
 * Just enough DNS and IPv4/UDP for link protection: read the site name out of a lookup the phone sends to Atlas's
 * DNS address, and wrap an answer (the real one, or "no such site" for a blocked one) to send back. Plain logic,
 * tested on the PC; the service that uses it is LinkGuard.
 */
class DnsQuery(
    val source: ByteArray, // the app's IPv4 address and port, where the answer goes
    val sourcePort: Int,
    val server: ByteArray, // Atlas's DNS address, which the answer comes from
    val dns: ByteArray, // the DNS message itself
    val name: String, // "example.com", lower case
    val type: Int, // 1 = A, 28 = AAAA, ...
)

object Dns {
    private const val UDP = 17

    /** The lookup in an IPv4 packet sent to port 53, or null for anything else. */
    fun parse(packet: ByteArray, length: Int = packet.size): DnsQuery? {
        if (length < 28 || (packet[0].toInt() shr 4) != 4 || packet[9].toInt() != UDP) return null
        val ihl = (packet[0].toInt() and 0x0F) * 4
        if (ihl < 20 || length < ihl + 8 + 12) return null
        if (u16(packet, 6) and 0x3FFF != 0) return null // a fragment: lookups are small, so never expected
        val port = u16(packet, ihl + 2)
        if (port != 53) return null
        val udpLength = u16(packet, ihl + 4)
        val end = minOf(length, ihl + udpLength)
        if (end < ihl + 8 + 12) return null
        val dns = packet.copyOfRange(ihl + 8, end)
        val (name, type) = question(dns) ?: return null
        return DnsQuery(packet.copyOfRange(12, 16), u16(packet, ihl), packet.copyOfRange(16, 20), dns, name, type)
    }

    /** The site name and record type a DNS message asks for, or null for an answer or anything else. */
    fun question(dns: ByteArray): Pair<String, Int>? {
        if (dns.size < 12 || dns[2].toInt() and 0x80 != 0 || u16(dns, 4) < 1) return null // an answer, or no question
        val (name, after) = readName(dns, 12) ?: return null
        if (after + 4 > dns.size) return null
        return name to u16(dns, after)
    }

    /** "No such site" for a blocked lookup: the question, with the answer code NXDOMAIN and no records. */
    fun blocked(query: DnsQuery): ByteArray = blocked(query.dns)

    fun blocked(dns: ByteArray): ByteArray {
        val (_, after) = readName(dns, 12)!!
        val reply = dns.copyOf(after + 4)
        reply[2] = (0x80 or (dns[2].toInt() and 0x01)).toByte() // an answer; recursion asked, as asked
        reply[3] = 0x83.toByte() // recursion available; NXDOMAIN
        put16(reply, 4, 1)
        put16(reply, 6, 0)
        put16(reply, 8, 0)
        put16(reply, 10, 0)
        return reply
    }

    /** An IPv4/UDP packet carrying [dns] back to the app that asked. */
    fun answer(query: DnsQuery, dns: ByteArray): ByteArray {
        val packet = ByteArray(28 + dns.size)
        packet[0] = 0x45
        put16(packet, 2, packet.size)
        put16(packet, 6, 0x4000) // don't fragment
        packet[8] = 64 // time to live
        packet[9] = UDP.toByte()
        query.server.copyInto(packet, 12)
        query.source.copyInto(packet, 16)
        put16(packet, 10, checksum(packet, 0, 20))
        put16(packet, 20, 53)
        put16(packet, 22, query.sourcePort)
        put16(packet, 24, 8 + dns.size)
        // UDP checksum 0: "not computed", which IPv4 allows.
        dns.copyInto(packet, 28)
        return packet
    }

    fun checksum(data: ByteArray, from: Int, length: Int): Int {
        var sum = 0L
        var i = from
        while (i < from + length - 1) {
            sum += u16(data, i)
            i += 2
        }
        if (length % 2 == 1) sum += (data[from + length - 1].toInt() and 0xFF) shl 8
        while (sum shr 16 != 0L) sum = (sum and 0xFFFF) + (sum shr 16)
        return (sum.inv() and 0xFFFF).toInt()
    }

    /** A name without compression (lookups never use it): "example.com" and where the question goes on. */
    private fun readName(dns: ByteArray, start: Int): Pair<String, Int>? {
        val labels = mutableListOf<String>()
        var i = start
        while (true) {
            if (i >= dns.size) return null
            val length = dns[i].toInt() and 0xFF
            if (length == 0) break
            if (length > 63 || i + 1 + length > dns.size) return null
            labels += String(dns, i + 1, length, Charsets.ISO_8859_1).lowercase()
            i += 1 + length
        }
        return labels.joinToString(".") to i + 1
    }
}

private fun u16(data: ByteArray, at: Int) = ((data[at].toInt() and 0xFF) shl 8) or (data[at + 1].toInt() and 0xFF)

private fun put16(data: ByteArray, at: Int, value: Int) {
    data[at] = (value shr 8).toByte()
    data[at + 1] = value.toByte()
}

private fun u32(data: ByteArray, at: Int) = (u16(data, at).toLong() shl 16) or u16(data, at + 2).toLong()

private fun put32(data: ByteArray, at: Int, value: Long) {
    put16(data, at, (value shr 16).toInt() and 0xFFFF)
    put16(data, at + 2, value.toInt() and 0xFFFF)
}

/** What link protection blocks: a site the threat data names as stalkerware or malware (monitoring apps' own sites
 * are legitimate businesses, so they open), unless you allowed it. */
fun blockFor(host: String, allowed: Set<String>, site: (String) -> Family?): Family? {
    var h = host.lowercase().trimEnd('.')
    while (h.contains('.')) {
        if (h in allowed) return null
        h = h.substringAfter('.')
    }
    return site(host)?.takeIf { !it.watchware }
}

/** One TCP segment an app sent to Atlas's DNS address on port 53. */
class TcpSegment(
    val source: ByteArray,
    val sourcePort: Int,
    val server: ByteArray,
    val seq: Long,
    val ack: Long,
    val flags: Int,
    val mss: Int, // the biggest piece the app takes at once
    val payload: ByteArray,
) {
    val key get() = source.joinToString(".") { (it.toInt() and 0xFF).toString() } + ":" + sourcePort

    fun has(flag: Int) = flags and flag != 0
}

/** Just enough IPv4/TCP to read a segment and write one back. */
object Tcp {
    const val FIN = 0x01
    const val SYN = 0x02
    const val RST = 0x04
    const val PSH = 0x08
    const val ACK = 0x10
    private const val PROTOCOL = 6

    fun parse(packet: ByteArray, length: Int = packet.size): TcpSegment? {
        if (length < 40 || (packet[0].toInt() shr 4) != 4 || packet[9].toInt() != PROTOCOL) return null
        val ihl = (packet[0].toInt() and 0x0F) * 4
        if (ihl < 20 || length < ihl + 20) return null
        if (u16(packet, 6) and 0x3FFF != 0) return null // a fragment
        if (u16(packet, ihl + 2) != 53) return null
        val total = minOf(length, u16(packet, 2))
        val header = ((packet[ihl + 12].toInt() and 0xFF) shr 4) * 4
        if (header < 20 || ihl + header > total) return null
        var mss = 536 // TCP's default when the app doesn't say
        var i = ihl + 20
        while (i + 1 < ihl + header) {
            val kind = packet[i].toInt() and 0xFF
            if (kind == 0) break
            if (kind == 1) {
                i++
                continue
            }
            val size = packet[i + 1].toInt() and 0xFF
            if (size < 2) break
            if (kind == 2 && size == 4 && i + 4 <= ihl + header) mss = u16(packet, i + 2)
            i += size
        }
        return TcpSegment(packet.copyOfRange(12, 16), u16(packet, ihl), packet.copyOfRange(16, 20),
            u32(packet, ihl + 4), u32(packet, ihl + 8), packet[ihl + 13].toInt() and 0x3F, mss,
            packet.copyOfRange(ihl + header, total))
    }

    /** A segment from Atlas's DNS address back to the app that sent [to]. */
    fun segment(to: TcpSegment, seq: Long, ack: Long, flags: Int, payload: ByteArray = ByteArray(0), mss: Int = 0): ByteArray {
        val header = if (mss > 0) 24 else 20
        val packet = ByteArray(20 + header + payload.size)
        packet[0] = 0x45
        put16(packet, 2, packet.size)
        put16(packet, 6, 0x4000) // don't fragment
        packet[8] = 64
        packet[9] = PROTOCOL.toByte()
        to.server.copyInto(packet, 12)
        to.source.copyInto(packet, 16)
        put16(packet, 10, Dns.checksum(packet, 0, 20))
        put16(packet, 20, 53)
        put16(packet, 22, to.sourcePort)
        put32(packet, 24, seq)
        put32(packet, 28, ack)
        packet[32] = ((header / 4) shl 4).toByte()
        packet[33] = flags.toByte()
        put16(packet, 34, 65535) // window
        if (mss > 0) {
            packet[40] = 2
            packet[41] = 4
            put16(packet, 42, mss)
        }
        payload.copyInto(packet, 20 + header)
        // TCP's checksum also covers the addresses (the "pseudo-header").
        val sum = ByteArray(12 + header + payload.size)
        to.server.copyInto(sum, 0)
        to.source.copyInto(sum, 4)
        sum[9] = PROTOCOL.toByte()
        put16(sum, 10, header + payload.size)
        packet.copyInto(sum, 12, 20, packet.size)
        put16(packet, 36, Dns.checksum(sum, 0, sum.size))
        return packet
    }
}

/**
 * DNS over TCP, which apps fall back to when an answer is too big for one UDP packet: just enough TCP to take
 * lookups in and send their answers back on a short connection. Plain logic; LinkGuard does the asking.
 */
class TcpDns(private val isn: () -> Long = { Random.nextLong(0, 1L shl 32) }) {
    private class Connection(val first: TcpSegment, val start: Long, val isn: Long, val mss: Int) {
        var theirs = next(start, 1) // the next byte the app sends
        var ours = next(isn, 1) // the next byte Atlas sends
        var seen = 0L
        var waiting = 0 // lookups still being answered
        var finished = false // the app closed its side
        val buffer = ByteArrayOutputStream()
    }

    /** What to send back right away, and each lookup that arrived whole. */
    class Received(val send: List<ByteArray>, val lookups: List<ByteArray>)

    private val open = LinkedHashMap<String, Connection>()

    @Synchronized
    fun receive(s: TcpSegment, now: Long): Received {
        open.values.removeAll { now - it.seen > IDLE_MS }
        val key = s.key
        if (s.has(Tcp.RST)) {
            open.remove(key)
            return Received(emptyList(), emptyList())
        }
        if (s.has(Tcp.SYN) && !s.has(Tcp.ACK)) {
            val c = open[key]?.takeIf { it.start == s.seq } ?: Connection(s, s.seq, isn(), minOf(s.mss, MSS)).also {
                if (open.size >= MAX) open.remove(open.keys.first())
                open[key] = it
            }
            c.seen = now
            return Received(listOf(Tcp.segment(s, c.isn, c.theirs, Tcp.SYN or Tcp.ACK, mss = MSS)), emptyList())
        }
        val c = open[key]
            ?: return Received(if (s.has(Tcp.ACK)) listOf(Tcp.segment(s, s.ack, 0, Tcp.RST)) else emptyList(), emptyList())
        c.seen = now
        val lookups = mutableListOf<ByteArray>()
        if (s.payload.isNotEmpty() && s.seq == c.theirs) {
            c.buffer.write(s.payload)
            c.theirs = next(c.theirs, s.payload.size)
            var bytes = c.buffer.toByteArray()
            while (bytes.size >= 2 && bytes.size >= 2 + u16(bytes, 0)) {
                val size = u16(bytes, 0)
                lookups += bytes.copyOfRange(2, 2 + size)
                bytes = bytes.copyOfRange(2 + size, bytes.size)
            }
            c.buffer.reset()
            c.buffer.write(bytes)
            c.waiting += lookups.size
        }
        if (s.has(Tcp.FIN) && next(s.seq, s.payload.size) == c.theirs) {
            c.theirs = next(c.theirs, 1)
            c.finished = true
        }
        val send = mutableListOf<ByteArray>()
        if (s.payload.isNotEmpty() || s.has(Tcp.FIN)) send += Tcp.segment(c.first, c.ours, c.theirs, Tcp.ACK)
        if (c.finished && c.waiting <= 0) send += close(key, c)
        return Received(send, lookups)
    }

    /** The answer to a lookup on connection [key] (null: none came), split to fit what the app takes at once. */
    @Synchronized
    fun reply(key: String, dns: ByteArray?): List<ByteArray> {
        val c = open[key] ?: return emptyList()
        c.waiting--
        val out = mutableListOf<ByteArray>()
        if (dns != null) {
            val data = ByteArray(2 + dns.size).also { put16(it, 0, dns.size) }
            dns.copyInto(data, 2)
            var at = 0
            while (at < data.size) {
                val piece = data.copyOfRange(at, minOf(data.size, at + c.mss))
                out += Tcp.segment(c.first, c.ours, c.theirs, Tcp.ACK or Tcp.PSH, piece)
                c.ours = next(c.ours, piece.size)
                at += piece.size
            }
        }
        if (c.finished && c.waiting <= 0) out += close(key, c)
        return out
    }

    private fun close(key: String, c: Connection): ByteArray {
        open.remove(key)
        return Tcp.segment(c.first, c.ours, c.theirs, Tcp.FIN or Tcp.ACK)
    }

    private companion object {
        const val MSS = 4160 // LinkGuard's MTU less the headers
        const val MAX = 64 // open connections at once
        const val IDLE_MS = 30_000L

        fun next(seq: Long, by: Int) = (seq + by) and 0xFFFFFFFFL
    }
}
