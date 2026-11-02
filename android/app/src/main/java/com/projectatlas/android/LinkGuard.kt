package com.projectatlas.android

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import java.io.DataInputStream
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import kotlin.concurrent.thread

/**
 * Link protection: a VPN that carries only site-name lookups (DNS), never the browsing itself. A lookup for a site
 * the threat data lists as malware or stalkerware gets "no such site", so it can't open in any app or browser;
 * every other lookup goes on to the network's own DNS (or Quad9, if you choose it) unchanged. Nothing is saved
 * except the last few blocked site names, shown on the Protection screen.
 */
class LinkGuard : VpnService() {
    private var tun: ParcelFileDescriptor? = null
    private var pool: ExecutorService? = null
    private val tcp = TcpDns()
    private val unsaved = mutableListOf<String>() // blocked sites not yet written, newest first
    private var unsavedCount = 0
    private val told = HashMap<String, Long>() // when each site's last notification went out
    private val saver = Handler(Looper.getMainLooper())

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == STOP) {
            close()
            stopSelf()
            return START_NOT_STICKY
        }
        if (tun == null && !open()) {
            prefs(this).edit().putBoolean("on", false).apply()
            stopSelf()
            return START_NOT_STICKY
        }
        return START_STICKY
    }

    private fun open(): Boolean {
        val builder = Builder()
            .setSession("Link protection")
            .addAddress(ADDRESS, 32)
            .addDnsServer(DNS)
            .addRoute(DNS, 32) // only lookups come to Atlas; everything else goes straight out as before
            .setMtu(MTU)
            .setBlocking(true)
            .setConfigureIntent(PendingIntent.getActivity(this, 0, Intent(this, ProtectionActivity::class.java)
                .putExtra(SHOW, true), PendingIntent.FLAG_IMMUTABLE))
        try {
            builder.addDisallowedApplication(packageName) // Atlas's own lookups, and forwarding, skip the VPN
        } catch (e: PackageManager.NameNotFoundException) {
        }
        if (Build.VERSION.SDK_INT >= 29) builder.setMetered(false) // metered only when the real network is
        val fd = try {
            builder.establish()
        } catch (e: Exception) {
            null
        } ?: return false
        tun = fd
        pool = Executors.newFixedThreadPool(4)
        running = true
        Sensors.start(this)
        thread(name = "atlas-links", isDaemon = true) { serve(fd) }
        return true
    }

    private fun serve(fd: ParcelFileDescriptor) {
        val input = FileInputStream(fd.fileDescriptor)
        val output = FileOutputStream(fd.fileDescriptor)
        val buffer = ByteArray(MTU)
        while (true) {
            val n = try {
                input.read(buffer)
            } catch (e: IOException) {
                break // closed: switched off
            }
            if (n < 0) break
            val query = Dns.parse(buffer, n)
            if (query == null) {
                Tcp.parse(buffer, n)?.let { overTcp(output, it) }
                continue
            }
            val bad = danger(query.name)
            if (bad != null) {
                send(output, Dns.answer(query, Dns.blocked(query)))
                blocked(query.name, bad)
                continue
            }
            try {
                pool?.execute { forward(query)?.let { send(output, Dns.answer(query, it)) } }
            } catch (e: Exception) {
                break // the pool shut down: switched off
            }
        }
    }

    /** The family behind a site the threat data lists, unless it's one you allowed. */
    private fun danger(host: String): Family? {
        val intel = try {
            IntelStore.get(this)
        } catch (e: Exception) {
            null
        }
        return intel?.let { blockFor(host, allowed(this), it::site) }
    }

    /** A lookup asked again over TCP, because its answer was too big for one UDP packet. */
    private fun overTcp(output: FileOutputStream, segment: TcpSegment) {
        val got = tcp.receive(segment, System.currentTimeMillis())
        got.send.forEach { send(output, it) }
        for (dns in got.lookups) {
            val name = Dns.question(dns)?.first
            val bad = name?.let { danger(it) }
            if (name == null || bad != null) {
                tcp.reply(segment.key, if (bad != null) Dns.blocked(dns) else null).forEach { send(output, it) }
                if (name != null && bad != null) blocked(name, bad)
                continue
            }
            try {
                pool?.execute { tcp.reply(segment.key, forwardTcp(dns)).forEach { send(output, it) } }
            } catch (e: Exception) {
            }
        }
    }

    private fun send(output: FileOutputStream, packet: ByteArray) {
        synchronized(output) {
            try {
                output.write(packet)
            } catch (e: IOException) {
            }
        }
    }

    private fun forward(query: DnsQuery): ByteArray? {
        for (server in servers()) {
            try {
                DatagramSocket().use { socket ->
                    protect(socket)
                    socket.soTimeout = 4_000
                    socket.send(DatagramPacket(query.dns, query.dns.size, server, 53))
                    val answer = ByteArray(4096)
                    val packet = DatagramPacket(answer, answer.size)
                    socket.receive(packet)
                    if (packet.length >= 12 && answer[0] == query.dns[0] && answer[1] == query.dns[1]) {
                        return answer.copyOf(packet.length)
                    }
                }
            } catch (e: IOException) {
                // try the next server; the app asks again if none answer
            }
        }
        return null
    }

    /** The same over TCP, for an answer too big for one UDP packet. */
    private fun forwardTcp(dns: ByteArray): ByteArray? {
        for (server in servers()) {
            try {
                Socket().use { socket ->
                    protect(socket)
                    socket.connect(InetSocketAddress(server, 53), 4_000)
                    socket.soTimeout = 4_000
                    socket.getOutputStream().apply {
                        write(byteArrayOf((dns.size shr 8).toByte(), dns.size.toByte()) + dns)
                        flush()
                    }
                    val input = DataInputStream(socket.getInputStream())
                    val answer = ByteArray(input.readUnsignedShort()).also { input.readFully(it) }
                    if (answer.size >= 12 && answer[0] == dns[0] && answer[1] == dns[1]) return answer
                }
            } catch (e: IOException) {
                // try the next server
            }
        }
        return null
    }

    /** The real network's DNS servers (Atlas itself is outside the VPN, so its network is the real one). */
    private fun servers(): List<InetAddress> {
        if (quad9(this)) return QUAD9
        val manager = getSystemService(ConnectivityManager::class.java)
        val network = manager.activeNetwork?.takeIf {
            manager.getNetworkCapabilities(it)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == false
        }
        val own = network?.let { manager.getLinkProperties(it)?.dnsServers }.orEmpty()
            .filter { it.hostAddress != DNS }
        return own.ifEmpty { QUAD9 }
    }

    private fun blocked(host: String, family: Family) {
        val now = System.currentTimeMillis()
        val tell: Boolean
        synchronized(unsaved) {
            unsaved.add(0, "$now\t$host\t${family.name}\t${family.kind}")
            if (unsaved.size > KEEP) unsaved.removeAt(unsaved.size - 1)
            if (++unsavedCount == 1) saver.postDelayed(::save, SAVE_MS)
            tell = now - (told[host] ?: 0) > HOUR_MS // once an hour per site, however often it's asked
            if (tell) {
                if (told.size >= 500) told.clear()
                told[host] = now
            }
        }
        if (tell) {
            Watch.notify(this, "link:$host", if (family.spyware) "Blocked a spyware site" else "Blocked a dangerous site",
                "Atlas stopped an app from opening $host, a site that ${family.name} (${family.what}) uses. Tap to " +
                    "see blocked sites or allow one you trust.",
                Intent(this, ProtectionActivity::class.java).putExtra(SHOW, true))
        }
    }

    /** Writes the sites blocked since the last save: at most every few seconds, however fast an app keeps asking. */
    private fun save() {
        val lines: List<String>
        val n: Int
        synchronized(unsaved) {
            lines = unsaved.toList()
            n = unsavedCount
            unsaved.clear()
            unsavedCount = 0
        }
        if (n == 0) return
        val prefs = prefs(this)
        val recent = (lines + prefs.getString("recent", "").orEmpty().lines().filter { it.isNotBlank() }).take(KEEP)
        prefs.edit().putString("recent", recent.joinToString("\n")).putInt("count", prefs.getInt("count", 0) + n).apply()
    }

    private fun close() {
        saver.removeCallbacksAndMessages(null)
        save()
        running = false
        pool?.shutdownNow()
        pool = null
        try {
            tun?.close()
        } catch (e: IOException) {
        }
        tun = null
    }

    override fun onRevoke() {
        // Another VPN took over, or the person switched it off in Android's settings.
        prefs(this).edit().putBoolean("on", false).apply()
        close()
        super.onRevoke()
    }

    override fun onDestroy() {
        close()
        super.onDestroy()
    }

    class Blocked(val time: Long, val host: String, val family: Family)

    companion object {
        const val SHOW = "links" // open the Protection screen with link protection's choices
        private const val STOP = "com.projectatlas.android.STOP_LINKS"
        private const val ADDRESS = "10.111.222.2"
        private const val DNS = "10.111.222.1"
        private const val MTU = 4200 // a lookup's answer can be up to 4096 bytes
        private const val KEEP = 30
        private const val HOUR_MS = 60 * 60_000L
        private const val SAVE_MS = 5_000L
        private val QUAD9 = listOf("9.9.9.9", "149.112.112.112").map { InetAddress.getByName(it) }

        @Volatile var running = false
            private set

        private fun prefs(context: Context) = context.getSharedPreferences("links", Context.MODE_PRIVATE)

        fun enabled(context: Context) = prefs(context).getBoolean("on", false)

        /** After VpnService.prepare said yes. */
        fun start(context: Context) {
            prefs(context).edit().putBoolean("on", true).apply()
            context.startService(Intent(context, LinkGuard::class.java))
        }

        fun stop(context: Context) {
            prefs(context).edit().putBoolean("on", false).apply()
            if (running) context.startService(Intent(context, LinkGuard::class.java).setAction(STOP))
        }

        /** After a restart, if it was on and Android still allows it. */
        fun resume(context: Context) {
            if (enabled(context) && prepare(context) == null) {
                try {
                    context.startService(Intent(context, LinkGuard::class.java))
                } catch (e: Exception) {
                }
            }
        }

        fun count(context: Context) = prefs(context).getInt("count", 0)

        fun recent(context: Context): List<Blocked> = prefs(context).getString("recent", "").orEmpty().lines()
            .mapNotNull { line ->
                val p = line.split('\t')
                if (p.size == 4) Blocked(p[0].toLongOrNull() ?: 0, p[1], Family(p[2], p[3])) else null
            }

        fun allowed(context: Context): Set<String> = prefs(context).getStringSet("allowed", null).orEmpty()

        fun allow(context: Context, host: String, yes: Boolean) {
            val now = allowed(context).toMutableSet().apply { if (yes) add(host) else remove(host) }
            prefs(context).edit().putStringSet("allowed", now).apply()
        }

        fun quad9(context: Context) = prefs(context).getBoolean("quad9", false)

        fun setQuad9(context: Context, on: Boolean) = prefs(context).edit().putBoolean("quad9", on).apply()

        /** Private DNS set to a provider's name: Android sends lookups there itself, past Atlas. */
        fun privateDnsBypasses(context: Context): Boolean {
            if (Build.VERSION.SDK_INT < 28) return false
            val manager = context.getSystemService(ConnectivityManager::class.java)
            return manager.activeNetwork?.let { manager.getLinkProperties(it)?.privateDnsServerName } != null
        }
    }
}
