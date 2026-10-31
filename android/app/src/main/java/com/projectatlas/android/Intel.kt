package com.projectatlas.android

/**
 * Threat data that works without a VirusTotal key: known stalkerware and monitoring apps, by fingerprint, signing
 * certificate and package name, and their websites, plus (when the weekly build has an abuse.ch key) MalwareBazaar's
 * newest Android malware by fingerprint. Built by tools/build_intel.py; the app ships a copy and fetches a newer one
 * once a week.
 */
/** kind: "stalkerware", "watchware" (a monitoring app) or "malware" (other Android malware, from MalwareBazaar). */
data class Family(val name: String, val kind: String) {
    val stalkerware get() = kind == "stalkerware"
    val malware get() = kind == "malware"
    val what get() = if (malware) "Android malware" else if (stalkerware) "stalkerware" else "monitoring app"
}

enum class Match(val strong: Boolean, val how: String) {
    FILE(true, "the app file itself is a known sample"),
    CERTIFICATE(true, "it's signed with the same certificate as known samples"),
    PACKAGE(false, "its package name matches"),
}

data class IntelHit(val family: Family, val match: Match)

class Intel(
    val version: Long,
    val sources: List<String>, // "Stalkerware indicators by Echap, CC BY 4.0, https://..."
    private val families: List<Family>,
    private val packages: Map<String, Int>,
    private val certificates: Map<String, Int>,
    private val hashes: Map<String, Int>,
    private val domains: Map<String, Int>,
) {
    val size get() = families.size

    /** The strongest match: the file, then the signer, then the name. */
    fun app(packageName: String?, signers: List<String> = emptyList(), sha256: String? = null): IntelHit? {
        sha256?.let { h -> hashes[h.lowercase()]?.let { return IntelHit(families[it], Match.FILE) } }
        for (s in signers) certificates[s.uppercase()]?.let { return IntelHit(families[it], Match.CERTIFICATE) }
        packageName?.let { p -> packages[p]?.let { return IntelHit(families[it], Match.PACKAGE) } }
        return null
    }

    fun file(sha256: String): Family? = hashes[sha256.lowercase()]?.let { families[it] }

    /** A listed website, or one of its subdomains. */
    fun site(host: String): Family? {
        var h = host.lowercase().trimEnd('.')
        while (h.contains('.')) {
            domains[h]?.let { return families[it] }
            h = h.substringAfter('.')
        }
        return null
    }

    companion object {
        const val FORMAT = 1

        /** Null when the text isn't threat data in a format this app reads (a failed or tampered download). */
        fun parse(text: String): Intel? {
            val lines = text.lineSequence().iterator()
            if (!lines.hasNext() || lines.next().trim() != "# atlas-intel $FORMAT") return null
            var version = 0L
            val sources = mutableListOf<String>()
            val families = mutableListOf<Family>()
            val maps = mapOf('P' to HashMap<String, Int>(), 'C' to HashMap(), 'H' to HashMap(), 'D' to HashMap())
            for (line in lines) {
                if (line.startsWith("# version ")) version = line.removePrefix("# version ").trim().toLongOrNull() ?: 0
                if (line.startsWith("# source: ")) sources += line.removePrefix("# source: ").trim()
                if (line.length < 3 || line[1] != '\t') continue
                val parts = line.split('\t')
                if (line[0] == 'F' && parts.size == 4) {
                    if (parts[1].toIntOrNull() != families.size) return null
                    families += Family(parts[2], parts[3])
                } else if (parts.size == 3) {
                    val id = parts[2].toIntOrNull()?.takeIf { it in families.indices } ?: return null
                    maps[line[0]]?.put(parts[1], id)
                }
            }
            if (families.isEmpty()) return null
            return Intel(version, sources, families, maps.getValue('P'), maps.getValue('C'), maps.getValue('H'), maps.getValue('D'))
        }
    }
}

/** What a known stalkerware or monitoring app adds to an app's verdict. */
fun intelReason(hit: IntelHit): Pair<Verdict, String> {
    val f = hit.family
    return if (f.malware) {
        Verdict.MALICIOUS to "Known Android malware: ${f.name} (${hit.match.how}). Uninstall it from its App settings " +
            "(if it's a device administrator, switch that off first), then change the passwords you used on this phone."
    } else if (f.stalkerware) {
        (if (hit.match.strong) Verdict.MALICIOUS else Verdict.SUSPICIOUS) to "Known stalkerware: ${f.name} " +
            "(${hit.match.how}). It can secretly share your messages, location and photos with whoever installed " +
            "it. Before removing it, think about your safety: whoever installed it will notice it stopped."
    } else {
        (if (hit.match.strong) Verdict.SUSPICIOUS else Verdict.UNKNOWN) to "A monitoring app: ${f.name} " +
            "(${hit.match.how}). It lets someone else see this phone's activity. Fine if you set it up for your " +
            "child; if you didn't, someone may be watching."
    }
}
