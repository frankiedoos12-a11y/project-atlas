package com.projectatlas.android

import org.json.JSONObject
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.util.Base64

class RateLimited : IOException("VirusTotal's limit for this key was reached")
class BadKey : IOException("VirusTotal didn't accept the API key")

/** VirusTotal's API, with the person's own key. `get` is swapped in tests: (address, key) -> (status, body). */
class VirusTotal(private val key: String, private val get: (String, String) -> Pair<Int, String> = ::httpGet) {
    fun file(sha256: String) = report("files/${sha256.lowercase()}")
    fun url(url: String) = report("urls/${urlId(url)}")
    fun domain(domain: String) = report("domains/${domain.lowercase()}")

    /** How many lookups a minute this key may make, from VirusTotal's own record of it (null: it didn't say). */
    fun lookupsPerMinute(): Int? {
        val (status, body) = get("$API/users/$key", key)
        return when (status) {
            200 -> minuteLimit(body)
            401, 403 -> throw BadKey()
            else -> null
        }
    }

    private fun report(path: String): VtReport {
        val (status, body) = get("$API/$path", key)
        return when (status) {
            200 -> parseReport(body)
            404 -> VtReport(found = false)
            401, 403 -> throw BadKey()
            429 -> throw RateLimited()
            else -> throw IOException("VirusTotal answered $status")
        }
    }

    companion object {
        const val API = "https://www.virustotal.com/api/v3"
        const val GUI = "https://www.virustotal.com/gui"
        const val LOOKUPS_PER_MINUTE = 4 // a free key's limit (and 500 a day)
        /** A file every key can look up: checking it tells whether the key works. */
        const val TEST_HASH = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f" // EICAR test file
    }
}

/** The key's hourly (or else daily) allowance as lookups a minute; a company key's group allowance counts too. */
fun minuteLimit(body: String): Int? {
    val quotas = try {
        JSONObject(body).getJSONObject("data").getJSONObject("attributes").getJSONObject("quotas")
    } catch (e: Exception) {
        return null
    }
    fun allowed(name: String): Long {
        val quota = quotas.optJSONObject(name) ?: return 0
        return maxOf(quota.optJSONObject("user")?.optLong("allowed") ?: 0, quota.optJSONObject("group")?.optLong("allowed") ?: 0)
    }
    val perMinute = allowed("api_requests_hourly").takeIf { it > 0 }?.div(60)
        ?: allowed("api_requests_daily").takeIf { it > 0 }?.div(24 * 60) ?: return null
    return perMinute.toInt().coerceIn(1, MAX_PER_MINUTE)
}

/** Atlas's own ceiling, whatever the key allows: one phone, one lookup at a time, stays light. */
const val MAX_PER_MINUTE = 600

/** A lookup that, if VirusTotal says to slow down, waits a minute and tries once more. */
fun <T> patiently(sleep: (Long) -> Unit = { Thread.sleep(it) }, lookup: () -> T): T = try {
    lookup()
} catch (e: RateLimited) {
    sleep(60_000)
    lookup()
}

fun parseReport(body: String): VtReport {
    val attributes = JSONObject(body).getJSONObject("data").getJSONObject("attributes")
    val stats = attributes.optJSONObject("last_analysis_stats") ?: JSONObject()
    val total = stats.keys().asSequence().sumOf { stats.optInt(it) }
    val label = attributes.optJSONObject("popular_threat_classification")?.optString("suggested_threat_label", "") ?: ""
    return VtReport(true, stats.optInt("malicious"), stats.optInt("suspicious"), total, label)
}

/** VirusTotal's name for a link: unpadded URL-safe base64. */
fun urlId(url: String): String = Base64.getUrlEncoder().withoutPadding().encodeToString(url.toByteArray())

/** VirusTotal's web page about a file, a site or a link. Opening it needs no key. */
fun guiLink(kind: String, target: String): String = when (kind) {
    "file" -> "${VirusTotal.GUI}/file/$target"
    "domain" -> "${VirusTotal.GUI}/domain/$target"
    else -> "${VirusTotal.GUI}/url/${urlId(target)}"
}

fun httpGet(address: String, key: String): Pair<Int, String> {
    val connection = URL(address).openConnection() as HttpURLConnection
    try {
        connection.connectTimeout = 20_000
        connection.readTimeout = 20_000
        connection.setRequestProperty("x-apikey", key)
        connection.setRequestProperty("Accept", "application/json")
        val status = connection.responseCode
        val stream = if (status in 200..299) connection.inputStream else connection.errorStream
        return status to (stream?.bufferedReader()?.use { it.readText() } ?: "")
    } finally {
        connection.disconnect()
    }
}
