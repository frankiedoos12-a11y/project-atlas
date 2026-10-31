package com.projectatlas.android

import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

/**
 * Is this message a scam? The Windows rules (atlas/scam.py), worded for a phone: the classic tricks are recognised
 * by their wording, and each link adds what VirusTotal says about it. No AI service; only the links leave the phone.
 */
const val SCAM = "Looks like a scam"
const val CAREFUL = "Be careful"
const val NOTHING = "Nothing obvious found"
const val SCAM_SCORE = 4
const val CAREFUL_SCORE = 2

class Rule(val title: String, val weight: Int, val why: String, vararg words: String) {
    val pattern = Regex("(?<![\\w])(?:" + words.joinToString("|") + ")(?![\\w])", RegexOption.IGNORE_CASE)
}

val RULES = listOf(
    Rule("Asks for remote access", 4, "Nobody legitimate asks you to install an app so they can control your phone " +
        "or computer. This is how tech-support and bank scams start.",
        """any ?desk""", """team ?viewer""", """quick ?(?:assist|support)""", """screen ?connect""", """ultra ?viewer""",
        """rust ?desk""", """remote (?:access|desktop|support|session)""",
        """(?:access|connect to|control) your (?:computer|pc|laptop|phone|device)""", """share your screen"""),
    Rule("Gift cards", 4, "Real companies and government offices never ask to be paid in gift cards.",
        """gift ?cards?""", """(?:google play|itunes|apple|steam|amazon|target|walmart|ebay|razer gold) cards?""",
        """scratch (?:off )?the back"""),
    Rule("Crypto or wire payment", 3, "Crypto, wire transfers and payment apps can't be reversed, which is why " +
        "scammers want them.", """bitcoin(?: atm)?""", """btc""", """usdt""", """crypto(?:currency)?""", """wallet address""",
        """wire (?:transfer|the money)""", """western union""", """money ?gram""", """zelle""", """cash ?app""", """venmo"""),
    Rule("Asks for codes or passwords", 3, "A one-time code or password lets someone into your account. No real " +
        "company asks you to read one out or send it.", """verification code""", """one[- ]time (?:code|password|pin)""",
        """otp""", """(?:send|give|tell|read) (?:me |us )?(?:the |that |your )?(?:\d-digit )?code""", """your password""",
        """social security number""", """ssn""", """card number""", """bank (?:login|password)""", """(?:atm|card) pin"""),
    Rule("Fake invoice or renewal", 2, "\"Your subscription renewed, call to cancel\" messages are a common way to " +
        "get you on the phone with a scammer.", """geek ?squad""", """norton""", """mcafee""", """auto[- ]?renew(?:al|ed)?""",
        """(?:subscription|membership|plan) (?:has been |was )?renewed""", """invoice""", """order (?:no|number|#)""",
        """(?:has|have) been charged""", """refund"""),
    Rule("Threats or authority", 2, "Scammers pose as the police, the tax office or a bank to scare you into " +
        "acting fast.", """arrest(?:ed)?""", """warrant""", """police""", """irs""", """social security administration""",
        """fbi""", """lawsuit""", """legal action""", """customs""", """court""", """deport(?:ed|ation)?"""),
    Rule("Virus scare", 2, "Messages and calls saying your phone or computer is infected are scams. Google, Apple, " +
        "Microsoft and Atlas don't phone or text you about it.",
        """(?:computer|pc|device|phone) (?:is|has been|was) (?:infected|hacked|compromised|locked)""",
        """virus(?:es)? (?:detected|found)""", """trojan""", """spyware""", """hackers? (?:have|has|got)"""),
    Rule("Fake security pop-up", 3, "Real security warnings never show a phone number, never lock your phone and " +
        "never tell you not to restart. Close the browser tab and don't call.",
        """(?:windows|microsoft|defender|apple|mac|google|android) (?:defender )?(?:security|firewall|virus) (?:alert|warning)""",
        """(?:pc|computer|device|phone|access|browser) (?:is|has been|was|will be) blocked""",
        """(?:do not|don't|dont) (?:restart|shut ?down|turn off|close this)""",
        """call (?:microsoft|windows|apple|google|technical|tech) (?:support|help ?desk)"""),
    Rule("Blackmail", 4, "\"I recorded you\" messages are mass-mailed blackmail. They have nothing; don't pay or reply.",
        """recorded you""", """your webcam""", """compromising (?:video|photos?)""", """intimate (?:video|photos?)"""),
    Rule("Prize or money for nothing", 2, "You can't win a contest you didn't enter, and real prizes don't cost a " +
        "fee.", """you(?:'ve| have)? won""", """winner""", """lottery""", """sweepstakes""", """claim your (?:prize|reward)""",
        """inheritance""", """unclaimed funds""", """free iphone"""),
    Rule("Unpaid toll or parcel", 2, "Texts about unpaid tolls or a parcel that needs a fee are a very common " +
        "phishing trick.", """unpaid toll""", """toll (?:balance|charges?|fees?)""",
        """(?:package|parcel|shipment) (?:could not|couldn't|cannot|can't|was not|wasn't) (?:be )?deliver(?:ed)?""",
        """redelivery""", """delivery fee""", """customs fee"""),
    Rule("Keep it secret", 2, "Being told not to tell your family or bank is a warning sign on its own.",
        """(?:do not|don't|dont) tell (?:anyone|your|the bank)""", """keep (?:this|it) (?:between us|secret|private)""",
        """(?:do not|don't|dont) hang up"""),
    Rule("Pressure to act now", 1, "Rushing you is how scammers stop you from thinking it through or asking " +
        "someone.", """urgent(?:ly)?""", """immediately""", """within (?:24|48) hours""", """act now""",
        """final (?:notice|warning)""", """last (?:chance|warning)""",
        """(?:account|card) (?:has been |is |will be )?(?:suspended|locked|closed|disabled|frozen)""", """expires? today"""),
    Rule("Easy money job", 1, "Jobs that pay well for simple tasks, especially over Telegram or WhatsApp, end with " +
        "you paying them.", """work from home""", """earn \$?\d+""", """per day""", """easy money""", """simple tasks?""",
        """telegram""", """whatsapp me"""),
)
private val PHONE = Regex("""(?<!\d)(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}(?!\d)""")
private val CALL = Regex("""(?<![\w])(?:call|phone|dial|ring|contact|text)(?![\w])""", RegexOption.IGNORE_CASE)
const val CALL_THIS_NUMBER = "Call this number"

data class Reason(val title: String, val why: String, val quote: String, val weight: Int)

private fun quote(text: String, match: MatchResult): String {
    val start = maxOf(0, match.range.first - 30)
    val end = minOf(text.length, match.range.last + 31)
    val snippet = text.substring(start, end).split(Regex("\\s+")).filter { it.isNotEmpty() }.joinToString(" ")
    return (if (start > 0) "..." else "") + snippet + if (end < text.length) "..." else ""
}

/** Tricks that turn into a scam the moment they come with a link to pay or claim through (not invoices: real shops
 * send order emails with links every day). */
private val PAY_BY_LINK = setOf("Unpaid toll or parcel", "Prize or money for nothing")
const val PAY_THROUGH_LINK = "Pay or claim through a link"

fun wordReasons(text: String): List<Reason> {
    var reasons = RULES.mapNotNull { rule -> rule.pattern.find(text)?.let { Reason(rule.title, rule.why, quote(text, it), rule.weight) } }
    val links = extractLinks(text)
    if (links.isNotEmpty() && reasons.any { it.title in PAY_BY_LINK }) {
        reasons = reasons + Reason(PAY_THROUGH_LINK, "Real delivery companies, toll offices and prize draws don't " +
            "send you a link to pay a fee or claim a prize. Go to their website or app yourself instead.", links.first(), 2)
    }
    val phone = PHONE.find(text)
    if (phone != null && CALL.containsMatchIn(text)) {
        return reasons + Reason(CALL_THIS_NUMBER, "Scam messages want you to call them, so they can talk you into " +
            "paying or installing something. If you're worried, call the company on a number you already know (the " +
            "back of your card, their real website).", quote(text, phone), 2)
    }
    return reasons
}

/** What a checked link adds: a dangerous one 4, a suspicious one 2. */
fun linkPoints(verdict: Verdict) = when (verdict) {
    Verdict.MALICIOUS -> 4
    Verdict.SUSPICIOUS -> 2
    else -> 0
}

fun scamVerdict(score: Int) = if (score >= SCAM_SCORE) SCAM else if (score >= CAREFUL_SCORE) CAREFUL else NOTHING

fun scamSummary(verdict: String) = when (verdict) {
    SCAM -> "This looks like a scam. Don't reply, call, click or pay. If it claims to be from a company you use, " +
        "contact them on a number or website you already know."
    CAREFUL -> "Some things here are often used in scams. Check with the company or person another way before you " +
        "do what it asks."
    else -> "Atlas found none of the usual scam signs. That doesn't prove it's safe: if it asks for money, codes or " +
        "remote access, check another way first."
}

fun scamColor(verdict: String) = when (verdict) {
    SCAM -> Verdict.MALICIOUS.color
    CAREFUL -> Verdict.SUSPICIOUS.color
    else -> Verdict.CLEAN.color
}

// --- Has this password been leaked? (atlas/pwned.py) ---------------------------------------------------------

/**
 * Checked against Have I Been Pwned's Pwned Passwords list. The password never leaves the phone: only the first 5
 * characters of its SHA-1 hash are sent, and the answer (hundreds of hashes, padded with fakes) is searched here.
 */
object Pwned {
    const val RANGE_URL = "https://api.pwnedpasswords.com/range/"

    fun sha1(password: String): String =
        MessageDigest.getInstance("SHA-1").digest(password.toByteArray()).joinToString("") { "%02X".format(it) }

    /** How many times the password appears in known leaks (0: not found). */
    fun timesLeaked(password: String, get: (String) -> String = ::rangeGet): Int {
        val digest = sha1(password)
        val rest = digest.substring(5)
        for (line in get(RANGE_URL + digest.take(5)).lineSequence()) {
            val (suffix, count) = line.trim().split(':').let { it[0] to it.getOrNull(1) }
            if (suffix.equals(rest, ignoreCase = true)) return count?.trim()?.toIntOrNull() ?: 0
        }
        return 0
    }

    fun verdict(count: Int): String = if (count == 0) {
        "Not found in any known leak. That doesn't make it strong: use a long, unique password for each account, " +
            "ideally from a password manager."
    } else {
        "This password has appeared in data leaks ${"%,d".format(count)} time${if (count == 1) "" else "s"}. Criminals " +
            "try leaked passwords first, so stop using it everywhere you do, starting with email and banking. Turn on " +
            "two-step sign-in too."
    }

    private fun rangeGet(address: String): String {
        val connection = URL(address).openConnection() as HttpURLConnection
        try {
            connection.connectTimeout = 20_000
            connection.readTimeout = 20_000
            connection.setRequestProperty("Add-Padding", "true")
            connection.setRequestProperty("User-Agent", "Project-Atlas")
            if (connection.responseCode !in 200..299) throw java.io.IOException("the service answered ${connection.responseCode}")
            return connection.inputStream.bufferedReader().use { it.readText() }
        } finally {
            connection.disconnect()
        }
    }
}

/** Links to known stalkerware or monitoring sites (from the threat data, so no key needed). */
fun siteReasons(links: List<String>, site: (String) -> Family?): List<Reason> = links.mapNotNull { link ->
    site(hostOf(link))?.let { f ->
        if (f.stalkerware) {
            Reason("Link to stalkerware", "This link goes to ${f.name}, an app made to secretly watch someone's " +
                "phone. Don't install anything from it.", link, 4)
        } else {
            Reason("Link to a monitoring app", "This link goes to ${f.name}, an app that lets someone else see a " +
                "phone's activity. Only install it on purpose.", link, 2)
        }
    }
}.distinctBy { it.title + it.quote }

/** The text of a message notification: the newest message of a conversation, or the whole text. */
fun messageText(messages: List<String>, bigText: String?, text: String?): String? =
    messages.lastOrNull { it.isNotBlank() } ?: bigText?.takeIf { it.isNotBlank() } ?: text?.takeIf { it.isNotBlank() }

/** "just now", "5 minutes ago", "3 hours ago", "2 days ago". */
fun ago(ms: Long): String {
    val minutes = ms / 60_000
    return when {
        minutes < 1 -> "just now"
        minutes < 60 -> "$minutes minute${if (minutes == 1L) "" else "s"} ago"
        minutes < 48 * 60 -> "${minutes / 60} hour${if (minutes / 60 == 1L) "" else "s"} ago"
        else -> "${minutes / 1440} days ago"
    }
}
