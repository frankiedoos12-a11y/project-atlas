"""Is this message a scam? Paste an email, text or chat message and Atlas explains what looks wrong.

Rules only, no AI service: the classic tricks (pressure, gift cards and crypto, "call this number",
remote access, fake invoices, threats, prizes, asking for codes) are recognised by their wording,
and every link in the message is checked like the link checker does (VirusTotal plus the offline
look-alike checks). Nothing is sent anywhere except the links, which go to VirusTotal.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from atlas.links import LinkCheck, check_link
from atlas.scanner import Verdict

SCAM, CAREFUL, NOTHING = "Looks like a scam", "Be careful", "Nothing obvious found"
SCAM_SCORE, CAREFUL_SCORE = 4, 2
MAX_LINKS = 5  # each link costs up to two VirusTotal lookups


@dataclass(frozen=True)
class Rule:
    title: str
    weight: int
    why: str
    pattern: re.Pattern


def _rule(title: str, weight: int, why: str, *words: str) -> Rule:
    return Rule(title, weight, why, re.compile(r"(?<![\w])(?:" + "|".join(words) + r")(?![\w])", re.I))


RULES = [
    _rule("Asks for remote access", 4, "Nobody legitimate asks you to install a program so they can control your "
          "PC. This is how tech-support scams start.",
          r"any ?desk", r"team ?viewer", r"quick ?assist", r"screen ?connect", r"ultra ?viewer", r"rust ?desk",
          r"remote (?:access|desktop|support|session)", r"(?:access|connect to|control) your (?:computer|pc|laptop)"),
    _rule("Gift cards", 4, "Real companies and government offices never ask to be paid in gift cards.",
          r"gift ?cards?", r"(?:google play|itunes|apple|steam|amazon|target|walmart|ebay|razer gold) cards?",
          r"scratch (?:off )?the back"),
    _rule("Crypto or wire payment", 3, "Crypto, wire transfers and payment apps can't be reversed, which is why "
          "scammers want them.", r"bitcoin(?: atm)?", r"btc", r"usdt", r"crypto(?:currency)?", r"wallet address",
          r"wire (?:transfer|the money)", r"western union", r"money ?gram", r"zelle", r"cash ?app", r"venmo"),
    _rule("Asks for codes or passwords", 3, "A one-time code or password lets someone into your account. No real "
          "company asks you to read one out or send it.", r"verification code", r"one[- ]time (?:code|password|pin)",
          r"otp", r"(?:send|give|tell|read) (?:me |us )?(?:the |that |your )?(?:\d-digit )?code", r"your password",
          r"social security number", r"ssn", r"card number", r"bank (?:login|password)", r"(?:atm|card) pin"),
    _rule("Fake invoice or renewal", 2, "\"Your subscription renewed, call to cancel\" messages are a common way to "
          "get you on the phone with a scammer.", r"geek ?squad", r"norton", r"mcafee", r"auto[- ]?renew(?:al|ed)?",
          r"(?:subscription|membership|plan) (?:has been |was )?renewed", r"invoice", r"order (?:no|number|#)",
          r"(?:has|have) been charged", r"refund"),
    _rule("Threats or authority", 2, "Scammers pose as the police, the tax office or a bank to scare you into "
          "acting fast.", r"arrest(?:ed)?", r"warrant", r"police", r"irs", r"social security administration", r"fbi",
          r"lawsuit", r"legal action", r"customs", r"court", r"deport(?:ed|ation)?"),
    _rule("Virus scare", 2, "Pop-ups and calls saying your PC is infected are scams. Windows and Atlas don't phone "
          "you.", r"(?:computer|pc|device|phone) (?:is|has been|was) (?:infected|hacked|compromised|locked)",
          r"virus(?:es)? (?:detected|found)", r"trojan", r"spyware", r"hackers? (?:have|has|got)"),
    _rule("Fake security pop-up", 3, "Real Windows and Defender warnings never show a phone number, never lock "
          "your PC and never tell you not to restart. Close the browser (Ctrl+Shift+Esc > End task if it won't "
          "close) and don't call.",
          r"(?:windows|microsoft|defender|apple|mac) (?:defender )?(?:security|firewall|virus) (?:alert|warning)",
          r"(?:pc|computer|device|access|browser) (?:is|has been|was|will be) blocked",
          r"(?:do not|don't|dont) (?:restart|shut ?down|turn off|close this)",
          r"call (?:microsoft|windows|apple|technical|tech) (?:support|help ?desk)"),
    _rule("Blackmail", 4, "\"I recorded you\" emails are mass-mailed blackmail. They have nothing; don't pay or reply.",
          r"recorded you", r"your webcam", r"compromising (?:video|photos?)", r"intimate (?:video|photos?)"),
    _rule("Prize or money for nothing", 2, "You can't win a contest you didn't enter, and real prizes don't cost a "
          "fee.", r"you(?:'ve| have)? won", r"winner", r"lottery", r"sweepstakes", r"claim your (?:prize|reward)",
          r"inheritance", r"unclaimed funds", r"free iphone"),
    _rule("Unpaid toll or parcel", 2, "Texts about unpaid tolls or a parcel that needs a fee are a very common "
          "phishing trick.", r"unpaid toll", r"toll (?:balance|charges?|fees?)", r"(?:package|parcel|shipment) "
          r"(?:could not|couldn't|cannot|can't|was not|wasn't) (?:be )?deliver(?:ed)?", r"redelivery",
          r"delivery fee", r"customs fee"),
    _rule("Keep it secret", 2, "Being told not to tell your family or bank is a warning sign on its own.",
          r"(?:do not|don't|dont) tell (?:anyone|your|the bank)", r"keep (?:this|it) (?:between us|secret|private)",
          r"(?:do not|don't|dont) hang up"),
    _rule("Pressure to act now", 1, "Rushing you is how scammers stop you from thinking it through or asking "
          "someone.", r"urgent(?:ly)?", r"immediately", r"within (?:24|48) hours", r"act now", r"final (?:notice|warning)",
          r"last (?:chance|warning)", r"(?:account|card) (?:has been |is |will be )?(?:suspended|locked|closed|"
          r"disabled|frozen)", r"expires? today"),
    _rule("Easy money job", 1, "Jobs that pay well for simple tasks, especially over Telegram or WhatsApp, end with "
          "you paying them.", r"work from home", r"earn \$?\d+", r"per day", r"easy money", r"simple tasks?",
          r"telegram", r"whatsapp me"),
]
PHONE = re.compile(r"(?<!\d)(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}(?!\d)")
CALL = re.compile(r"(?<![\w])(?:call|phone|dial|ring|contact)(?![\w])", re.I)
URL = re.compile(r"(?:https?://|www\.)[^\s<>\"')\]]+|(?<![@\w.])(?:[a-z0-9-]+\.)+(?:com|net|org|info|xyz|top|"
                 r"live|online|site|shop|click|app|io|co|me|us|cc|biz|link)(?:/[^\s<>\"')\]]*)?", re.I)


@dataclass
class Reason:
    title: str
    why: str
    quote: str
    points: int | None = None  # its own weight (email and screenshot checks); None = the rule's weight


@dataclass
class ScamCheck:
    verdict: str = NOTHING
    score: int = 0
    reasons: list[Reason] = field(default_factory=list)
    links: list[LinkCheck] = field(default_factory=list)
    skipped_links: int = 0
    about: list[tuple[str, str]] = field(default_factory=list)  # e.g. ("From", "..."), shown above the reasons


def links_in(text: str) -> list[str]:
    found: list[str] = []
    for m in URL.finditer(text):
        url = m.group(0).rstrip(".,;:!?")
        if url.lower() not in {u.lower() for u in found}:
            found.append(url)
    return found


def _quote(text: str, match: re.Match) -> str:
    start, end = max(0, match.start() - 30), min(len(text), match.end() + 30)
    snippet = " ".join(text[start:end].split())
    return ("..." if start else "") + snippet + ("..." if end < len(text) else "")


def word_reasons(text: str) -> list[Reason]:
    reasons = []
    for rule in RULES:
        m = rule.pattern.search(text)
        if m:
            reasons.append(Reason(rule.title, rule.why, _quote(text, m)))
    phone = PHONE.search(text)
    if phone and CALL.search(text):
        reasons.append(Reason("Call this number", "Scam messages want you to call them, so they can talk you into "
                              "paying or installing something. If you're worried, call the company on a number you "
                              "already know (the back of your card, their real website).", _quote(text, phone)))
    return reasons


def weight(reason: Reason) -> int:
    if reason.points is not None:
        return reason.points
    return next((r.weight for r in RULES if r.title == reason.title), 2)


def check_message(text: str, scanner=None, links: list[str] | None = None, extra: list[Reason] = ()) -> ScamCheck:
    """`links` replaces the links found in the text (an email's real link targets); `extra` adds reasons found
    elsewhere (the sender, sign-in checks, attachments)."""
    result = ScamCheck(reasons=list(extra) + word_reasons(text))
    result.score = sum(weight(r) for r in result.reasons)
    urls = links_in(text) if links is None else links
    result.skipped_links = max(0, len(urls) - MAX_LINKS)
    for url in urls[:MAX_LINKS]:
        link = check_link(scanner, url)
        result.links.append(link)
        if link.verdict is Verdict.MALICIOUS:
            result.score += 4
            result.reasons.append(Reason("Dangerous link", "VirusTotal or Atlas's own checks flag this link as "
                                         "malicious. Don't open it.", link.url))
        elif link.verdict is Verdict.SUSPICIOUS:
            result.score += 2
            result.reasons.append(Reason("Suspicious link", link.reasons[0] if link.reasons else
                                         "This link looks suspicious.", link.url))
    result.verdict = SCAM if result.score >= SCAM_SCORE else CAREFUL if result.score >= CAREFUL_SCORE else NOTHING
    return result


def summary(result: ScamCheck) -> str:
    if result.verdict == SCAM:
        return ("This looks like a scam. Don't reply, call, click or pay. If it claims to be from a company you use, "
                "contact them on a number or website you already know.")
    if result.verdict == CAREFUL:
        return ("Some things here are often used in scams. Check with the company or person another way before "
                "you do what it asks.")
    return ("Atlas found none of the usual scam signs. That doesn't prove it's safe: if it asks for money, codes or "
            "remote access, check another way first.")
