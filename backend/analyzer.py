"""
EchoShield AI - deterministic, rule-based message analyzer (v3).

This module is the source of truth for the risk score and risk level. The
optional Bedrock layer only *explains* these findings; it never changes them.

Focus: Indian banking / UPI / OTP scams, delivery and job scams, malicious
apps, and suspicious links.

Design notes
- Every finding is an "indicator" with a name, the evidence that triggered it
  and a severity: high = strong evidence, medium = supporting signal,
  low = weak signal that is common in genuine messages too.
- Weak signals alone can never produce a HIGH score: without at least one
  high-severity indicator the score is capped just below HIGH.
- A message with no indicators is "not flagged", never "proven safe".
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

DISCLAIMER = (
    "This is an automated risk assessment, not proof of fraud or of safety, and it can be wrong. "
    "When in doubt, contact the organisation using a number or app you already trust."
)

# ---------------------------------------------------------------------------
# 1. Phrase rules
# ---------------------------------------------------------------------------
# severity: strength when two or more phrases match. A single match is
# downgraded one step (high -> medium, medium -> low) because one common
# word is weak evidence.

PHRASE_RULES = [
    {
        "key": "urgency", "name": "Urgency language", "severity": "medium",
        "points": 10, "cap": 25, "pressure": True,
        "phrases": [
            "urgent", "urgently", "immediately", "right now", "act now",
            "act fast", "asap", "last warning", "final notice", "final warning",
            "limited time", "expires today", "expires soon", "expiring today",
            "within 24 hours", "within 2 hours", "within 1 hour",
            "today only", "before midnight", "do not ignore", "don't ignore",
            "failure to comply", "last chance", "respond immediately",
            "turant", "jaldi", "aaj hi",  # Hinglish
        ],
    },
    {
        "key": "threat", "name": "Account-block or penalty threat", "severity": "medium",
        "points": 12, "cap": 30, "pressure": True,
        "phrases": [
            "account will be blocked", "account will be suspended",
            "account will be closed", "account has been blocked",
            "account has been suspended", "account is blocked",
            "your card has been blocked", "card will be blocked",
            "kyc will expire", "kyc has expired", "kyc is pending",
            "kyc expired", "kyc update", "update your kyc", "complete your kyc",
            "pan card will be blocked", "pan will be blocked",
            "aadhaar will be blocked", "sim will be blocked",
            "unauthorized transaction", "suspicious activity",
            "suspicious transaction", "security alert",
            "legal action", "electricity will be disconnected",
            "service will be discontinued", "pay penalty",
            "block ho jayega", "band ho jayega", "band kar diya jayega",
        ],
    },
    {
        "key": "authority", "name": "Police / authority scare tactic", "severity": "high",
        "points": 25, "cap": 40, "pressure": True,
        "phrases": [
            "digital arrest", "arrest warrant", "fir will be filed",
            "money laundering case", "parcel contains drugs", "drugs were found",
        ],
    },
    {
        "key": "upi_trick", "name": "UPI trick or advance-fee request", "severity": "high",
        "points": 15, "cap": 30, "pressure": True,
        "phrases": [
            "collect request", "approve the request", "accept the request",
            "accept the collect request", "scan the qr", "scan this qr",
            "scan qr code to receive", "to receive money", "to receive payment",
            "money will be credited", "enter your upi pin to receive",
            "wrong transfer", "sent by mistake", "refund your money",
            "pay a small fee", "processing fee", "registration fee",
            "joining fee", "security deposit", "refundable deposit",
        ],
    },
    {
        "key": "remote_app", "name": "Remote-access or sideloaded app", "severity": "high",
        "points": 25, "cap": 40, "pressure": True,
        "phrases": [
            "anydesk", "teamviewer", "quicksupport", "quick support", "rustdesk",
            "share your screen", "screen sharing", "screen share", "apk file",
        ],
        "regexes": [re.compile(r"\b[\w\-.]{1,60}\.apk\b", re.IGNORECASE)],
    },
    {
        "key": "install_prompt", "name": "Asks you to install an app", "severity": "low",
        "points": 8, "cap": 8,
        "phrases": ["install the app", "install this app", "download the app",
                    "download this app", "install app"],
    },
    {
        "key": "parcel", "name": "Parcel / delivery scam wording", "severity": "medium",
        "points": 12, "cap": 24,
        "phrases": [
            "parcel is held", "parcel is on hold", "delivery failed", "delivery attempt failed",
            "reschedule delivery", "reschedule your delivery", "customs fee", "redelivery fee",
            "package could not be delivered", "update your address", "address is incomplete",
            "pay the delivery fee",
        ],
    },
    {
        "key": "job", "name": "Job / task scam wording", "severity": "medium",
        "points": 10, "cap": 20,
        "phrases": [
            "part time job", "part-time job", "work from home", "earn rs", "earn daily",
            "daily income", "telegram group", "like and subscribe",
            "no experience needed",
        ],
    },
    {
        "key": "investment", "name": "Investment scam wording", "severity": "medium",
        "points": 12, "cap": 24,
        "phrases": [
            "guaranteed returns", "double your money", "risk free returns",
            "trading tips", "investment group", "vip group", "assured profit",
        ],
    },
    {
        "key": "secrecy", "name": "Asks you to keep it secret", "severity": "high",
        "points": 12, "cap": 12, "pressure": True,
        "phrases": ["do not tell anyone", "don't tell anyone", "keep this confidential",
                    "do not inform anyone", "don't inform anyone", "keep it secret"],
    },
    {
        "key": "lure", "name": "Reward / refund lure", "severity": "low",
        "points": 8, "cap": 16,
        "phrases": [
            "you have won", "you've won", "lottery", "lucky winner",
            "congratulations", "claim your reward", "reward points",
            "cashback", "free gift", "prize", "kbc", "refund",
        ],
    },
    {
        "key": "callback", "name": "Asks you to phone a number in the message", "severity": "low",
        "points": 5, "cap": 5,
        "phrases": ["customer care number", "customer support number", "helpline number",
                    "call this number", "toll free number"],
    },
    {
        "key": "greeting", "name": "Generic greeting", "severity": "low",
        "points": 3, "cap": 3,
        "phrases": ["dear customer", "dear user", "dear account holder"],
    },
]

_SEVERITY_DOWN = {"high": "medium", "medium": "low", "low": "low"}


def _phrase_regex(phrase: str) -> re.Pattern:
    escaped = re.escape(phrase).replace(r"\ ", r"\s+")
    return re.compile(rf"\b{escaped}\b", re.IGNORECASE)


for _rule in PHRASE_RULES:
    _rule["compiled"] = [(p, _phrase_regex(p)) for p in _rule["phrases"]]

# ---------------------------------------------------------------------------
# 2. Sensitive-information rules
# ---------------------------------------------------------------------------

SENSITIVE_RULES = {
    "OTP": re.compile(
        r"\b(?:otp|one[- ]?time[- ]?(?:password|passcode|pin|code)"
        r"|verification\s+code|security\s+code)\b", re.IGNORECASE),
    # "pin code" (postal PIN code) is deliberately excluded
    "UPI PIN / PIN": re.compile(
        r"\b(?:upi\s*pin|m[- ]?pin|atm\s*pin|pin(?!\s*code))\b", re.IGNORECASE),
    "password": re.compile(r"\b(?:password|passcode|passwd)s?\b", re.IGNORECASE),
    "CVV": re.compile(r"\b(?:cvv2?|cvc)\b", re.IGNORECASE),
    "card number": re.compile(
        r"\b(?:(?:debit|credit|atm)\s+)?card\s*(?:number|num\b|no\b|details)", re.IGNORECASE),
}

# Verbs that clearly ask the reader to hand a secret over.
STRONG_REQUEST_VERBS = re.compile(
    r"\b(?:share|send|give|provide|tell|reply|submit|reveal|forward|read\s+out|"
    r"bhej\w*|bata\w*|dijiye|batayen)\b", re.IGNORECASE)
# Verbs that also appear in genuine messages ("Enter the OTP on the website").
# They only count for secrets other than an OTP.
WEAK_REQUEST_VERBS = re.compile(r"\b(?:enter|confirm|verify|update)\b", re.IGNORECASE)

# Genuine warnings ("Never share your OTP with anyone") must not count as requests.
WARNING_CLAUSE = re.compile(
    r"\b(?:do\s+not|don't|dont|never|not\s+to)\s+(?:ever\s+)?"
    r"(?:share|disclose|reveal|give|tell)\b[^.!?\n]*", re.IGNORECASE)

# "123456 is your OTP" / "OTP: 123456": a delivered code, not a request.
OTP_DELIVERY = re.compile(
    r"\b\d{4,8}\b\s+is\s+(?:your|the)\b[^.\n]{0,40}\b(?:otp|code|password)\b"
    r"|\b(?:otp|code)\b\s*(?:is|:)?\s*\b\d{4,8}\b", re.IGNORECASE)

# ---------------------------------------------------------------------------
# 3. URL and brand rules
# ---------------------------------------------------------------------------

URL_REGEX = re.compile(r"(?:https?://|www\.)[^\s<>\"'()]+", re.IGNORECASE)
IP_HOST_REGEX = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

URL_SHORTENERS = {
    "bit.ly", "bit.do", "tinyurl.com", "t.co", "t.ly", "goo.gl", "ow.ly",
    "is.gd", "v.gd", "buff.ly", "cutt.ly", "rb.gy", "rebrand.ly", "bl.ink",
    "shorturl.at", "tiny.cc", "s.id", "clk.sh", "lnkd.in", "tr.im",
}
SUSPICIOUS_TLDS = (".xyz", ".top", ".click", ".tk", ".gq", ".ml", ".cf", ".work",
                   ".zip", ".country", ".buzz", ".icu")

# Domains EchoShield knows for a few brands. This list is NOT exhaustive: a
# genuine organisation may use other domains, so a mismatch is a warning only.
BRANDS = [
    {"key": "sbi", "name": "SBI", "text": r"\bsbi\b",
     "domains": ("sbi.co.in", "onlinesbi.sbi", "sbi.bank.in", "sbicard.com", "sbilife.co.in")},
    {"key": "hdfc", "name": "HDFC Bank", "text": r"\bhdfc\b",
     "domains": ("hdfcbank.com", "hdfc.com", "hdfclife.com")},
    {"key": "icici", "name": "ICICI Bank", "text": r"\bicici\b",
     "domains": ("icicibank.com", "icicilombard.com", "iciciprulife.com", "icicidirect.com")},
    {"key": "axisbank", "name": "Axis Bank", "text": r"\baxis\s*bank\b",
     "domains": ("axisbank.com",)},
    {"key": "kotak", "name": "Kotak", "text": r"\bkotak\b", "domains": ("kotak.com",)},
    {"key": "pnb", "name": "PNB", "text": r"\bpnb\b", "domains": ("pnbindia.in",)},
    {"key": "paytm", "name": "Paytm", "text": r"\bpaytm\b",
     "domains": ("paytm.com", "paytmbank.com")},
    {"key": "phonepe", "name": "PhonePe", "text": r"\bphonepe\b", "domains": ("phonepe.com",)},
    {"key": "npci", "name": "NPCI", "text": r"\bnpci\b", "domains": ("npci.org.in",)},
    {"key": "rbi", "name": "RBI", "text": r"\brbi\b", "domains": ("rbi.org.in",)},
]
for _b in BRANDS:
    _b["rx"] = re.compile(_b["text"], re.IGNORECASE)

# ---------------------------------------------------------------------------
# 4. Scoring weights (total capped at 100)
# ---------------------------------------------------------------------------

SENSITIVE_REQUEST_BASE = 30
SENSITIVE_REQUEST_EXTRA = 10
SENSITIVE_REQUEST_CAP = 60
SENSITIVE_MENTION_POINTS = 8
SENSITIVE_MENTION_CAP = 16

URL_PRESENT_POINTS = 5
URL_PRESENT_CAP = 10
URL_SHORTENER_POINTS = 20
URL_FLAGS_CAP = 40
BRAND_MISMATCH_POINTS = 12
COMBO_BONUS = 10

LEVEL_HIGH = 50
LEVEL_MEDIUM = 25
NO_STRONG_EVIDENCE_CAP = LEVEL_HIGH - 1  # weak signals alone never reach HIGH

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ZERO_WIDTH = re.compile("[\u200b-\u200f\u2060\ufeff]")


def _extract_urls(text: str) -> list[str]:
    urls: list[str] = []
    for match in URL_REGEX.findall(text):
        cleaned = match.rstrip(".,;:!?")
        if cleaned and cleaned not in urls:
            urls.append(cleaned)
    return urls


def _get_host(url: str) -> str:
    target = url if "://" in url else f"http://{url}"
    try:
        host = (urlparse(target).hostname or "").lower()
    except ValueError:
        return ""
    return host[4:] if host.startswith("www.") else host


def _is_official(host: str, domains: tuple[str, ...]) -> bool:
    return any(host == d or host.endswith("." + d) for d in domains)


def _analyze_url(url: str) -> dict:
    """Return {'shortener': bool, 'flags': [(text, severity, points)]} for one URL."""
    host = _get_host(url)
    if not host:
        return {"shortener": False, "flags": [("is malformed or unreadable", "medium", 12)]}

    flags: list[tuple[str, str, int]] = []
    if url.lower().startswith("http://"):
        flags.append(("uses unencrypted HTTP", "low", 4))
    if IP_HOST_REGEX.match(host):
        flags.append(("uses a raw IP address instead of a domain name", "high", 15))
    if host.endswith(SUSPICIOUS_TLDS):
        flags.append(("uses a domain extension common in scams", "medium", 12))
    if host.startswith("xn--") or ".xn--" in host:
        flags.append(("uses an internationalized (possible look-alike) domain", "medium", 12))
    if "@" in url.split("//", 1)[-1].split("/", 1)[0]:
        flags.append(("contains '@', which can disguise the real destination", "high", 15))
    if host.count(".") >= 4:
        flags.append(("has an unusually long chain of subdomains", "low", 8))

    tokens = re.split(r"[.\-_]", host)
    for brand in BRANDS:
        key = brand["key"]
        mentions = any(t == key or t.startswith(key) for t in tokens)
        if mentions and not _is_official(host, brand["domains"]):
            flags.append((f"imitates '{key}' but is not a domain EchoShield knows for {brand['name']}",
                          "high", 20))
            break

    return {"shortener": host in URL_SHORTENERS, "flags": flags}


def _risk_level(score: int) -> str:
    if score <= 0:
        return "NONE"
    if score >= LEVEL_HIGH:
        return "HIGH"
    if score >= LEVEL_MEDIUM:
        return "MEDIUM"
    return "LOW"


def _quote(items: list[str], limit: int = 5) -> str:
    shown = ", ".join(f"'{i[:60]}'" for i in items[:limit])
    return shown + (f" (+{len(items) - limit} more)" if len(items) > limit else "")


THREAT_TYPES = [  # (category key, label), first match wins
    ("remote_app", "malicious app or remote-access scam"),
    ("authority", "authority impersonation scam"),
    ("secrets", "credential or OTP theft (phishing)"),
    ("parcel", "parcel or delivery scam"),
    ("job", "job or task scam"),
    ("investment", "investment scam"),
    ("upi_trick", "UPI or advance-fee payment scam"),
    ("bad_link", "phishing link"),
    ("threat", "account-block pressure scam"),
    ("lure", "prize or refund lure"),
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_message(text: str) -> dict:
    """Analyze a message and return the deterministic risk assessment."""
    text = _ZERO_WIDTH.sub("", (text or "").replace("\u2019", "'")).strip()
    lowered = re.sub(r"\s+", " ", text.lower())

    details: list[dict] = []
    recs: list[str] = []
    cats: set[str] = set()
    pressure = False
    score = 0

    def add(name: str, evidence: str, severity: str) -> None:
        details.append({"name": name, "evidence": evidence, "severity": severity})

    # --- 1. Phrase categories -----------------------------------------------
    for rule in PHRASE_RULES:
        found = [p for p, rx in rule["compiled"] if rx.search(lowered)]
        for rx in rule.get("regexes", []):
            m = rx.search(text)
            if m:
                found.append(m.group(0).lower())
        if not found:
            continue
        score += min(len(found) * rule["points"], rule["cap"])
        cats.add(rule["key"])
        pressure = pressure or rule.get("pressure", False)
        sev = rule["severity"] if len(found) >= 2 or rule["severity"] == "low" \
            else _SEVERITY_DOWN[rule["severity"]]
        if rule["key"] in ("remote_app", "authority"):
            sev = "high"  # a single match is already strong evidence
        add(rule["name"], "Message contains " + _quote(found) + ".", sev)

    # --- 2. Requests for secrets --------------------------------------------
    mentioned = [label for label, rx in SENSITIVE_RULES.items() if rx.search(lowered)]
    secrets_requested = False
    if mentioned:
        cleaned = WARNING_CLAUSE.sub(" ", lowered)
        had_warning = cleaned != lowered
        strong = bool(STRONG_REQUEST_VERBS.search(cleaned))
        weak = bool(WEAK_REQUEST_VERBS.search(cleaned)) and mentioned != ["OTP"]
        secrets_requested = strong or weak

        if secrets_requested:
            score += min(SENSITIVE_REQUEST_BASE + SENSITIVE_REQUEST_EXTRA * (len(mentioned) - 1),
                         SENSITIVE_REQUEST_CAP)
            cats.add("secrets")
            add("Asks for sensitive details",
                "The message asks you to share or confirm your " + ", ".join(mentioned) +
                ". Banks and UPI apps do not ask for these by SMS, call or chat.", "high")
        elif OTP_DELIVERY.search(lowered) or had_warning:
            add("OTP or code mentioned, no request found",
                "Looks like a delivered code or a safety warning, which is typical of genuine "
                "alerts. Not counted as a risk signal.", "low")
        else:
            score += min(len(mentioned) * SENSITIVE_MENTION_POINTS, SENSITIVE_MENTION_CAP)
            add("Mentions sensitive details",
                "Mentions " + ", ".join(mentioned) + " but no direct request was detected.", "low")

    # --- 3. URLs ---------------------------------------------------------------
    urls = _extract_urls(text)
    shorteners: list[str] = []
    if urls:
        score += min(len(urls) * URL_PRESENT_POINTS, URL_PRESENT_CAP)
        add("Contains a link" if len(urls) == 1 else f"Contains {len(urls)} links",
            "Links: " + _quote(urls, 3) + ". EchoShield does not open or check them.", "low")

        flag_points = 0
        for url in urls:
            result = _analyze_url(url)
            if result["shortener"]:
                shorteners.append(url)
                flag_points += URL_SHORTENER_POINTS
                cats.add("bad_link")
                add("Shortened link", f"{url} hides where it really leads.", "medium")
            for flag_text, sev, pts in result["flags"]:
                flag_points += pts
                if sev != "low":
                    cats.add("bad_link")
                add("Suspicious link", f"{url} {flag_text}.", sev)
        score += min(flag_points, URL_FLAGS_CAP)

        # Message names an organisation but links somewhere unrelated
        named = [b for b in BRANDS if b["rx"].search(lowered)]
        mismatched = [
            b["name"] for b in named
            if not any(_is_official(_get_host(u), b["domains"]) for u in urls)
        ]
        if mismatched:
            score += BRAND_MISMATCH_POINTS
            cats.add("bad_link")
            add("Link does not match the organisation named",
                f"The message mentions {', '.join(mismatched)}, but no link is on a domain "
                "EchoShield knows for it (this list is not exhaustive, so check manually).",
                "medium")

    # --- 4. Combination bonuses ---------------------------------------------------
    if secrets_requested and pressure:
        score += COMBO_BONUS
        add("Secret request combined with pressure",
            "Asking for codes or PINs while rushing or threatening you is a classic scam pattern.",
            "high")
    if secrets_requested and urls:
        score += COMBO_BONUS
        add("Secret request combined with a link",
            "The message asks for sensitive details and also pushes a link.", "high")

    # --- 5. Cap, level -----------------------------------------------------------------
    has_strong = any(d["severity"] == "high" for d in details)
    if not has_strong:
        score = min(score, NO_STRONG_EVIDENCE_CAP)
    score = max(0, min(score, 100))
    level = _risk_level(score)

    details.sort(key=lambda d: {"high": 0, "medium": 1, "low": 2}[d["severity"]])

    # --- 6. Threat type ----------------------------------------------------------------
    if level == "NONE":
        threat_type = "No scam pattern detected"
    elif level == "LOW":
        threat_type = "Weak signals only"
    else:
        label = next((lbl for key, lbl in THREAT_TYPES if key in cats), "suspicious message")
        threat_type = "Possible " + label

    # --- 7. Recommendations --------------------------------------------------------------
    if secrets_requested:
        recs.append("Never share your OTP, UPI PIN, password, CVV or card number with anyone. "
                    "Banks and UPI apps never ask for these by call, SMS or chat.")
    if "upi_trick" in cats or (secrets_requested and "UPI PIN / PIN" in mentioned):
        recs.append("You never need to enter your UPI PIN to receive money. Decline unknown "
                    "collect requests and do not scan QR codes sent to you.")
    if "remote_app" in cats or "install_prompt" in cats:
        recs.append("Do not install apps or APK files sent by SMS or WhatsApp, and never install "
                    "screen-sharing apps such as AnyDesk for a stranger. Use only the official app store.")
    if "authority" in cats:
        recs.append("Police and government agencies do not arrest or investigate people over a call "
                    "or message, and a 'digital arrest' does not exist. Hang up and tell a family member.")
    if "parcel" in cats:
        recs.append("Check the delivery status in the courier's official app or website using your "
                    "own tracking number. Do not pay fees through links in a message.")
    if "job" in cats or "investment" in cats:
        recs.append("Genuine employers and investment firms do not ask for joining fees or advance "
                    "payments, or run 'tasks' through Telegram or WhatsApp groups.")
    if urls:
        recs.append("Do not click the link. Open the official app or type the website address yourself.")
    if shorteners:
        recs.append("Shortened links hide where they lead. Treat them as untrusted.")
    if pressure:
        recs.append("Pause before acting. Scammers create fake deadlines and threats so you do "
                    "not stop to verify.")
    if level in ("MEDIUM", "HIGH"):
        recs.append("Verify through the official number on your card or the organisation's official "
                    "app. If money was lost, call the National Cyber Crime Helpline 1930 or report at "
                    "cybercrime.gov.in.")
    if not recs:
        recs.append("No known scam pattern was found, but that does not prove the message is genuine. "
                    "Do not share codes or click links in unexpected messages.")

    # --- 8. Summary -----------------------------------------------------------------------
    if level == "NONE":
        summary = ("EchoShield's checks did not find known scam indicators in this message. "
                   "That does not prove it is safe.")
    elif level == "LOW":
        summary = (f"Only minor or weak warning signs were found (score {score}/100). "
                   "This is probably harmless, but stay alert.")
    elif level == "MEDIUM":
        summary = (f"This message has several traits commonly seen in scams (score {score}/100). "
                   "Do not act on it until you verify the sender another way.")
    else:
        summary = (f"This message contains multiple indicators commonly associated with scams "
                   f"(score {score}/100). Do not reply, click links, or share any codes.")

    return {
        "risk_level": level,
        "risk_score": score,
        "summary": summary,
        "threat_type": threat_type,
        "indicators": [f"{d['name']}: {d['evidence']}" for d in details],
        "indicator_details": details,
        "recommendations": recs,
        "urls_found": urls,
        "spoken_summary": _spoken_summary(level, details, recs),
        "disclaimer": DISCLAIMER,
    }


def _spoken_summary(level: str, details: list[dict], recs: list[str]) -> str:
    """Two or three short sentences suitable for a voice assistant."""
    opener = {
        "NONE": "I did not find known scam signs, but that does not prove the message is safe.",
        "LOW": "I found only minor warning signs.",
        "MEDIUM": "This looks suspicious.",
        "HIGH": "This has strong scam warning signs.",
    }[level]
    parts = [opener]
    top = next((d for d in details if d["severity"] in ("high", "medium")), None)
    if top and level in ("MEDIUM", "HIGH"):
        parts.append(f"Main reason: {top['name'].lower()}.")
    if level in ("MEDIUM", "HIGH") and recs:
        first = re.split(r"(?<=[.!?])\s", recs[0], maxsplit=1)[0]
        parts.append(first)
    return " ".join(parts)


# Helpers reused elsewhere
extract_urls = _extract_urls
risk_level_for_score = _risk_level
