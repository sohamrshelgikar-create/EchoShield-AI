"""Minimise personal data before anything is sent to an external AI service."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from backend.analyzer import URL_REGEX

MAX_CHARS_TO_AI = 2500

_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
# Phone, account and card numbers (6+ digits, optionally spaced or dashed)
_LONG_NUMBER = re.compile(r"(?<![\w])\+?\d[\d \-]{4,}\d(?![\w])")
# Short codes right next to OTP wording ("OTP 482913", "482913 is your OTP")
_OTP_AFTER = re.compile(r"(\b(?:otp|code|pin|cvv)\b\D{0,12})\d{3,8}\b", re.IGNORECASE)
_OTP_BEFORE = re.compile(r"\b\d{4,8}\b(?=\s+is\s+(?:your|the)\b)", re.IGNORECASE)


def _mask_url(match: re.Match) -> str:
    raw = match.group(0).rstrip(".,;:!?")
    target = raw if "://" in raw else f"http://{raw}"
    try:
        host = urlparse(target).hostname or "unknown-host"
    except ValueError:
        host = "unknown-host"
    scheme = "http" if raw.lower().startswith("http://") else "https"
    return f"{scheme}://{host}/[path-removed]"


def redact_for_ai(text: str) -> str:
    """Mask emails, long numbers, OTP-like codes and URL paths; neutralise angle brackets."""
    out = URL_REGEX.sub(_mask_url, text)
    out = _EMAIL.sub("[email]", out)
    out = _OTP_AFTER.sub(r"\1[code]", out)
    out = _OTP_BEFORE.sub("[code]", out)
    out = _LONG_NUMBER.sub("[number]", out)
    out = out.replace("<", "\u2039").replace(">", "\u203a")  # stop tag break-out
    return out[:MAX_CHARS_TO_AI]
