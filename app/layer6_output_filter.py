"""
Layer 6: Output Safety Filter — Final Decision
Final gate before anything is returned to the caller.
- If the request was BLOCKed upstream, returns a safe generic refusal
  (never echoes the malicious payload back).
- If ALLOWed, redacts obvious PII patterns (emails, phone numbers, card
  numbers) from any generated content as a last line of defense before
  it leaves the system.
"""
import re

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
PHONE_RE = re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?(?:\d{10}|\d{3}[-.\s]\d{3}[-.\s]\d{4})\b")
CARD_RE = re.compile(r"\b(?:\d[ -]*?){13,16}\b")

REFUSAL_MESSAGE = (
    "This request was blocked by TwinShield due to a detected policy "
    "violation. If you believe this is an error, please contact the security team."
)

BLACKLIST_MESSAGE = (
    "This client is blacklisted and cannot submit requests to this gateway."
)


def redact_pii(text: str) -> str:
    text = EMAIL_RE.sub("[REDACTED_EMAIL]", text)
    text = CARD_RE.sub("[REDACTED_CARD_NUMBER]", text)
    text = PHONE_RE.sub("[REDACTED_PHONE]", text)
    return text


def output_safety_filter(final_verdict: str, echo_payload: str, blacklisted: bool = False) -> str:
    if blacklisted:
        return BLACKLIST_MESSAGE
    if final_verdict == "BLOCK":
        return REFUSAL_MESSAGE
    # In this prototype we simply echo back a safe, redacted confirmation.
    # In a real system this is where you'd filter the downstream app's
    # actual generated response before returning it to the user.
    safe_text = redact_pii(echo_payload)
    return f"Request accepted and processed safely. Sanitized echo: {safe_text}"
