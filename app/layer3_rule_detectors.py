"""
Layer 3 (rule-based half): regex jailbreak/prompt-injection detectors.
Direct port of TwinShield's backend/layers/risk.py — the eight
_detect_* methods and _analyze_local, ported verbatim as module-level
functions since they carry no state (regex patterns only).

Runs alongside the semantic similarity detector in Layer 3 so both are
visible side by side (rule_flags vs semantic_flags), same as your
original RiskAnalysisEngine.analyze().
"""
import re
import base64
from typing import List


def detect_jailbreak(text: str) -> List[str]:
    patterns = [
        r"dan mode",
        r"jailbreak",
        r"do anything now",
        r"ignore (your|all|previous|prior) (rules|instructions|guidelines|training|constraints)",
        r"pretend (you are|to be|you're) (not|without|free)",
        r"as an? (ai|language model) without",
        r"you are now (free|unrestricted|without)",
        r"disable (your|all) (filters|restrictions|safety)",
        r"developer mode",
        r"god mode",
        r"unrestricted mode",
        r"without (ethical|moral|safety) (guidelines|constraints|restrictions)",
    ]
    for p in patterns:
        if re.search(p, text, re.IGNORECASE):
            return ["JAILBREAK_ATTEMPT"]
    return []


def detect_role_injection(text: str) -> List[str]:
    patterns = [
        r"you are now (a |an )?(system|admin|root|superuser|god|master)",
        r"act as (a |an )?(system|admin|root|unrestricted|evil|malicious)",
        r"your (new |true )?(role|persona|identity|name) is",
        r"switch to (system|admin|developer|unrestricted) mode",
        r"you are (no longer|not) (an? )?(ai|assistant|language model)",
        r"from now on (you are|you will be|act as)",
        r"i (hereby|now) appoint you",
    ]
    for p in patterns:
        if re.search(p, text, re.IGNORECASE):
            return ["ROLE_INJECTION"]
    return []


def detect_ignore_instructions(text: str) -> List[str]:
    patterns = [
        r"ignore\s+(.+?\s+)?(instructions|prompts|rules|guidelines|context)",
        r"disregard\s+(everything|all|any|previous|prior)",
        r"forget\s+(everything|all|your|previous|prior)",
        r"override\s+(your|all|previous)\s*(instructions|settings|rules)",
        r"new\s+(instructions|rules|prompt|system prompt)\s*:",
        r"actual\s+(instructions|task|goal|objective)\s*:",
    ]
    for p in patterns:
        if re.search(p, text, re.IGNORECASE):
            return ["IGNORE_INSTRUCTIONS"]
    return []


def detect_system_override(text: str) -> List[str]:
    patterns = [
        r"\[system\]",
        r"<s>",
        r"###\s*system",
        r"system\s*prompt\s*:",
        r"\|\s*system\s*\|",
        r"<<sys>>",
        r"\[inst\]",
        r"<\|system\|>",
        r"<\|im_start\|>\s*system",
    ]
    for p in patterns:
        if re.search(p, text, re.IGNORECASE):
            return ["SYSTEM_OVERRIDE_ATTEMPT"]
    return []


def detect_hidden_prompt(text: str) -> List[str]:
    flags = []

    invisible = ['\u200b', '\u200c', '\u200d', '\ufeff', '\u00ad']
    if any(ch in text for ch in invisible):
        flags.append("HIDDEN_UNICODE_PAYLOAD")

    if re.search(r'\s{20,}', text):
        flags.append("WHITESPACE_STUFFING")

    if re.search(r'<!--.*?-->', text, re.DOTALL):
        flags.append("HTML_COMMENT_INJECTION")

    return flags


def detect_base64_injection(text: str) -> List[str]:
    pattern = r'[A-Za-z0-9+/]{30,}={0,2}'
    matches = re.findall(pattern, text)

    for m in matches[:5]:
        try:
            decoded = base64.b64decode(m).decode("utf-8", errors="ignore")
            lower_d = decoded.lower()
            if any(kw in lower_d for kw in [
                "ignore", "system", "prompt", "role",
                "jailbreak", "admin", "override", "instructions"
            ]):
                return ["BASE64_INJECTION"]
        except Exception:
            pass

    return []


def detect_prompt_leaking(text: str) -> List[str]:
    patterns = [
        r"(reveal|show|print|output|display|tell me|give me|repeat|leak) (your|the) (system |original |initial )?(prompt|instructions|rules|context|setup)",
        r"what (are|were) your (instructions|rules|system prompt|guidelines)",
        r"what (is|was) (in )?your (system|context|initial) prompt",
    ]
    for p in patterns:
        if re.search(p, text, re.IGNORECASE):
            return ["PROMPT_LEAKING_ATTEMPT"]
    return []


def detect_context_manipulation(text: str) -> List[str]:
    patterns = [
        r"end of (conversation|context|prompt|system)",
        r"new (conversation|context|session) (starts?|begins?|here)",
        r"---+\s*(end|start|begin|new)",
        r"(above|previous) (text|context|prompt) (is |was )?(a )?(test|example|fake|ignore)",
    ]
    for p in patterns:
        if re.search(p, text, re.IGNORECASE):
            return ["CONTEXT_MANIPULATION"]
    return []

# ── Password / PII action-request gating ──────────────────────────
# NOT part of your original TwinShield repo — added per your explicit
# request. Blocks requests asking the assistant to DO something with a
# password or personal info ("reset my password", "send me the SSN"),
# while explicitly NOT blocking informational questions about the same
# topic ("how do I reset my password").

_INFO_INTENT_MARKERS = [
    r"\bhow (do|can|would|should|might) i\b",
    r"\bhow to\b",
    r"\bwhat is the (process|procedure|steps?)\b",
    r"\bwhat are the steps\b",
    r"\bexplain how\b",
    r"\bguide (me|to)\b",
    r"\bwalk me through\b",
    r"\bwhat should i do\b",
    r"\bwhy (do|does|is|would)\b",
    r"\bwhat happens (if|when)\b",
    r"\bcan you explain\b",
]

_PASSWORD_ACTION_PATTERNS = [
    r"\breset (my|the|our|this) (account )?password\b",
    r"\bchange (my|the|our) password\b",
    r"\bsend (me )?(my|the) password\b",
    r"\bgive (me )?(my|the|your) password\b",
    r"\bwhat('?s| is) my password\b",
    r"\btell me (my|the) password\b",
    r"\bupdate (my|the) password\b",
]

_PII_ACTION_PATTERNS = [
    r"\bsend (me )?(my|the) (ssn|social security number|credit card( number)?|bank details|home address|phone number)\b",
    r"\bgive (me )?(my|the|your) (ssn|social security number|credit card( number)?|bank details|personal (information|details))\b",
    r"\bwhat('?s| is) my (ssn|social security number|home address|phone number)\b",
    r"\btell me (my|the) (ssn|social security number|home address|phone number|personal (information|details))\b",
]


def detect_password_or_pii_action(text: str) -> List[str]:
    """Blocks action-phrased requests ('reset my password', 'send me the
    SSN') but exempts anything carrying an informational-intent marker
    ('how do I...', 'what is the process...') even if it mentions the
    same nouns — those get answered normally, not blocked."""
    lower = text.lower()
    if any(re.search(p, lower) for p in _INFO_INTENT_MARKERS):
        return []

    flags = []
    if any(re.search(p, lower) for p in _PASSWORD_ACTION_PATTERNS):
        flags.append("PASSWORD_RESET_ACTION_REQUEST")
    if any(re.search(p, lower) for p in _PII_ACTION_PATTERNS):
        flags.append("PII_DISCLOSURE_ACTION_REQUEST")
    return flags

def analyze_local(prompt: str) -> List[str]:
    """Direct port of RiskAnalysisEngine._analyze_local — runs all eight
    detectors and returns the deduplicated union of flags. Note: unlike
    the other _detect_* calls in your original which run on the
    lowercased text, detect_hidden_prompt and detect_base64_injection
    run on the ORIGINAL prompt (case/whitespace/encoding matters for
    those two) — same split as your original code."""
    lower = prompt.lower()
    flags = []
    flags += detect_jailbreak(lower)
    flags += detect_role_injection(lower)
    flags += detect_ignore_instructions(lower)
    flags += detect_system_override(lower)
    flags += detect_hidden_prompt(prompt)
    flags += detect_base64_injection(prompt)
    flags += detect_prompt_leaking(lower)
    flags += detect_context_manipulation(lower)
    flags += detect_password_or_pii_action(prompt)
    return list(set(flags))
