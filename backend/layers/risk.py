import re
import base64
from typing import List

class RiskAnalysisEngine:
    """
    Detects prompt injection, jailbreaks, role confusion,
    system override attempts, and hidden payloads.
    """

    def analyze(self, prompt: str) -> dict:
        risk_flags = []
        lower      = prompt.lower()

        # Run all detectors
        risk_flags += self._detect_jailbreak(lower)
        risk_flags += self._detect_role_injection(lower)
        risk_flags += self._detect_ignore_instructions(lower)
        risk_flags += self._detect_system_override(lower)
        risk_flags += self._detect_hidden_prompt(prompt)
        risk_flags += self._detect_base64_injection(prompt)
        risk_flags += self._detect_prompt_leaking(lower)
        risk_flags += self._detect_context_manipulation(lower)

        # Deduplicate
        risk_flags = list(set(risk_flags))

        # Score
        risk_score = min(len(risk_flags) * 18, 100)

        return {
            "risk_flags":    risk_flags,
            "is_suspicious": len(risk_flags) > 0,
            "risk_score":    risk_score,
        }

    # ── Detectors ─────────────────────────────────────────────────────

    def _detect_jailbreak(self, text: str) -> List[str]:
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
        flags = []
        for p in patterns:
            if re.search(p, text, re.IGNORECASE):
                flags.append("JAILBREAK_ATTEMPT")
                break
        return flags

    def _detect_role_injection(self, text: str) -> List[str]:
        patterns = [
            r"you are now (a |an )?(system|admin|root|superuser|god|master)",
            r"act as (a |an )?(system|admin|root|unrestricted|evil|malicious)",
            r"your (new |true )?(role|persona|identity|name) is",
            r"switch to (system|admin|developer|unrestricted) mode",
            r"you are (no longer|not) (an? )?(ai|assistant|language model)",
            r"from now on (you are|you will be|act as)",
            r"i (hereby|now) appoint you",
        ]
        flags = []
        for p in patterns:
            if re.search(p, text, re.IGNORECASE):
                flags.append("ROLE_INJECTION")
                break
        return flags

    def _detect_ignore_instructions(self, text: str) -> List[str]:
        patterns = [
            r"ignore\s+(.+?\s+)?(instructions|prompts|rules|guidelines|context)",
            r"disregard\s+(everything|all|any|previous|prior)",
            r"forget\s+(everything|all|your|previous|prior)",
            r"override\s+(your|all|previous)\s*(instructions|settings|rules)",
            r"new\s+(instructions|rules|prompt|system prompt)\s*:",
            r"actual\s+(instructions|task|goal|objective)\s*:",
        ]
        flags = []
        for p in patterns:
            if re.search(p, text, re.IGNORECASE):
                flags.append("IGNORE_INSTRUCTIONS")
                break
        return flags

    def _detect_system_override(self, text: str) -> List[str]:
        patterns = [
            r"\[system\]",
            r"<system>",
            r"###\s*system",
            r"system\s*prompt\s*:",
            r"\|\s*system\s*\|",
            r"<<sys>>",
            r"\[inst\]",
            r"<\|system\|>",
            r"<\|im_start\|>\s*system",
        ]
        flags = []
        for p in patterns:
            if re.search(p, text, re.IGNORECASE):
                flags.append("SYSTEM_OVERRIDE_ATTEMPT")
                break
        return flags

    def _detect_hidden_prompt(self, text: str) -> List[str]:
        flags = []

        # Invisible unicode characters
        invisible = ['\u200b', '\u200c', '\u200d', '\ufeff', '\u00ad']
        if any(ch in text for ch in invisible):
            flags.append("HIDDEN_UNICODE_PAYLOAD")

        # Whitespace stuffing
        if re.search(r'\s{20,}', text):
            flags.append("WHITESPACE_STUFFING")

        # HTML comment injection
        if re.search(r'<!--.*?-->', text, re.DOTALL):
            flags.append("HTML_COMMENT_INJECTION")

        return flags

    def _detect_base64_injection(self, text: str) -> List[str]:
        flags   = []
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
                    flags.append("BASE64_INJECTION")
                    break
            except Exception:
                pass

        return flags

    def _detect_prompt_leaking(self, text: str) -> List[str]:
        patterns = [
            r"(reveal|show|print|output|display|tell me|give me|repeat|leak) (your|the) (system |original |initial )?(prompt|instructions|rules|context|setup)",
            r"what (are|were) your (instructions|rules|system prompt|guidelines)",
            r"what (is|was) (in )?your (system|context|initial) prompt",
        ]
        flags = []
        for p in patterns:
            if re.search(p, text, re.IGNORECASE):
                flags.append("PROMPT_LEAKING_ATTEMPT")
                break
        return flags

    def _detect_context_manipulation(self, text: str) -> List[str]:
        patterns = [
            r"end of (conversation|context|prompt|system)",
            r"new (conversation|context|session) (starts?|begins?|here)",
            r"---+\s*(end|start|begin|new)",
            r"(above|previous) (text|context|prompt) (is |was )?(a )?(test|example|fake|ignore)",
        ]
        flags = []
        for p in patterns:
            if re.search(p, text, re.IGNORECASE):
                flags.append("CONTEXT_MANIPULATION")
                break
        return flags
