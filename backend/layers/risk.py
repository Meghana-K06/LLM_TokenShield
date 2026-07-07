import re
import base64
import asyncio
import logging
from typing import List, Optional

from config import get_settings
from layers.semantic_similarity import SemanticSimilarityDetector
from layers.lakera_client import LakeraGuardClient

settings = get_settings()
logger = logging.getLogger("twinshield.risk")

# Maps Lakera Guard's category names to TwinShield's existing flag
# taxonomy, so downstream code (scoring, dashboard, Layer 9) can treat
# a flag the same regardless of which detector raised it. Any Lakera
# category not listed here still gets surfaced, just under a
# generated LAKERA_<CATEGORY> name instead of being silently dropped.
_LAKERA_CATEGORY_MAP = {
    "prompt_injection": "JAILBREAK_ATTEMPT",
    "jailbreak": "JAILBREAK_ATTEMPT",
    "unknown_links": "PROMPT_LEAKING_ATTEMPT",  # closest existing bucket
    "pii": "PII_DETECTED",
    "moderated_content/hate": "CONTENT_MODERATION_FLAG",
    "moderated_content/violence": "CONTENT_MODERATION_FLAG",
    "moderated_content/sexual": "CONTENT_MODERATION_FLAG",
    "moderated_content/weapons": "CONTENT_MODERATION_FLAG",
    "moderated_content/self_harm": "CONTENT_MODERATION_FLAG",
}


class RiskAnalysisEngine:
    """
    Detects prompt injection, jailbreaks, role confusion, system
    override attempts, hidden payloads, and content risks.

    Layer 3 runs THREE independent detectors on every prompt, in
    parallel, and reports all three outputs separately (not just a
    merged verdict) so they can be compared side by side — e.g. for
    a report section on how often each one catches something the
    others miss:

    1. Local regex detectors (`rule_flags`) — fast, offline, exact
       phrasing only. See each `_detect_*` method.
    2. Local semantic/embedding detector (`semantic_flags`) — offline
       via Ollama, catches paraphrases the regex list misses. See
       layers/semantic_similarity.py.
    3. Lakera Guard cloud API (`lakera_flags`) — broader threat
       coverage (PII, content moderation, continuously updated threat
       intel), requires internet + API key. See layers/lakera_client.py.

    Lakera failing (no key, network down, timeout) does NOT block the
    other two — it just means `lakera_status` reports why, and
    `lakera_flags` comes back empty. The final `risk_flags` is the
    union of all three, and `risk_score` is the max of each source's
    own score (the single most confident detector wins, rather than
    stacking scores that would otherwise double-count the same threat
    caught by more than one path).
    """

    def __init__(
        self,
        semantic_detector: Optional[SemanticSimilarityDetector] = None,
        lakera_client: Optional[LakeraGuardClient] = None,
    ):
        self.semantic_detector = semantic_detector or SemanticSimilarityDetector()
        self.lakera_client = lakera_client or LakeraGuardClient()

    async def analyze(self, prompt: str) -> dict:
        rule_flags = self._analyze_local(prompt)
        rule_score = min(len(rule_flags) * 18, 100)

        # Semantic (Ollama) and Lakera (cloud) both make network calls
        # — run them concurrently rather than sequentially.
        semantic_task = self.semantic_detector.analyze(prompt)
        lakera_task = self._safe_lakera_check(prompt)
        semantic_result, lakera_result = await asyncio.gather(semantic_task, lakera_task)

        semantic_flags = semantic_result["semantic_flags"]
        semantic_score = (
            round(semantic_result["max_similarity"] * 100) if semantic_flags else 0
        )

        lakera_flags = lakera_result["flags"]
        lakera_score = lakera_result["score"]

        risk_flags = list(set(rule_flags + semantic_flags + lakera_flags))
        risk_score = max(rule_score, semantic_score, lakera_score)

        return {
            "risk_flags":        risk_flags,
            "is_suspicious":     len(risk_flags) > 0,
            "risk_score":        risk_score,

            "rule_flags":        rule_flags,

            "semantic_flags":    semantic_flags,
            "semantic_matches":  semantic_result["semantic_matches"],
            "semantic_score":    semantic_score,

            "lakera_flags":      lakera_flags,
            "lakera_categories": lakera_result["categories"],
            "lakera_scores":     lakera_result["category_scores"],
            "lakera_score":      lakera_score,
            "lakera_status":     lakera_result["status"],
        }

    async def _safe_lakera_check(self, prompt: str) -> dict:
        """
        Wraps LakeraGuardClient.check so a failure (no key, timeout,
        network down) never breaks Layer 3 — it just means Lakera has
        no opinion on this request, reported via `status`.
        """
        if not settings.ENABLE_LAKERA:
            return {"flags": [], "categories": {}, "category_scores": {}, "score": 0, "status": "disabled"}

        try:
            result = await self.lakera_client.check(prompt)
        except Exception as e:
            logger.warning(f"Lakera Guard unavailable: {e}")
            return {"flags": [], "categories": {}, "category_scores": {}, "score": 0, "status": f"unavailable: {e}"}

        categories = result["categories"]
        scores = result["category_scores"]
        flags = [
            _LAKERA_CATEGORY_MAP.get(cat, f"LAKERA_{cat.upper()}")
            for cat, detected in categories.items() if detected
        ]
        flags = list(set(flags))
        score = int(max(scores.values()) * 100) if scores else (100 if result["flagged"] else 0)

        return {
            "flags": flags,
            "categories": categories,
            "category_scores": scores,
            "score": score,
            "status": "ok",
        }

    def _analyze_local(self, prompt: str) -> List[str]:
        lower = prompt.lower()
        rule_flags = []
        rule_flags += self._detect_jailbreak(lower)
        rule_flags += self._detect_role_injection(lower)
        rule_flags += self._detect_ignore_instructions(lower)
        rule_flags += self._detect_system_override(lower)
        rule_flags += self._detect_hidden_prompt(prompt)
        rule_flags += self._detect_base64_injection(prompt)
        rule_flags += self._detect_prompt_leaking(lower)
        rule_flags += self._detect_context_manipulation(lower)
        return list(set(rule_flags))

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

        invisible = ['\u200b', '\u200c', '\u200d', '\ufeff', '\u00ad']
        if any(ch in text for ch in invisible):
            flags.append("HIDDEN_UNICODE_PAYLOAD")

        if re.search(r'\s{20,}', text):
            flags.append("WHITESPACE_STUFFING")

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
