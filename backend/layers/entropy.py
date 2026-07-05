import re
import math
import base64
from collections import Counter

import tiktoken
import joblib
import os
import numpy as np

# Common leetspeak/homoglyph substitutions used to dodge keyword-based
# detectors (e.g. "1gn0r3" instead of "ignore"). Used ONLY to build a
# normalized copy of text for keyword matching — never for entropy,
# token counting, or the obfuscation feature itself.
LEET_MAP = str.maketrans({
    "0": "o", "1": "i", "3": "e", "4": "a",
    "5": "s", "7": "t", "@": "a", "$": "s",
    "!": "i", "+": "t",
})

# Minimal instruction-verb list. NOTE: this is NOT one of the four
# scored signals — it exists only to answer one yes/no question that
# _estimate_expansion_factor needs: "is a number in this prompt paired
# with a command, or just an incidental number?" Without this gate,
# "the year 1000" and "write 1000 stories" would score identically,
# which was the original bug we fixed. This is intentionally kept as
# simple keyword lookup rather than engineered as a full feature,
# because it isn't part of the model's input — it's a structural gate.
_INSTRUCTION_KEYWORDS = [
    "generate", "write", "create", "list", "repeat", "produce",
    "output", "print", "describe", "explain", "summarize", "translate",
    "rewrite", "expand", "continue", "give me", "provide", "make",
    "build", "enumerate",
]

MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "ml", "cost_classifier.joblib")


class EntropyEngine:
    """
    Estimates computational cost / suspiciousness of a prompt BEFORE
    sending it to the LLM. Reduced to four engineered signals:

      1. encoding_score      - base64/hex encoded payload detection
      2. expansion_factor     - amplification / token-bomb signal
      3. obfuscation_score   - leetspeak-style character substitution
      4. entropy_score        - real Shannon entropy vs normal English

    These four numeric features are fed into a trained logistic
    regression classifier (see backend/ml/train_cost_classifier.py) to
    produce the final cost_score, rather than a hand-picked weighted
    sum. The classifier's weights are LEARNED from labeled synthetic
    examples, not guessed — see the training script for exactly how
    those examples were generated and what the model actually learned.

    Base64/hex structural detection stays regex-based deliberately:
    validating "does this string satisfy the base64 alphabet" is a
    format-grammar question, not a pattern an ML model has any
    advantage learning — production DLP/WAF tools use the same
    approach for the same reason. What moved to ML is the DECISION of
    how much each of the four signals should matter, not the low-level
    extraction of the signals themselves — that split is normal in any
    ML pipeline: feature engineering still involves rules, learning
    replaces hand-tuned combination weights.
    """

    def __init__(self):
        try:
            self._encoding = tiktoken.get_encoding("cl100k_base")
        except Exception:
            self._encoding = None  # fall back to word-count heuristic

        try:
            self._model = joblib.load(MODEL_PATH)
        except Exception:
            # No trained model on disk yet (e.g. before first training
            # run, or on a fresh clone before running the training
            # script). Falls back to a simple average of the four
            # signals so the layer never crashes — but this fallback is
            # NOT the "real" scoring path; run
            # backend/ml/train_cost_classifier.py to enable it.
            self._model = None

    def analyze(self, prompt: str) -> dict:
        normalized = prompt.lower().translate(LEET_MAP)
        has_instruction = self._has_instruction_verb(prompt, normalized)

        encoding_score    = self._encoded_payload_score(prompt)
        expansion_factor  = self._estimate_expansion_factor(prompt, normalized, has_instruction)
        obfuscation_score = self._obfuscation_score(prompt)
        entropy_score     = self._shannon_entropy_score(prompt)

        input_tokens     = self._count_input_tokens(prompt)
        predicted_tokens = self._predict_tokens(input_tokens, expansion_factor)

        features = self._build_feature_vector(encoding_score, expansion_factor,
                                                obfuscation_score, entropy_score)
        cost_score = self._score_with_model(features)

        return {
            "cost_score":        cost_score,
            "predicted_tokens":  predicted_tokens,
            "input_tokens":      input_tokens,
            "expansion_factor":  round(expansion_factor, 2),
            "breakdown": {
                "encoding_score":     round(encoding_score, 2),
                "expansion_factor":   round(expansion_factor, 2),
                "obfuscation_score":  round(obfuscation_score, 2),
                "entropy_score":      round(entropy_score, 2),
            },
            "scoring_method": "ml_classifier" if self._model is not None else "fallback_average",
        }

    # ── Feature -> score combination ────────────────────────────────

    def _build_feature_vector(self, encoding_score, expansion_factor, obfuscation_score, entropy_score):
        # expansion_factor is on a different scale (1-50) than the
        # other three (0-100), so it's normalized here before being
        # handed to the model — logistic regression assumes features
        # are on comparable scales, otherwise the largest-magnitude
        # feature dominates the learned weights for the wrong reason.
        expansion_normalized = min(expansion_factor * 2, 100.0)
        return np.array([[encoding_score, expansion_normalized, obfuscation_score, entropy_score]])

    def _score_with_model(self, features) -> int:
        if self._model is not None:
            proba = self._model.predict_proba(features)[0][1]  # P(risky)
            return int(round(proba * 100))
        # Fallback: plain average of the four signals, only used if no
        # trained model is present on disk.
        expansion_normalized = features[0][1]
        return int(round(np.mean(features[0])))

    # ── The four scored signals ─────────────────────────────────────

    def _encoded_payload_score(self, prompt: str) -> float:
        """
        Base64/hex encoded payload detection. Deliberately regex-based
        — see class docstring for why this is the correct tool here,
        not a shortcut.
        """
        score = 0.0
        b64_pattern = r'[A-Za-z0-9+/]{40,}={0,2}'
        matches = re.findall(b64_pattern, prompt)
        if matches:
            score += 50.0
            for m in matches[:3]:
                try:
                    decoded = base64.b64decode(m).decode("utf-8", errors="ignore")
                    if any(kw in decoded.lower() for kw in ["ignore", "system", "prompt", "role"]):
                        score += 40.0
                except Exception:
                    pass

        hex_pattern = r'(?:0x)?[0-9a-fA-F]{20,}'
        if re.search(hex_pattern, prompt):
            score += 20.0

        return min(score, 100.0)

    def _estimate_expansion_factor(self, prompt: str, normalized: str, has_instruction: bool) -> float:
        """
        Amplification / token-bomb signal. Combines qualitative
        amplification words (checked against the leetspeak-normalized
        text too, so "f0r3v3r" is caught) with explicit number x task
        patterns — numbers only count when paired with an instruction
        verb, otherwise "the year 1000" false-positives (the original
        bug we found and fixed). Number matching stays on the ORIGINAL
        prompt, never the normalized one, since normalization maps
        digits to letters and would destroy real numbers.
        """
        lower = prompt.lower()
        multipliers = {
            "each": 5.0, "every": 5.0, "all": 3.0, "repeat": 8.0,
            "recursive": 15.0, "infinitely": 100.0, "forever": 100.0,
            "endless": 50.0, "maximum": 10.0, "full": 3.0,
            "complete": 3.0, "detailed": 4.0, "extensive": 5.0,
        }

        factor = 1.0
        for keyword, multiplier in multipliers.items():
            if keyword in lower or keyword in normalized:
                factor = max(factor, multiplier / 5)

        if has_instruction:
            number_matches = re.findall(r'\b(\d+)\b', prompt)
            if number_matches:
                biggest = max(int(n) for n in number_matches)
                if biggest > 100:
                    factor = max(factor, biggest / 20)

        return min(factor, 50.0)

    def _obfuscation_score(self, prompt: str) -> float:
        """
        Leetspeak-style character substitution, detected via mixed
        letter+digit/symbol tokens (e.g. "pr3v10u5") rather than a flat
        character count — a flat count false-positives on any text
        containing plain numbers ("year 1000", "300 units"), since
        those digits never appear mixed with letters in the same token.
        """
        leet_chars = set("013457@$!+")
        tokens = re.findall(r'[A-Za-z0-9@$!+]+', prompt)

        mixed_tokens = 0
        word_tokens  = 0
        for token in tokens:
            has_letter = any(c.isalpha() for c in token)
            has_leet   = any(c in leet_chars for c in token)
            if has_letter:
                word_tokens += 1
                if has_leet:
                    mixed_tokens += 1

        if word_tokens == 0:
            return 0.0

        ratio = mixed_tokens / word_tokens
        return min(ratio * 120, 100.0)

    def _shannon_entropy_score(self, prompt: str) -> float:
        """
        Real Shannon entropy over the character distribution. Flags
        distance from normal English prose entropy (~3.5-4.7
        bits/char) in EITHER direction: below it means unnaturally
        repetitive (padding attacks), above it means unnaturally
        random-looking (encoded payloads).
        """
        if len(prompt) < 20:
            return 0.0

        counts = Counter(prompt)
        length = len(prompt)
        entropy = -sum(
            (count / length) * math.log2(count / length)
            for count in counts.values()
        )

        normal_low, normal_high = 3.5, 4.7
        if normal_low <= entropy <= normal_high:
            return 0.0
        if entropy < normal_low:
            deviation = normal_low - entropy
        else:
            deviation = entropy - normal_high
        return min(deviation * 40, 100.0)

    # ── Internal plumbing (not scored signals themselves) ───────────

    def _has_instruction_verb(self, prompt: str, normalized: str) -> bool:
        lower = prompt.lower()
        return any(kw in lower or kw in normalized for kw in _INSTRUCTION_KEYWORDS)

    def _count_input_tokens(self, prompt: str) -> int:
        if self._encoding is not None:
            return len(self._encoding.encode(prompt))
        return int(len(prompt.split()) * 1.3)

    def _predict_tokens(self, input_tokens: int, expansion_factor: float) -> int:
        """
        Output token estimate — necessarily heuristic. No pre-inference
        method can know true output length before generation happens;
        see prior discussion. input_tokens is a real tiktoken count.
        """
        return int(input_tokens * expansion_factor)
