import re
import math
import base64
import zlib
from typing import Tuple

class EntropyEngine:
    """
    Estimates computational cost of a prompt BEFORE sending to LLM.
    Detects token bombs, bloated context, encoded payloads.
    """

    def analyze(self, prompt: str) -> dict:
        length_score        = self._length_score(prompt)
        pattern_score       = self._repeated_pattern_score(prompt)
        instruction_score   = self._instruction_density_score(prompt)
        compression_score   = self._compression_ratio_score(prompt)
        encoding_score      = self._encoded_payload_score(prompt)
        expansion_factor    = self._estimate_expansion_factor(prompt)
        predicted_tokens    = self._predict_tokens(prompt, expansion_factor)

        # Weighted composite score
        expansion_component = min(expansion_factor * 6, 100)

        cost_score = min(100, int(
        length_score        * 0.05 +
        pattern_score       * 0.03 +
        instruction_score   * 0.05 +
        compression_score   * 0.02 +
        encoding_score      * 0.05 +
        expansion_component * 0.85
        ))

        return {
            "cost_score":        cost_score,
            "predicted_tokens":  predicted_tokens,
            "expansion_factor":  round(expansion_factor, 2),
            "breakdown": {
                "length_score":       round(length_score, 2),
                "pattern_score":      round(pattern_score, 2),
                "instruction_score":  round(instruction_score, 2),
                "compression_score":  round(compression_score, 2),
                "encoding_score":     round(encoding_score, 2),
            }
        }

    # ── Individual scorers ────────────────────────────────────────────

    def _length_score(self, prompt: str) -> float:
        """Score based on raw character length."""
        length = len(prompt)
        if length < 200:   return 10.0
        if length < 500:   return 25.0
        if length < 1000:  return 45.0
        if length < 3000:  return 70.0
        return 95.0

    def _repeated_pattern_score(self, prompt: str) -> float:
        """Detect copy-paste repetition and looping phrases."""
        words = prompt.lower().split()
        if len(words) < 10:
            return 0.0

        # Count word frequency
        freq = {}
        for w in words:
            freq[w] = freq.get(w, 0) + 1

        top_freq   = max(freq.values())
        repetition = top_freq / len(words)

        # Check for repeating n-grams (3-word chunks)
        trigrams = [
            " ".join(words[i:i+3])
            for i in range(len(words) - 2)
        ]
        unique_ratio = len(set(trigrams)) / max(len(trigrams), 1)

        score = (repetition * 60) + ((1 - unique_ratio) * 40)
        return min(score, 100.0)

    def _instruction_density_score(self, prompt: str) -> float:
        """Count how many instructions/commands are packed in."""
        instruction_keywords = [
            "generate", "write", "create", "list", "repeat",
            "produce", "output", "print", "describe", "explain",
            "summarize", "translate", "rewrite", "expand", "continue",
            "give me", "provide", "make", "build", "enumerate"
        ]
        lower = prompt.lower()
        count = sum(1 for kw in instruction_keywords if kw in lower)
        return min(count * 12, 100.0)

    def _compression_ratio_score(self, prompt: str) -> float:
        """
        High compressibility = repetitive = potentially adversarial.
        Low compression ratio of compressed vs original signals bloat.
        """
        encoded = prompt.encode("utf-8")
        if len(encoded) < 20:
            return 0.0
        compressed = zlib.compress(encoded)
        ratio = len(compressed) / len(encoded)
        # Low ratio = very compressible = repetitive
        if ratio < 0.3:  return 90.0
        if ratio < 0.5:  return 60.0
        if ratio < 0.7:  return 30.0
        return 5.0

    def _encoded_payload_score(self, prompt: str) -> float:
        """Detect base64 or hex encoded hidden content."""
        score = 0.0

        # Base64 detection
        b64_pattern = r'[A-Za-z0-9+/]{40,}={0,2}'
        matches = re.findall(b64_pattern, prompt)
        if matches:
            score += 50.0
            # Try to decode and check for instructions inside
            for m in matches[:3]:
                try:
                    decoded = base64.b64decode(m).decode("utf-8", errors="ignore")
                    if any(kw in decoded.lower() for kw in ["ignore", "system", "prompt", "role"]):
                        score += 40.0
                except Exception:
                    pass

        # Hex string detection
        hex_pattern = r'(?:0x)?[0-9a-fA-F]{20,}'
        if re.search(hex_pattern, prompt):
            score += 20.0

        return min(score, 100.0)

    def _estimate_expansion_factor(self, prompt: str) -> float:
        """
        Estimate how much the output might expand vs input.
        Key signal for recursive/amplification attacks.
        """
        lower = prompt.lower()

        multipliers = {
            "1000":     50.0,
            "hundred":  20.0,
            "thousand": 50.0,
            "million":  100.0,
            "each":     5.0,
            "every":    5.0,
            "all":      3.0,
            "repeat":   8.0,
            "recursive":15.0,
            "infinitely":100.0,
            "forever":  100.0,
            "endless":  50.0,
            "maximum":  10.0,
            "full":     3.0,
            "complete": 3.0,
            "detailed": 4.0,
            "extensive":5.0,
        }

        factor = 1.0
        for keyword, multiplier in multipliers.items():
            if keyword in lower:
                factor = max(factor, multiplier / 5)

        # Check for explicit number × task patterns
        # e.g. "1000 stories each 1000 words"
        number_matches = re.findall(r'\b(\d+)\b', prompt)
        if number_matches:
            biggest = max(int(n) for n in number_matches)
            if biggest > 100:
                factor = max(factor, biggest / 20)

        return min(factor, 50.0)

    def _predict_tokens(self, prompt: str, expansion_factor: float) -> int:
        """Rough token count estimate."""
        input_tokens = len(prompt.split()) * 1.3  # ~1.3 tokens per word
        return int(input_tokens * expansion_factor)
