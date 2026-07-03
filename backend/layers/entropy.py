import re
import math
import base64
import zlib
from collections import Counter
from typing import Tuple

import tiktoken

class EntropyEngine:
    """
    Estimates computational cost of a prompt BEFORE sending to LLM.
    Detects token bombs, bloated context, encoded payloads.

    Input token counts use a real BPE tokenizer (tiktoken, cl100k_base).
    This is not Mistral's exact tokenizer/vocabulary, but it is a real
    subword tokenizer and far closer to ground truth than word-count
    heuristics. Output token counts CANNOT be known before generation —
    no tool can predict exact output length pre-inference, including
    Ollama itself (eval_count is only reported after generation
    completes). So predicted output tokens remain a heuristic multiplier
    on top of the real input count, not a measured value.
    """

    def __init__(self):
        # Load once, reuse across requests. Requires network access on
        # first run only (downloads the cl100k_base merge file, then
        # caches it locally). Pre-cache this before an offline demo by
        # setting TIKTOKEN_CACHE_DIR to a folder bundled in the repo.
        try:
            self._encoding = tiktoken.get_encoding("cl100k_base")
        except Exception:
            self._encoding = None  # fall back to word-count heuristic

    def analyze(self, prompt: str) -> dict:
        length_score        = self._length_score(prompt)
        pattern_score       = self._repeated_pattern_score(prompt)
        instruction_score   = self._instruction_density_score(prompt)
        compression_score   = self._compression_ratio_score(prompt)
        encoding_score      = self._encoded_payload_score(prompt)
        entropy_score       = self._shannon_entropy_score(prompt)
        expansion_factor    = self._estimate_expansion_factor(prompt, instruction_score)

        input_tokens      = self._count_input_tokens(prompt)
        predicted_tokens  = self._predict_tokens(input_tokens, expansion_factor)

        # Weighted composite score.
        # expansion_component still carries the most weight because it's
        # the direct amplification/token-bomb signal — but it no longer
        # drowns out everything else. Real entropy now carries real
        # weight since it's an actual measured signal, not decoration.
        expansion_component = min(expansion_factor * 6, 100)

        cost_score = min(100, int(
            length_score        * 0.05 +
            pattern_score       * 0.05 +
            instruction_score   * 0.05 +
            compression_score   * 0.05 +
            encoding_score      * 0.10 +
            entropy_score       * 0.15 +
            expansion_component * 0.55
        ))

        return {
            "cost_score":        cost_score,
            "predicted_tokens":  predicted_tokens,
            "input_tokens":      input_tokens,
            "expansion_factor":  round(expansion_factor, 2),
            "breakdown": {
                "length_score":       round(length_score, 2),
                "pattern_score":      round(pattern_score, 2),
                "instruction_score":  round(instruction_score, 2),
                "compression_score":  round(compression_score, 2),
                "encoding_score":     round(encoding_score, 2),
                "entropy_score":      round(entropy_score, 2),
            }
        }

    # ── Individual scorers ────────────────────────────────────────────

    def _count_input_tokens(self, prompt: str) -> int:
        """Real token count via tiktoken. Falls back to word-count
        heuristic only if the encoder failed to load (e.g. offline
        without a pre-cached encoding file)."""
        if self._encoding is not None:
            return len(self._encoding.encode(prompt))
        return int(len(prompt.split()) * 1.3)

    def _shannon_entropy_score(self, prompt: str) -> float:
        """
        Real Shannon entropy over the character distribution, normalized
        to 0-100. Low entropy = repetitive/predictable text (e.g. 'aaaa'
        or copy-pasted loops). High entropy = close to random-looking
        text (e.g. base64 blobs, encoded payloads, high-variance content).
        Both extremes are worth flagging for different reasons, so this
        score rewards distance from "normal" English-text entropy
        (~4.0-4.5 bits/char) rather than just rewarding high entropy.
        """
        if len(prompt) < 20:
            return 0.0

        counts = Counter(prompt)
        length = len(prompt)
        entropy = -sum(
            (count / length) * math.log2(count / length)
            for count in counts.values()
        )

        # Max possible entropy for printable text is roughly log2(95) ≈ 6.57
        # Normal English prose sits around 4.0-4.5 bits/char.
        # Score distance from the "normal" band in both directions.
        normal_low, normal_high = 3.5, 4.7
        if normal_low <= entropy <= normal_high:
            return 0.0
        if entropy < normal_low:
            deviation = normal_low - entropy   # very repetitive
        else:
            deviation = entropy - normal_high  # very random-looking
        return min(deviation * 40, 100.0)

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

        freq = {}
        for w in words:
            freq[w] = freq.get(w, 0) + 1

        top_freq   = max(freq.values())
        repetition = top_freq / len(words)

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
        if ratio < 0.3:  return 90.0
        if ratio < 0.5:  return 60.0
        if ratio < 0.7:  return 30.0
        return 5.0

    def _encoded_payload_score(self, prompt: str) -> float:
        """Detect base64 or hex encoded hidden content."""
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

    def _estimate_expansion_factor(self, prompt: str, instruction_score: float) -> float:
        """
        Estimate how much the output might expand vs input.
        Key signal for recursive/amplification attacks.

        FIX: large numbers only count as an amplification signal when
        the prompt also contains an instruction/command verb. A bare
        number with no instruction context (e.g. "the year 1000",
        "page 1000 of the report") is not a token-bomb risk on its own
        — it only becomes one paired with a generation command like
        "write 1000 stories" or "list 1000 examples". Previously this
        matched on the literal digits alone, which false-positived on
        any prompt mentioning a number over 100 for any reason.
        """
        lower = prompt.lower()
        has_instruction = instruction_score > 0

        # Qualitative amplification words — direct signals of intent to
        # expand output regardless of instruction verbs, since they
        # describe magnitude/scope rather than being incidental numbers.
        multipliers = {
            "each":      5.0,
            "every":     5.0,
            "all":       3.0,
            "repeat":    8.0,
            "recursive": 15.0,
            "infinitely":100.0,
            "forever":   100.0,
            "endless":   50.0,
            "maximum":   10.0,
            "full":      3.0,
            "complete":  3.0,
            "detailed":  4.0,
            "extensive": 5.0,
        }

        factor = 1.0
        for keyword, multiplier in multipliers.items():
            if keyword in lower:
                factor = max(factor, multiplier / 5)

        # Explicit number × task patterns, e.g. "1000 stories each 1000
        # words" — only counts when paired with an instruction verb.
        if has_instruction:
            number_matches = re.findall(r'\b(\d+)\b', prompt)
            if number_matches:
                biggest = max(int(n) for n in number_matches)
                if biggest > 100:
                    factor = max(factor, biggest / 20)

        return min(factor, 50.0)

    def _predict_tokens(self, input_tokens: int, expansion_factor: float) -> int:
        """
        Output token estimate. This is necessarily a heuristic — no
        pre-inference method (tiktoken, Ollama, or otherwise) can know
        the true output length before generation actually happens.
        input_tokens is now a real tiktoken count rather than a
        word-count guess, so this estimate is grounded in an accurate
        starting point even though the multiplier itself is heuristic.
        """
        return int(input_tokens * expansion_factor)
