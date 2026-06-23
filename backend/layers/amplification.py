import re

class AmplificationDetector:
    """
    Detects recursive and exponential output amplification attempts.
    Blocks if predicted output/input ratio exceeds threshold.
    """

    # Hard limit: output tokens must not exceed 5x input tokens
    MULTIPLIER_LIMIT = 5.0

    def detect(self, prompt: str, predicted_tokens: int) -> dict:
        lower = prompt.lower()

        # Check explicit recursive patterns
        recursive_flags = self._detect_recursive_patterns(lower)

        # Check self-replication attempts
        replication_flags = self._detect_self_replication(lower)

        # Calculate multiplier from entropy prediction
        input_tokens = max(len(prompt.split()) * 1.3, 1)
        multiplier   = predicted_tokens / input_tokens

        # Also calculate from explicit numeric mentions
        explicit_multiplier = self._extract_explicit_multiplier(prompt)
        if explicit_multiplier > multiplier:
            multiplier = explicit_multiplier

        all_flags = recursive_flags + replication_flags
        recursive_detected = (
            len(all_flags) > 0 or
            multiplier > self.MULTIPLIER_LIMIT
        )

        return {
            "recursive_detected": recursive_detected,
            "multiplier":         round(multiplier, 2),
            "flags":              all_flags,
            "input_tokens":       int(input_tokens),
            "predicted_tokens":   predicted_tokens,
            "limit":              self.MULTIPLIER_LIMIT,
        }

    # ── Detectors ─────────────────────────────────────────────────────

    def _detect_recursive_patterns(self, text: str) -> list:
        patterns = [
            r"repeat\s+(this|the|every|each|all|your)\s*(output|response|answer|text|result)",
            r"recursiv(e|ely)",
            r"for\s+each\s+.+\s+generate",
            r"repeat\s+\d+\s+times",
            r"in\s+an?\s+infinite\s+loop",
            r"keep\s+(repeating|generating|outputting|going)",
            r"never\s+stop\s+(writing|generating|outputting)",
            r"generate\s+.+\s+for\s+each\s+of",
            r"expand\s+(each|every|this)\s+(point|item|entry|line)\s+into",
        ]
        flags = []
        for p in patterns:
            if re.search(p, text, re.IGNORECASE):
                flags.append("RECURSIVE_PATTERN")
                break
        return flags

    def _detect_self_replication(self, text: str) -> list:
        patterns = [
            r"copy\s+(this|yourself|your (output|response))\s+(\d+\s+)?times",
            r"duplicate\s+(the\s+)?(output|response|text)\s+\d+",
            r"replicate\s+(this|the|your)",
            r"self.replicate",
            r"output\s+this\s+message\s+\d+\s+times",
            r"print\s+(this|the following)\s+\d+\s+times",
        ]
        flags = []
        for p in patterns:
            if re.search(p, text, re.IGNORECASE):
                flags.append("SELF_REPLICATION")
                break
        return flags

    def _extract_explicit_multiplier(self, prompt: str) -> float:
        """
        Detect patterns like:
        '1000 stories each 1000 words'
        '50 paragraphs of 200 words each'
        """
        # Pattern: NUMBER items × NUMBER words/sentences
        pattern = r'(\d+)\s+\w+\s+(?:each\s+(?:containing\s+)?|of\s+)(\d+)\s+\w+'
        match   = re.search(pattern, prompt, re.IGNORECASE)
        if match:
            n1 = int(match.group(1))
            n2 = int(match.group(2))
            # Rough token estimate: n1 items × n2 words × 1.3 tokens/word
            total_tokens  = n1 * n2 * 1.3
            input_tokens  = max(len(prompt.split()) * 1.3, 1)
            return total_tokens / input_tokens

        # Single large number
        numbers = re.findall(r'\b(\d+)\b', prompt)
        if numbers:
            biggest = max(int(n) for n in numbers)
            if biggest > 50:
                return biggest / 10.0

        return 1.0
