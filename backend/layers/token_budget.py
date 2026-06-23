from config import get_settings

settings = get_settings()

class TokenBudgetAllocator:
    """
    Allocates token budget based on risk score and trust score.
    Higher risk + lower trust = fewer tokens allowed.
    """

    def allocate(self, risk_score: float, trust_score: float) -> dict:
        # Determine risk tier
        risk_tier = self._risk_tier(risk_score)

        # Base allocation by risk
        base_tokens = {
            "low":    settings.TOKEN_BUDGET_LOW,    # 5000
            "medium": settings.TOKEN_BUDGET_MEDIUM, # 2000
            "high":   settings.TOKEN_BUDGET_HIGH,   # 500
        }[risk_tier]

        # Trust multiplier — trusted users get more headroom
        trust_multiplier = self._trust_multiplier(trust_score)
        allocated = int(base_tokens * trust_multiplier)

        # Hard caps
        allocated = max(100, min(allocated, 8000))

        return {
            "tokens_allocated": allocated,
            "risk_tier":        risk_tier,
            "trust_multiplier": trust_multiplier,
            "base_tokens":      base_tokens,
        }

    def _risk_tier(self, risk_score: float) -> str:
        if risk_score >= 60:  return "high"
        if risk_score >= 30:  return "medium"
        return "low"

    def _trust_multiplier(self, trust_score: float) -> float:
        """
        trusted    (>= 0.75) → 1.0x  (full allocation)
        authenticated (0.45-0.75) → 0.75x
        anonymous  (< 0.45)  → 0.50x
        """
        if trust_score >= 0.75: return 1.0
        if trust_score >= 0.45: return 0.75
        return 0.5
