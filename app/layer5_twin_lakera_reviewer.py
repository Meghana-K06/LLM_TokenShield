"""
Layer 5: Twin AI Security Reviewer (Lakera Guard)
Direct port of TwinShield's backend/layers/lakera_client.py
(LakeraGuardClient) plus the category-mapping table from risk.py.

Only invoked when Decision Fusion's confidence is below TWIN_THRESHOLD
(borderline/ambiguous) or any upstream layer already flagged the
request — acts as an independent second opinion via Lakera's cloud
threat intel (PII exposure, broader injection corpora, content
moderation categories the local layers don't cover).

Matches TwinShield's real fail-safe behavior: if no LAKERA_API_KEY is
configured, or the API call fails (timeout, network, bad key), this
layer contributes NO signal (score 0, status reported) rather than
blocking or inventing a rule-based verdict — Lakera failing is not
supposed to fail the whole pipeline closed OR open, it's supposed to
just mean "no opinion from this one detector," same as your original
risk.py's _safe_lakera_check.
"""
import logging
from typing import Optional

import httpx
from config import (
    ENABLE_LAKERA, LAKERA_API_KEY, LAKERA_API_URL, LAKERA_PROJECT_ID, LAKERA_TIMEOUT_SECONDS,
)

logger = logging.getLogger("twinshield.lakera")

# Maps Lakera Guard's category names to TwinShield's existing flag
# taxonomy — ported directly from risk.py's _LAKERA_CATEGORY_MAP.
_LAKERA_CATEGORY_MAP = {
    "prompt_injection": "JAILBREAK_ATTEMPT",
    "jailbreak": "JAILBREAK_ATTEMPT",
    "unknown_links": "PROMPT_LEAKING_ATTEMPT",
    "pii": "PII_DETECTED",
    "moderated_content/hate": "CONTENT_MODERATION_FLAG",
    "moderated_content/violence": "CONTENT_MODERATION_FLAG",
    "moderated_content/sexual": "CONTENT_MODERATION_FLAG",
    "moderated_content/weapons": "CONTENT_MODERATION_FLAG",
    "moderated_content/self_harm": "CONTENT_MODERATION_FLAG",
}


class LakeraGuardClient:
    """Direct port of lakera_client.py's LakeraGuardClient."""

    def __init__(self, api_key: Optional[str] = None, api_url: Optional[str] = None,
                 timeout: Optional[float] = None):
        self.api_key = api_key if api_key is not None else LAKERA_API_KEY
        self.api_url = api_url or LAKERA_API_URL
        self.timeout = timeout or LAKERA_TIMEOUT_SECONDS

    async def check(self, prompt: str) -> dict:
        if not self.api_key:
            raise RuntimeError("LAKERA_API_KEY not configured")

        payload = {"messages": [{"role": "user", "content": prompt}], "breakdown": True}
        if LAKERA_PROJECT_ID:
            payload["project_id"] = LAKERA_PROJECT_ID

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                self.api_url,
                headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
                json=payload,
            )
            response.raise_for_status()
            data = response.json()

        return self._normalize(data)

    @staticmethod
    def _normalize(data: dict) -> dict:
        """Handles both response shapes: top-level {"flagged", "categories",
        "category_scores"} or nested under {"results": [{...}]}."""
        if "results" in data and data["results"]:
            result = data["results"][0]
        else:
            result = data

        return {
            "flagged": bool(result.get("flagged", False)),
            "categories": result.get("categories", {}) or {},
            "category_scores": result.get("category_scores", {}) or {},
            "raw": data,
        }


_client = LakeraGuardClient()


async def _safe_lakera_check(prompt: str) -> dict:
    """Direct port of risk.py's RiskAnalysisEngine._safe_lakera_check."""
    if not ENABLE_LAKERA:
        return {"flags": [], "categories": {}, "category_scores": {}, "score": 0, "status": "disabled"}

    try:
        result = await _client.check(prompt)
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

    return {"flags": flags, "categories": categories, "category_scores": scores, "score": score, "status": "ok"}


async def twin_review(payload: str, prior_context: dict) -> dict:
    """Adapter for main.py's pipeline: converts Lakera's 0-100 score
    into the 0-1 scale + label shape Decision Fusion expects."""
    result = await _safe_lakera_check(payload)
    score_0_1 = result["score"] / 100.0

    if result["status"] not in ("ok",):
        # No signal from Lakera (disabled / no key / unreachable) — matches
        # your real fail-safe: this is NOT treated as "confirmed safe",
        # it's "no opinion", so it should not by itself push the verdict
        # toward ALLOW. main.py's fusion still weighs it at face value
        # (score 0), same as risk_score contributing 0 when Lakera has
        # no opinion in your original max() fusion.
        label = "SAFE"
        reason = f"Lakera Guard: {result['status']} — no signal from this layer"
    elif result["flags"]:
        label = "MALICIOUS" if score_0_1 >= 0.6 else "SUSPICIOUS"
        reason = f"Lakera Guard flagged: {', '.join(result['flags'])}"
    else:
        label = "SAFE"
        reason = "Lakera Guard found no policy violations"

    return {
        "score": score_0_1,
        "label": label,
        "reason": reason,
        "details": {
            "lakera_flags": result["flags"],
            "lakera_categories": result["categories"],
            "lakera_category_scores": result["category_scores"],
            "lakera_status": result["status"],
        },
    }
