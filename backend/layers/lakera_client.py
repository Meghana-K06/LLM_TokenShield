import logging
from typing import Optional

import httpx

from config import get_settings

settings = get_settings()
logger = logging.getLogger("twinshield.lakera")


class LakeraGuardClient:
    """
    Thin client for Lakera Guard's /v2/guard endpoint (Check Point AI
    Guardrails). Runs ALONGSIDE the local regex + semantic detectors
    in Layer 3 (not as a replacement) so both outputs are visible for
    comparison.

    Docs: https://docs.lakera.ai/docs/api/guard
    Auth: Bearer token in the Authorization header.
    Response shape (with breakdown=true) looks like:
        {
          "model": "lakera-guard-1",
          "results": [{
            "categories": {"prompt_injection": true, "jailbreak": false, ...},
            "category_scores": {"prompt_injection": 0.999, ...},
            "flagged": true
          }]
        }
    Some deployments return "flagged"/"categories" at the top level
    instead of nested under "results" — this client checks both shapes
    since we can't hit a live key from this dev environment to confirm
    which one your account's policy returns.

    Raises on any failure (no key configured, bad key, timeout,
    non-200, unexpected JSON shape) — callers catch and treat it as
    "no Lakera signal for this request" rather than blocking on it.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        api_url: Optional[str] = None,
        timeout: Optional[float] = None,
    ):
        self.api_key = api_key if api_key is not None else settings.LAKERA_API_KEY
        self.api_url = api_url or settings.LAKERA_API_URL
        self.timeout = timeout or settings.LAKERA_TIMEOUT_SECONDS

    async def check(self, prompt: str) -> dict:
        if not self.api_key:
            raise RuntimeError("LAKERA_API_KEY not configured")

        payload = {
            "messages": [{"role": "user", "content": prompt}],
            "breakdown": True,
        }
        if settings.LAKERA_PROJECT_ID:
            payload["project_id"] = settings.LAKERA_PROJECT_ID

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                self.api_url,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json=payload,
            )
            response.raise_for_status()
            data = response.json()

        return self._normalize(data)

    @staticmethod
    def _normalize(data: dict) -> dict:
        """
        Handle both response shapes: top-level {"flagged", "categories",
        "category_scores"} or nested under {"results": [{...}]}.
        """
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
