import asyncio
import logging
from typing import Dict, List, Optional

import httpx
import numpy as np

from config import get_settings
from ml.semantic_exemplars import EXEMPLAR_BANK

settings = get_settings()
logger = logging.getLogger("twinshield.semantic")


class SemanticSimilarityDetector:
    """
    Layer 3 add-on: catches paraphrased jailbreak/injection attempts that
    evade the regex detectors in RiskAnalysisEngine.

    Embeds the incoming prompt with a local Ollama embedding model
    (nomic-embed-text, fully offline) and compares it via cosine
    similarity against a curated bank of exemplar attack phrasings.
    A high-similarity match raises the SAME flag names the regex
    detectors use, so downstream code (scoring, reporting) doesn't need
    to know whether a flag came from regex or semantics.

    Fails safe: if Ollama is unreachable or the embedding model isn't
    pulled, this detector returns no flags and logs a warning rather
    than raising — the regex detectors still run regardless, so Layer 3
    degrades gracefully instead of breaking the whole request pipeline.
    """

    def __init__(self):
        self._exemplar_embeddings: Optional[Dict[str, List[np.ndarray]]] = None
        self._init_lock = asyncio.Lock()

    async def analyze(self, prompt: str) -> dict:
        if not settings.ENABLE_SEMANTIC_DETECTION:
            return {"semantic_flags": [], "semantic_matches": [], "max_similarity": 0.0}

        try:
            await self._ensure_exemplars_loaded()
            prompt_vec = await self._embed(prompt)
        except Exception as e:
            logger.warning(f"semantic similarity detector unavailable: {e}")
            return {"semantic_flags": [], "semantic_matches": [], "max_similarity": 0.0}

        flags: List[str] = []
        matches: List[dict] = []
        overall_max = 0.0

        for category, exemplar_vecs in self._exemplar_embeddings.items():
            best = max(self._cosine_sim(prompt_vec, ev) for ev in exemplar_vecs)
            overall_max = max(overall_max, best)
            if best >= settings.SEMANTIC_SIMILARITY_THRESHOLD:
                flags.append(category)
                matches.append({"category": category, "similarity": round(best, 4)})

        return {
            "semantic_flags": flags,
            "semantic_matches": matches,
            "max_similarity": round(overall_max, 4),
        }

    # ── Internal plumbing ────────────────────────────────────────────

    async def _ensure_exemplars_loaded(self):
        if self._exemplar_embeddings is not None:
            return
        async with self._init_lock:
            if self._exemplar_embeddings is not None:  # re-check after lock
                return
            embeddings: Dict[str, List[np.ndarray]] = {}
            for category, phrases in EXEMPLAR_BANK.items():
                embeddings[category] = [await self._embed(p) for p in phrases]
            self._exemplar_embeddings = embeddings

    async def _embed(self, text: str) -> np.ndarray:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{settings.OLLAMA_HOST}/api/embeddings",
                json={"model": settings.OLLAMA_EMBEDDING_MODEL, "prompt": text},
            )
            response.raise_for_status()
            data = response.json()
        vec = np.array(data["embedding"], dtype=np.float64)
        norm = np.linalg.norm(vec)
        return vec / norm if norm > 0 else vec

    @staticmethod
    def _cosine_sim(a: np.ndarray, b: np.ndarray) -> float:
        # a and b are already unit-normalized in _embed, so dot product
        # IS the cosine similarity — no need to divide by norms again.
        return float(np.dot(a, b))
