"""
Layer 3: ML Risk Engine — Rule Detectors + Vector/Cosine Similarity
Runs TWO detectors together, same as TwinShield's real
RiskAnalysisEngine.analyze() (minus Lakera, which lives in Layer 5
here per your layer split):

  1. Regex rule detectors (layer3_rule_detectors.py) — fast, offline,
     exact/near-exact phrasing. Direct port of risk.py's 8 _detect_*
     methods.
  2. Semantic/embedding detector (below) — offline via Ollama, catches
     paraphrases the regex list misses. Direct port of
     semantic_similarity.py.

risk_flags = union of both detectors' flags. risk_score = max(rule_score,
semantic_score), matching your original's "most confident detector wins"
design rather than stacking scores that would double-count the same
threat caught by more than one path.

Block condition ported from your real main.py: `risk_score >= 18 and
is_suspicious` (on a 0-100 scale) — which in practice means ANY single
rule flag (rule_score=18) or ANY semantic match above the 0.80 threshold
triggers an immediate MALICIOUS verdict. This is intentionally more
decisive than Layer 2/4's continuous ML scores: a confirmed regex/semantic
match is treated as confirmed, not merely "elevated risk".
"""
import asyncio
import logging
from typing import Dict, List, Optional

import httpx
import numpy as np

from config import (
    OLLAMA_HOST, OLLAMA_EMBED_MODEL, SEMANTIC_SIMILARITY_THRESHOLD, SEMANTIC_FALLBACK_TFIDF,
)
from ml.semantic_exemplars import EXEMPLAR_BANK
import layer3_rule_detectors as rules

logger = logging.getLogger("twinshield.semantic")

_exemplar_embeddings: Optional[Dict[str, List[np.ndarray]]] = None
_init_lock = asyncio.Lock()

# TF-IDF fallback state (only built/used if SEMANTIC_FALLBACK_TFIDF=true
# and Ollama is unreachable)
_tfidf_vectorizer = None
_tfidf_category_vecs = None


async def _embed(text: str) -> np.ndarray:
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(
            f"{OLLAMA_HOST}/api/embeddings",
            json={"model": OLLAMA_EMBED_MODEL, "prompt": text},
        )
        response.raise_for_status()
        data = response.json()
    vec = np.array(data["embedding"], dtype=np.float64)
    norm = np.linalg.norm(vec)
    return vec / norm if norm > 0 else vec


def _cosine_sim(a: np.ndarray, b: np.ndarray) -> float:
    # a and b are already unit-normalized in _embed, so dot product IS
    # the cosine similarity — no need to divide by norms again.
    return float(np.dot(a, b))


async def _ensure_exemplars_loaded():
    global _exemplar_embeddings
    if _exemplar_embeddings is not None:
        return
    async with _init_lock:
        if _exemplar_embeddings is not None:
            return
        embeddings: Dict[str, List[np.ndarray]] = {}
        for category, phrases in EXEMPLAR_BANK.items():
            embeddings[category] = [await _embed(p) for p in phrases]
        _exemplar_embeddings = embeddings


def _build_tfidf_fallback():
    """Only built the first time Ollama is found unreachable and the
    fallback is enabled — lazily, so it costs nothing when unused."""
    global _tfidf_vectorizer, _tfidf_category_vecs
    from sklearn.feature_extraction.text import TfidfVectorizer

    corpus = []
    category_ranges = {}
    for category, phrases in EXEMPLAR_BANK.items():
        start = len(corpus)
        corpus.extend(phrases)
        category_ranges[category] = (start, len(corpus))

    _tfidf_vectorizer = TfidfVectorizer(ngram_range=(1, 2), min_df=1)
    all_vecs = _tfidf_vectorizer.fit_transform(corpus)
    _tfidf_category_vecs = {
        category: all_vecs[start:end] for category, (start, end) in category_ranges.items()
    }


def _tfidf_analyze(prompt: str) -> dict:
    from sklearn.metrics.pairwise import cosine_similarity

    if _tfidf_vectorizer is None:
        _build_tfidf_fallback()

    query_vec = _tfidf_vectorizer.transform([prompt])
    flags: List[str] = []
    matches: List[dict] = []
    overall_max = 0.0

    for category, cat_vecs in _tfidf_category_vecs.items():
        best = float(cosine_similarity(query_vec, cat_vecs).max())
        overall_max = max(overall_max, best)
        if best >= SEMANTIC_SIMILARITY_THRESHOLD:
            flags.append(category)
            matches.append({"category": category, "similarity": round(best, 4)})

    return {
        "semantic_flags": flags, "semantic_matches": matches,
        "max_similarity": round(overall_max, 4), "backend": "tfidf_fallback",
    }


async def semantic_similarity_analyze(prompt: str) -> dict:
    """Direct port of SemanticSimilarityDetector.analyze()."""
    try:
        await _ensure_exemplars_loaded()
        prompt_vec = await _embed(prompt)
    except Exception as e:
        logger.warning(f"semantic similarity detector unavailable: {e}")
        if SEMANTIC_FALLBACK_TFIDF:
            logger.warning("falling back to offline TF-IDF approximation (SEMANTIC_FALLBACK_TFIDF=true)")
            return _tfidf_analyze(prompt)
        return {"semantic_flags": [], "semantic_matches": [], "max_similarity": 0.0, "backend": "ollama:unavailable"}

    flags: List[str] = []
    matches: List[dict] = []
    overall_max = 0.0

    for category, exemplar_vecs in _exemplar_embeddings.items():
        best = max(_cosine_sim(prompt_vec, ev) for ev in exemplar_vecs)
        overall_max = max(overall_max, best)
        if best >= SEMANTIC_SIMILARITY_THRESHOLD:
            flags.append(category)
            matches.append({"category": category, "similarity": round(best, 4)})

    return {
        "semantic_flags": flags, "semantic_matches": matches,
        "max_similarity": round(overall_max, 4), "backend": f"ollama:{OLLAMA_EMBED_MODEL}",
    }


async def semantic_risk_scan(payload: str) -> dict:
    """Adapter for main.py's pipeline: combines regex rule detectors and
    the semantic detector exactly like your real RiskAnalysisEngine.analyze(),
    minus Lakera (Layer 5 here). Runs the semantic (network) call and the
    regex (local, cheap) check concurrently-in-spirit — regex is sync so
    it just runs first, then semantic is awaited."""
    rule_flags = rules.analyze_local(payload)
    rule_score = min(len(rule_flags) * 18, 100) / 100.0  # 0-100 scale -> 0-1

    semantic_result = await semantic_similarity_analyze(payload)
    semantic_flags = semantic_result["semantic_flags"]
    max_sim = semantic_result["max_similarity"]
    semantic_score = max_sim if semantic_flags else 0.0

    risk_flags = list(set(rule_flags + semantic_flags))
    risk_score = max(rule_score, semantic_score)
    is_suspicious = len(risk_flags) > 0

    # Ported block condition from your real main.py:
    # `if risk_result["risk_score"] >= 18 and risk_result["is_suspicious"]`
    # (0-100 scale) => on our 0-1 scale, >= 0.18 and is_suspicious. In
    # practice this means any single rule flag or semantic match is
    # enough — a confirmed detection, not just "elevated".
    if risk_score >= 0.18 and is_suspicious:
        label = "MALICIOUS"
    elif is_suspicious:
        label = "SUSPICIOUS"
    else:
        label = "SAFE"

    return {
        "score": risk_score,
        "label": label,
        "reason": (
            f"risk_score={risk_score:.3f} rule_flags={rule_flags or 'none'} "
            f"semantic_flags={semantic_flags or 'none'} (backend={semantic_result['backend']})"
        ),
        "details": {
            "risk_flags": risk_flags,
            "rule_flags": rule_flags,
            "rule_score": rule_score,
            "semantic_flags": semantic_flags,
            "semantic_matches": semantic_result["semantic_matches"],
            "semantic_score": semantic_score,
            "max_similarity": max_sim,
            "backend": semantic_result["backend"],
        },
    }
