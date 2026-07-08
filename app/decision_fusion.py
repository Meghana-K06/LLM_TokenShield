"""
Decision Fusion Engine
Combines the three independent signals (Layer 2 Entropy Defender,
Layer 3 Semantic Risk Engine, Layer 4 Reputation) into one fused
malicious-probability score, and computes a 'confidence' value = how
far that score sits from the uncertain 0.5 midpoint, weighted by how
much the three layers agree. Low confidence => escalate to Layer 5
(Lakera Twin Reviewer).

Also used a second time (with Layer 5's opinion folded in) to produce
the FINAL verdict.
"""
from config import WEIGHT_ENTROPY_DEFENDER, WEIGHT_SEMANTIC_RISK, WEIGHT_REPUTATION, BLOCK_THRESHOLD


def fuse_scores(entropy_score: float, semantic_score: float, reputation_score: float) -> dict:
    fused = (
        WEIGHT_ENTROPY_DEFENDER * entropy_score
        + WEIGHT_SEMANTIC_RISK * semantic_score
        + WEIGHT_REPUTATION * reputation_score
    )
    fused = max(0.0, min(1.0, fused))

    # Confidence must reflect AGREEMENT between layers, not just distance from 0.5.
    # A low fused score produced by one high layer averaged against two low layers
    # is disagreement, not certainty, and must not read as "confidently safe".
    scores = [entropy_score, semantic_score, reputation_score]
    spread = max(scores) - min(scores)
    distance_component = abs(fused - 0.5) * 2      # 0 = uncertain, 1 = certain, by position
    agreement_component = max(0.0, 1.0 - spread)   # 0 = layers disagree wildly, 1 = layers agree
    confidence = distance_component * agreement_component

    verdict = "BLOCK" if fused >= BLOCK_THRESHOLD else "ALLOW"

    return {
        "fused_score": fused,
        "confidence": confidence,
        "verdict": verdict,
    }


def fuse_with_twin(
    original_fused_score: float,
    twin_score: float,
    entropy_label: str = "SAFE",
    semantic_label: str = "SAFE",
    reputation_label: str = "SAFE",
    twin_label: str = "SAFE",
) -> dict:
    """
    Final fusion after the Layer 5 (Lakera Twin) review.

    Rules:
    1. Any MALICIOUS label => BLOCK immediately.
    2. Otherwise use the combined score.
    3. SUSPICIOUS labels increase analyst awareness but do not automatically block.
    """
    final_score = (original_fused_score + twin_score) / 2
    final_score = max(0.0, min(1.0, final_score))

    labels = [entropy_label, semantic_label, reputation_label, twin_label]

    if "MALICIOUS" in labels:
        verdict = "BLOCK"
        reason = "One or more layers classified the request as MALICIOUS"
    elif final_score >= BLOCK_THRESHOLD:
        verdict = "BLOCK"
        reason = f"Final risk score ({final_score:.3f}) exceeds threshold ({BLOCK_THRESHOLD})"
    else:
        verdict = "ALLOW"
        reason = "No MALICIOUS layer and final risk score below threshold"

    return {
        "fused_score": final_score,
        "verdict": verdict,
        "reason": reason,
    }
