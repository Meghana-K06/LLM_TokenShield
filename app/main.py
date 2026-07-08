"""
TwinShield Gateway — Main Orchestrator
Wires together Layers 1-6:

Incoming -> L1 Auth & Input Validation (blacklist + tiktoken)     [can block: blacklisted]
         -> L2 ML Defender (Entropy Engine)                        [can block: MALICIOUS cost_score]
         -> L3 ML Risk Engine (regex rules + vector/cosine sim)    [can block: MALICIOUS risk_score]
         -> L4 Redis Correlation & Reputation                      [can block: MALICIOUS reputation/rate]
         -> Decision Fusion -> [confidence check]
               -> (high confidence) -> L6 Output Filter -> Response
               -> (low confidence)  -> L5 Twin AI Reviewer (Lakera) -> Final Fusion -> L6 -> Response

Each layer can independently short-circuit the pipeline: if a layer's
own verdict is MALICIOUS, the request is blocked immediately and NO
layer below it runs. This mirrors your real system's behavior where a
confirmed regex/rule match blocks outright rather than being averaged
against weaker signals from layers that haven't run yet. Layer 6
(Output Safety Filter) always runs at the end regardless of which path
was taken, since it's what produces the final response.

If (and only if) every layer that ran comes back SAFE/SUSPICIOUS
(nothing MALICIOUS on its own), the pipeline proceeds to Decision
Fusion across L2+L3+L4, with L5 (Lakera) escalation for genuinely
ambiguous cases.

NOTE: layer identifiers in LayerResult ("L1_Auth_Validation", "L2_AI_Defender", ...)
are kept stable so the bundled dashboard (static/index.html) can map them to
pipeline nodes without any frontend changes.
"""
import os
import uuid
import logging

from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from models import IncomingRequest, PipelineResponse, LayerResult
from layer1_auth_validation import verify_api_key, sanitize_and_validate, is_blacklisted
from layer2_entropy_engine import entropy_defender_scan
from layer3_semantic_risk_engine import semantic_risk_scan
from layer4_redis_correlation import (
    correlation_scan, update_reputation, log_history,
    get_history, increment_global_stats, get_global_stats,
)
from decision_fusion import fuse_scores, fuse_with_twin
from layer5_twin_lakera_reviewer import twin_review
from layer6_output_filter import output_safety_filter
from config import TWIN_THRESHOLD, API_KEY

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("twinshield-gateway")

app = FastAPI(title="TwinShield Gateway", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/api/v1/config")
async def get_config():
    """Exposes non-secret config so the dashboard can display current thresholds."""
    return {"twin_threshold": TWIN_THRESHOLD}


@app.get("/api/v1/stats")
async def stats():
    return get_global_stats()


@app.get("/api/v1/history/{client_id}")
async def history(client_id: str):
    return {"client_id": client_id, "events": get_history(client_id)}


# ---------------- Dashboard (static UI) ----------------
_static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.isdir(_static_dir):
    app.mount("/assets", StaticFiles(directory=_static_dir), name="assets")


@app.get("/dashboard")
async def dashboard():
    return FileResponse(os.path.join(_static_dir, "index.html"))


def _finalize_block(trace_id: str, client_id: str, clean_payload: str,
                     layers_result: list, blocked_by: str, score: float = 1.0) -> PipelineResponse:
    """Common short-circuit exit path: a layer already decided MALICIOUS,
    so no layer below it runs. Still updates reputation/history (Layer 4's
    feedback loop) and runs Layer 6 to produce the final response.

    Reputation is always nudged as a confirmed-malicious event (not the
    triggering layer's raw score) — a layer that decided MALICIOUS did so
    with its own threshold logic (e.g. Layer 3's regex match at 0.18 is
    just as confirmed as Layer 2's entropy block at 0.85); reputation's
    own >=0.6 "was this malicious" check must not silently disagree with
    a layer that already made the call."""
    logger.info(f"[{trace_id}] SHORT-CIRCUIT BLOCK at {blocked_by} — skipping all layers below it")
    update_reputation(client_id, 1.0)
    log_history(client_id, "BLOCK", score)
    increment_global_stats("block", False)
    safe_output = output_safety_filter("BLOCK", clean_payload)
    return PipelineResponse(
        client_id=client_id,
        final_verdict="BLOCK",
        fused_confidence=score,
        used_twin_reviewer=False,
        layers=layers_result,
        safe_output=safe_output,
        trace_id=trace_id,
    )


@app.post("/api/v1/evaluate", response_model=PipelineResponse)
async def evaluate(request: IncomingRequest, _auth=Depends(verify_api_key)):
    trace_id = str(uuid.uuid4())[:8]
    layers_result = []
    logger.info(f"[{trace_id}] Incoming request from client_id={request.client_id}")

    # ---------------- Layer 1: Auth & Input Validation ----------------
    blacklist_entry = is_blacklisted(request.client_id)
    if blacklist_entry:
        logger.info(f"[{trace_id}] BLOCKED — client_id={request.client_id} is blacklisted: {blacklist_entry}")
        layers_result.append(LayerResult(
            layer="L1_Auth_Validation", score=1.0, verdict="MALICIOUS",
            details={"blacklisted": True, **blacklist_entry},
        ))
        increment_global_stats("block", False)
        return PipelineResponse(
            client_id=request.client_id,
            final_verdict="BLOCK",
            fused_confidence=1.0,
            used_twin_reviewer=False,
            layers=layers_result,
            safe_output=output_safety_filter("BLOCK", request.payload, blacklisted=True),
            trace_id=trace_id,
        )

    clean_payload, token_count = sanitize_and_validate(request.payload)
    layers_result.append(LayerResult(
        layer="L1_Auth_Validation", score=0.0, verdict="PASS",
        details={"sanitized_length": len(clean_payload), "token_count": token_count},
    ))

    # ---------------- Layer 2: ML Defender (Entropy Engine) ----------------
    entropy_result = entropy_defender_scan(clean_payload)
    layers_result.append(LayerResult(
        layer="L2_AI_Defender", score=entropy_result["score"], verdict=entropy_result["label"],
        details={"reason": entropy_result["reason"], **entropy_result["details"]}
    ))
    logger.info(f"[{trace_id}] L2 Entropy Defender score={entropy_result['score']:.3f} label={entropy_result['label']}")

    if entropy_result["label"] == "MALICIOUS":
        return _finalize_block(trace_id, request.client_id, clean_payload, layers_result,
                                "L2_AI_Defender", entropy_result["score"])

    # ---------------- Layer 3: ML Risk Engine (regex rules + vector/cosine similarity) ----------------
    risk_result = await semantic_risk_scan(clean_payload)
    layers_result.append(LayerResult(
        layer="L3_ML_Risk_Engine", score=risk_result["score"], verdict=risk_result["label"],
        details=risk_result["details"]
    ))
    logger.info(f"[{trace_id}] L3 Risk Engine score={risk_result['score']:.3f} label={risk_result['label']}")

    if risk_result["label"] == "MALICIOUS":
        return _finalize_block(trace_id, request.client_id, clean_payload, layers_result,
                                "L3_ML_Risk_Engine", risk_result["score"])

    # ---------------- Layer 4: Redis Correlation & Reputation ----------------
    corr_result = correlation_scan(request.client_id)
    layers_result.append(LayerResult(
        layer="L4_Redis_Correlation", score=corr_result["score"], verdict=corr_result["label"],
        details=corr_result["details"]
    ))
    logger.info(f"[{trace_id}] L4 Correlation score={corr_result['score']:.3f} label={corr_result['label']}")

    if corr_result["label"] == "MALICIOUS":
        return _finalize_block(trace_id, request.client_id, clean_payload, layers_result,
                                "L4_Redis_Correlation", corr_result["score"])

    # ---------------- Decision Fusion Engine ----------------
    # Reached only if L2, L3, L4 all came back non-MALICIOUS on their own.
    fusion = fuse_scores(entropy_result["score"], risk_result["score"], corr_result["score"])
    logger.info(
        f"[{trace_id}] Fusion => fused={fusion['fused_score']:.3f} "
        f"confidence={fusion['confidence']:.3f} verdict={fusion['verdict']}"
    )

    used_twin = False
    final_score = fusion["fused_score"]
    final_verdict = fusion["verdict"]

    # ---------------- Confidence Check ----------------
    # Escalate to Layer 5 if the fused score is genuinely ambiguous (low
    # confidence) OR if any individual layer flagged SUSPICIOUS — a
    # suspicious label must not be silently averaged away.
    any_layer_suspicious = (
        entropy_result["label"] == "SUSPICIOUS" or risk_result["label"] == "SUSPICIOUS" or corr_result["label"] == "SUSPICIOUS"
    )

    if fusion["confidence"] < TWIN_THRESHOLD or any_layer_suspicious:
        # ---------------- Layer 5: Twin AI Security Reviewer (Lakera) ----------------
        used_twin = True
        twin_result = await twin_review(clean_payload, {
            "entropy_label": entropy_result["label"],
            "risk_label": risk_result["label"],
            "reputation_label": corr_result["label"],
        })
        layers_result.append(LayerResult(
            layer="L5_Twin_AI_Reviewer", score=twin_result["score"], verdict=twin_result["label"],
            details={"reason": twin_result["reason"], **twin_result["details"]}
        ))
        logger.info(f"[{trace_id}] L5 Lakera Twin Reviewer score={twin_result['score']:.3f} label={twin_result['label']}")

        if twin_result["label"] == "MALICIOUS":
            return _finalize_block(trace_id, request.client_id, clean_payload, layers_result,
                                    "L5_Twin_AI_Reviewer", twin_result["score"])

        # ---------------- Decision Fusion Engine (Final) ----------------
        final_fusion = fuse_with_twin(
            fusion["fused_score"],
            twin_result["score"],
            entropy_label=entropy_result["label"],
            semantic_label=risk_result["label"],
            reputation_label=corr_result["label"],
            twin_label=twin_result["label"],
        )
        final_score = final_fusion["fused_score"]
        final_verdict = final_fusion["verdict"]
        logger.info(f"[{trace_id}] Final Fusion => score={final_score:.3f} verdict={final_verdict}")

    # ---------------- Update reputation + history (Layer 4 feedback loop) ----------------
    update_reputation(request.client_id, final_score)
    log_history(request.client_id, final_verdict, final_score)
    increment_global_stats(final_verdict, used_twin)

    # ---------------- Layer 6: Output Safety Filter ----------------
    safe_output = output_safety_filter(final_verdict, clean_payload)

    return PipelineResponse(
        client_id=request.client_id,
        final_verdict=final_verdict,
        fused_confidence=final_score,
        used_twin_reviewer=used_twin,
        layers=layers_result,
        safe_output=safe_output,
        trace_id=trace_id,
    )
