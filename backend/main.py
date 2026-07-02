from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import redis as redis_lib
import json as json_lib
from pydantic import BaseModel
from typing import Optional
import time
import uuid

from config import get_settings
from layers.auth import AuthLayer
from layers.entropy import EntropyEngine
from layers.risk import RiskAnalysisEngine
from layers.correlation import CorrelationEngine
from layers.amplification import AmplificationDetector
from layers.reputation import ReputationEngine
from layers.challenge import ChallengeGenerator
from layers.proof_of_compute import ProofOfCompute
from layers.token_budget import TokenBudgetAllocator
from layers.twin_defender import TwinDefender
from adapters.ollama_adapter import OllamaAdapter
from monitoring.metrics import MetricsTracker
from monitoring.logger import TwinLogger

settings = get_settings()
_redis_log = redis_lib.Redis(
    host=settings.REDIS_HOST,
    port=settings.REDIS_PORT,
    db=settings.REDIS_DB,
    decode_responses=True
)

def log_request(prompt: str, report: dict, response: str = None):
    entry = {
        "timestamp": time.time(),
        "prompt":    prompt[:200],
        "response":  (response or "")[:300],
        "report":    report,
    }
    _redis_log.lpush("request_log:all", json_lib.dumps(entry))
    _redis_log.ltrim("request_log:all", 0, 199)

app = FastAPI(title="TwinShield", version="1.0.0")
logger = TwinLogger()
metrics = MetricsTracker()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

auth_layer        = AuthLayer()
entropy_engine    = EntropyEngine()
risk_engine       = RiskAnalysisEngine()
correlation_engine= CorrelationEngine()
amplification_det = AmplificationDetector()
reputation_engine = ReputationEngine()
challenge_gen     = ChallengeGenerator()
proof_of_compute  = ProofOfCompute()
token_allocator   = TokenBudgetAllocator()
twin_defender     = TwinDefender()
ollama_adapter    = OllamaAdapter()

class PromptRequest(BaseModel):
    prompt: str
    user_id: Optional[str] = None
    challenge_response: Optional[str] = None

@app.get("/health")
async def health():
    return {"status": "ok", "service": "TwinShield"}

@app.post("/v1/chat")
async def chat(request: Request, body: PromptRequest):
    start_time = time.time()
    request_id = str(uuid.uuid4())[:8]

    client_ip = request.client.host
    prompt    = body.prompt
    user_id   = body.user_id or f"anon_{client_ip}"

    logger.info(f"[{request_id}] New request from {user_id}")
    metrics.increment("total_requests")

    protection_report = {
        "request_id":         request_id,
        "user_id":            user_id,
        "client_ip":          client_ip,
        "cost_score":         0,
        "risk_flags":         [],
        "risk_score":         0,
        "trust_score":        1.0,
        "tokens_allocated":   settings.TOKEN_BUDGET_LOW,
        "campaign_detected":  False,
        "campaign_id":        None,
        "recursive_detected": False,
        "challenge_triggered":False,
        "challenge_jwt":      None,
        "defender_risk":      0.0,
        "blocked":            False,
        "block_reason":       None,
        "detection_breakdown":{
            "entropy":    "pending",
            "risk":       "pending",
            "reputation": "pending",
            "defender":   "pending",
        },
        "processing_time_ms": 0,
    }

    try:
        auth_result = auth_layer.check(user_id, client_ip)
        if not auth_result["allowed"]:
            metrics.increment("blocked_requests")
            protection_report["blocked"] = True
            protection_report["block_reason"] = "blacklisted or quota exceeded"
            log_request(prompt, protection_report)
            return JSONResponse(status_code=403, content={
                "error": "Access denied",
                "protection_report": protection_report
            })

        entropy_result = entropy_engine.analyze(prompt)
        protection_report["cost_score"] = entropy_result["cost_score"]
        protection_report["detection_breakdown"]["entropy"] = (
            "high" if entropy_result["cost_score"] > 70
            else "medium" if entropy_result["cost_score"] > 40
            else "low"
        )

        risk_result = risk_engine.analyze(prompt)
        protection_report["risk_flags"] = risk_result["risk_flags"]
        protection_report["risk_score"] = risk_result["risk_score"]
        protection_report["detection_breakdown"]["risk"] = (
            "critical" if risk_result["risk_score"] > 80
            else "suspicious" if risk_result["is_suspicious"]
            else "clean"
        )

        if risk_result["risk_score"] >= 18 and risk_result["is_suspicious"]:
            metrics.increment("blocked_requests")
            metrics.increment("attacks_detected")
            protection_report["blocked"] = True
            protection_report["block_reason"] = (
                f"rule-based detection: {', '.join(risk_result['risk_flags'])}"
            )
            reputation_engine.record_abuse(user_id)
            log_request(prompt, protection_report)
            return JSONResponse(status_code=400, content={
                "error": "Request blocked: prompt injection detected",
                "protection_report": protection_report
            })

        correlation_result = correlation_engine.check(user_id, client_ip, prompt)
        protection_report["campaign_detected"] = correlation_result["campaign_detected"]
        protection_report["campaign_id"]       = correlation_result.get("campaign_id")

        amp_result = amplification_det.detect(
            prompt,
            entropy_result["predicted_tokens"]
        )
        protection_report["recursive_detected"] = amp_result["recursive_detected"]

        if amp_result["recursive_detected"]:
            metrics.increment("blocked_requests")
            metrics.increment("attacks_detected")
            protection_report["blocked"] = True
            protection_report["block_reason"] = (
                f"recursive amplification detected "
                f"(multiplier: {amp_result['multiplier']:.1f}x)"
            )
            reputation_engine.record_abuse(user_id)
            log_request(prompt, protection_report)
            return JSONResponse(status_code=400, content={
                "error": "Request blocked: recursive amplification",
                "protection_report": protection_report
            })

        rep_result = reputation_engine.get_score(user_id)
        protection_report["trust_score"] = rep_result["trust_score"]
        protection_report["detection_breakdown"]["reputation"] = rep_result["tier"]

        challenge_result = challenge_gen.evaluate(
            user_id,
            rep_result["trust_score"],
            entropy_result["cost_score"]
        )

        if challenge_result["challenge_required"]:
            if not body.challenge_response:
                protection_report["challenge_triggered"] = True
                protection_report["challenge_jwt"]       = challenge_result["challenge_jwt"]
                log_request(prompt, protection_report)
                return JSONResponse(status_code=429, content={
                    "error": "Challenge required",
                    "challenge_jwt": challenge_result["challenge_jwt"],
                    "instructions": (
                        "Solve proof-of-compute and resubmit "
                        "with challenge_response field"
                    ),
                    "protection_report": protection_report
                })

            verified = proof_of_compute.verify(body.challenge_response)
            if not verified["verified"]:
                metrics.increment("blocked_requests")
                protection_report["blocked"] = True
                protection_report["block_reason"] = "proof-of-compute failed"
                reputation_engine.record_abuse(user_id)
                log_request(prompt, protection_report)
                return JSONResponse(status_code=403, content={
                    "error": "Proof-of-compute verification failed",
                    "protection_report": protection_report
                })

        budget_result = token_allocator.allocate(
            risk_result["risk_score"],
            rep_result["trust_score"]
        )
        protection_report["tokens_allocated"] = budget_result["tokens_allocated"]

        defender_result = await twin_defender.inspect(prompt)
        protection_report["defender_risk"] = defender_result["defender_risk"]
        protection_report["detection_breakdown"]["defender"] = (
            "dangerous" if defender_result["defender_risk"] >= 0.5
            else "suspicious" if defender_result["defender_risk"] > 0.4
            else "safe"
        )

        if defender_result["defender_risk"] >= 0.5:
            metrics.increment("blocked_requests")
            metrics.increment("attacks_detected")
            protection_report["blocked"] = True
            protection_report["block_reason"] = (
                f"Twin AI Defender blocked: {defender_result['reason']}"
            )
            reputation_engine.record_abuse(user_id)
            log_request(prompt, protection_report)
            return JSONResponse(status_code=400, content={
                "error": "Request blocked by Twin AI Defender",
                "protection_report": protection_report
            })

        llm_response = await ollama_adapter.generate(
            prompt,
            max_tokens=budget_result["tokens_allocated"]
        )

        reputation_engine.record_success(user_id, entropy_result["cost_score"])

        protection_report["processing_time_ms"] = round(
            (time.time() - start_time) * 1000, 2
        )
        metrics.increment("successful_requests")
        log_request(prompt, protection_report, llm_response)

        return JSONResponse(content={
            "response": llm_response,
            "protection_report": protection_report
        })

    except Exception as e:
        logger.error(f"[{request_id}] Pipeline error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/metrics")
async def get_metrics():
    return metrics.get_all()

@app.get("/reputation/{user_id}")
async def get_reputation(user_id: str):
    result = reputation_engine.get_score(user_id)
    return result

@app.get("/reputation")
async def get_all_reputation():
    return reputation_engine.get_all_scores()

@app.get("/campaigns")
async def get_campaigns():
    return correlation_engine.get_active_campaigns()

@app.post("/blacklist/user/{user_id}")
async def blacklist_user(user_id: str):
    auth_layer.blacklist_user(user_id)
    return {"blacklisted": user_id}

@app.delete("/blacklist/user/{user_id}")
async def unblacklist_user(user_id: str):
    _redis_log.srem("blacklist:users", user_id)
    return {"unblacklisted": user_id}

@app.post("/blacklist/ip/{ip}")
async def blacklist_ip(ip: str):
    auth_layer.blacklist_ip(ip)
    return {"blacklisted_ip": ip}

@app.delete("/reputation/{user_id}")
async def reset_reputation(user_id: str):
    _redis_log.delete(f"reputation:{user_id}")
    return {"reset": user_id}

@app.get("/requests/history")
async def get_request_history(limit: int = 50):
    raw = _redis_log.lrange("request_log:all", 0, limit - 1)
    return [json_lib.loads(r) for r in raw]
