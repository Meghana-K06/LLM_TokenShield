"""
Layer 4: Redis Correlation & Reputation Engine
Tracks per-client behavior over time so the system isn't just judging a
single request in isolation:
  - request rate (possible flooding/probing — quota pressure)
  - rolling reputation/trust score (0 = clean history, 1 = bad history),
    with decay: malicious requests push it up, clean requests cool it down
  - correlation of recent malicious hits from the same client_id

Reputation decays back toward "neutral" over time (TTL-based) so a client
isn't punished forever for a single old incident. A client whose reputation
crosses a hard ceiling is auto-escalated to Layer 1's blacklist so future
requests are blocked before they ever reach L2/L3.
"""
import time
import redis
from config import (
    REDIS_HOST, REDIS_PORT, MAX_REQUESTS_PER_WINDOW, WINDOW_SECONDS,
    REPUTATION_DECAY_ON_MALICIOUS, REPUTATION_COOLDOWN_ON_CLEAN, REPUTATION_TTL_SECONDS,
)
from layer1_auth_validation import blacklist_user as blacklist_client

_r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

AUTO_BLACKLIST_REPUTATION = 0.95  # trust score ceiling -> auto-blacklist


def _rate_key(client_id: str) -> str:
    return f"twinshield:rate:{client_id}"


def _reputation_key(client_id: str) -> str:
    return f"twinshield:reputation:{client_id}"


def _history_key(client_id: str) -> str:
    return f"twinshield:history:{client_id}"


def check_rate_limit(client_id: str) -> dict:
    key = _rate_key(client_id)
    count = _r.incr(key)
    if count == 1:
        _r.expire(key, WINDOW_SECONDS)
    over_limit = count > MAX_REQUESTS_PER_WINDOW
    return {"count": count, "limit": MAX_REQUESTS_PER_WINDOW, "over_limit": over_limit}


def get_reputation(client_id: str) -> float:
    val = _r.get(_reputation_key(client_id))
    return float(val) if val is not None else 0.0  # 0 = neutral/clean history


def update_reputation(client_id: str, upstream_malicious_score: float) -> float:
    """Nudge reputation up when upstream layers found this request risky;
    cool it down slightly on clean requests. Auto-blacklists on repeated abuse."""
    current = get_reputation(client_id)
    if upstream_malicious_score >= 0.6:
        new_rep = min(1.0, current + REPUTATION_DECAY_ON_MALICIOUS)
    else:
        new_rep = max(0.0, current - REPUTATION_COOLDOWN_ON_CLEAN)

    _r.set(_reputation_key(client_id), new_rep, ex=REPUTATION_TTL_SECONDS)

    if new_rep >= AUTO_BLACKLIST_REPUTATION:
        blacklist_client(client_id, reason="reputation ceiling exceeded", triggered_by="auto")

    return new_rep


def log_history(client_id: str, verdict: str, score: float):
    entry = f"{int(time.time())}|{verdict}|{score:.3f}"
    _r.lpush(_history_key(client_id), entry)
    _r.ltrim(_history_key(client_id), 0, 49)  # keep last 50 events
    _r.expire(_history_key(client_id), REPUTATION_TTL_SECONDS)


def get_history(client_id: str, limit: int = 20) -> list:
    raw = _r.lrange(_history_key(client_id), 0, limit - 1)
    out = []
    for entry in raw:
        ts, verdict, score = entry.split("|")
        out.append({"timestamp": int(ts), "verdict": verdict, "score": float(score)})
    return out


def increment_global_stats(verdict: str, used_twin: bool):
    _r.incr("twinshield:stats:total")
    _r.incr(f"twinshield:stats:{verdict.lower()}")
    if used_twin:
        _r.incr("twinshield:stats:twin_escalations")


def get_global_stats() -> dict:
    total = int(_r.get("twinshield:stats:total") or 0)
    allowed = int(_r.get("twinshield:stats:allow") or 0)
    blocked = int(_r.get("twinshield:stats:block") or 0)
    twin = int(_r.get("twinshield:stats:twin_escalations") or 0)
    return {"total": total, "allowed": allowed, "blocked": blocked, "twin_escalations": twin}


def correlation_scan(client_id: str) -> dict:
    """
    Layer 4 entry point: combines quota pressure + historical reputation
    into a single 0-1 'reputation risk' score used by Decision Fusion.
    """
    rate = check_rate_limit(client_id)
    reputation = get_reputation(client_id)

    rate_pressure = min(1.0, rate["count"] / rate["limit"]) if rate["limit"] else 0.0

    # Weighted blend: prior bad behavior matters more than momentary rate pressure
    combined_score = min(1.0, 0.7 * reputation + 0.3 * rate_pressure)

    label = "MALICIOUS" if combined_score >= 0.6 else ("SUSPICIOUS" if combined_score >= 0.3 else "SAFE")

    return {
        "score": combined_score,
        "label": label,
        "details": {
            "rate": rate,
            "reputation": reputation,
            "over_limit": rate["over_limit"],
        },
    }
