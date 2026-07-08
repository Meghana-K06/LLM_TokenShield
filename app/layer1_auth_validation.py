"""
Layer 1: Authentication & Input Validation
Faithful port of TwinShield's backend/layers/auth.py blacklist logic
(same Redis key names: `blacklist:users` set, `blacklist:meta:{user_id}`
JSON audit trail with reason/triggered_by/timestamp) plus real tiktoken
(cl100k_base) BPE tokenization, matching backend/layers/entropy.py's
_count_input_tokens method.

Quota/rate-limiting stays in Layer 4 (Redis Correlation & Reputation) in
this 6-layer redistribution, per the layer split requested — Layer 1's
job here is strictly: block blacklisted users, tokenize, sanitize.
"""
import re
import json
import time
import unicodedata

import redis
import tiktoken
from fastapi import HTTPException, Header

from config import API_KEY, REDIS_HOST, REDIS_PORT

_r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

BLACKLIST_USERS_KEY = "blacklist:users"
BLACKLIST_META_PREFIX = "blacklist:meta:"

try:
    _ENC = tiktoken.get_encoding("cl100k_base")
except Exception:
    _ENC = None  # falls back to a word-count heuristic, same as TwinShield's entropy.py


def verify_api_key(x_api_key: str = Header(default=None)):
    if x_api_key is None or x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized: invalid or missing API key")
    return True


def count_tokens(text: str) -> int:
    """Real BPE token count via tiktoken (cl100k_base). Falls back to
    TwinShield's word-count heuristic (len(words) * 1.3) if tiktoken's
    encoding couldn't be loaded (e.g. fully offline first run)."""
    if _ENC is not None:
        return len(_ENC.encode(text))
    return int(len(text.split()) * 1.3)


def is_blacklisted(user_id: str) -> dict:
    """Checks Redis for a blacklisted user, same key/shape as auth.py's
    check(): `blacklist:users` set + `blacklist:meta:{user_id}` JSON with
    reason / triggered_by / timestamp. Returns {} if not blacklisted."""
    if not _r.sismember(BLACKLIST_USERS_KEY, user_id):
        return {}
    raw = _r.get(f"{BLACKLIST_META_PREFIX}{user_id}")
    if raw:
        try:
            meta = json.loads(raw)
            meta.setdefault("reason", "blacklisted")
            return meta
        except (TypeError, ValueError):
            pass
    return {"reason": "blacklisted", "triggered_by": "unknown", "timestamp": time.time()}


def blacklist_user(user_id: str, reason: str = "Manually blacklisted", triggered_by: str = "manual"):
    """Direct port of auth.py's AuthLayer.blacklist_user."""
    _r.sadd(BLACKLIST_USERS_KEY, user_id)
    _r.set(f"{BLACKLIST_META_PREFIX}{user_id}", json.dumps({
        "reason": reason,
        "triggered_by": triggered_by,  # "manual" or "auto"
        "timestamp": time.time(),
    }))


def sanitize_and_validate(payload: str) -> tuple[str, int]:
    """Normalizes, strips control chars, and returns (cleaned_payload,
    token_count). No hard token ceiling by default (TwinShield's Layer 1
    doesn't reject on size — token cost is handled downstream); if
    MAX_PAYLOAD_TOKENS is set in config to a positive value, oversized
    payloads are rejected here so this standalone demo doesn't accept
    unbounded input forever."""
    if not payload or not payload.strip():
        raise HTTPException(status_code=400, detail="Empty payload rejected by Layer 1")

    normalized = unicodedata.normalize("NFKC", payload)
    cleaned = CONTROL_CHAR_RE.sub("", normalized).strip()
    token_count = count_tokens(cleaned)

    from config import MAX_PAYLOAD_TOKENS
    if MAX_PAYLOAD_TOKENS and token_count > MAX_PAYLOAD_TOKENS:
        raise HTTPException(
            status_code=413,
            detail=f"Payload too large ({token_count} tokens > {MAX_PAYLOAD_TOKENS} limit), rejected by Layer 1",
        )

    return cleaned, token_count
