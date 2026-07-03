import redis
import time
from config import get_settings
from layers.reputation import ReputationEngine

settings = get_settings()

class AuthLayer:
    def __init__(self, reputation_engine: ReputationEngine = None):
        self.redis = redis.Redis(
            host=settings.REDIS_HOST,
            port=settings.REDIS_PORT,
            db=settings.REDIS_DB,
            decode_responses=True
        )
        self.quota_limit    = settings.QUOTA_LIMIT
        self.window_seconds = settings.QUOTA_WINDOW_SECONDS
        # Tier now comes from the same trust-score logic ReputationEngine
        # uses everywhere else, instead of separate Redis sets
        # (users:authenticated / users:trusted) that nothing ever
        # populated — previously every user showed "anonymous" here
        # regardless of their actual trust score.
        self.reputation = reputation_engine or ReputationEngine()

    def check(self, user_id: str, client_ip: str) -> dict:
        # ── Blacklist check ───────────────────────────────────────────
        if self.redis.sismember("blacklist:users", user_id):
            meta = self.get_blacklist_reason(user_id)
            reason = f"user blacklisted: {meta['reason']}" if meta else "user blacklisted"
            return self._deny(user_id, reason)

        if self.redis.sismember("blacklist:ips", client_ip):
            return self._deny(user_id, "ip blacklisted")

        # ── Quota check ───────────────────────────────────────────────
        quota_key = f"quota:{user_id}"
        current   = self.redis.get(quota_key)

        if current is None:
            # First request — set counter with expiry
            self.redis.setex(quota_key, self.window_seconds, 1)
            count = 1
        else:
            count = int(current)
            if count >= self.quota_limit:
                return self._deny(user_id, "quota exceeded")
            self.redis.incr(quota_key)
            count += 1

        # ── Determine tier ────────────────────────────────────────────
        # Same trust-score-driven tiers as the reputation dashboard, so
        # this response and the dashboard never disagree with each other.
        tier = self.reputation.peek_tier(user_id)

        return {
            "user_id": user_id,
            "tier":    tier,
            "allowed": True,
            "quota_used": count,
            "quota_limit": self.quota_limit
        }

    def blacklist_user(self, user_id: str, reason: str = "Manually blacklisted", triggered_by: str = "manual"):
        import json as _json
        self.redis.sadd("blacklist:users", user_id)
        self.redis.set(f"blacklist:meta:{user_id}", _json.dumps({
            "reason":       reason,
            "triggered_by": triggered_by,   # "manual" or "auto"
            "timestamp":    time.time(),
        }))

    def get_blacklist_reason(self, user_id: str) -> dict:
        import json as _json
        raw = self.redis.get(f"blacklist:meta:{user_id}")
        if raw:
            return _json.loads(raw)
        return None

    def blacklist_ip(self, ip: str):
        self.redis.sadd("blacklist:ips", ip)

    def _deny(self, user_id: str, reason: str) -> dict:
        return {
            "user_id": user_id,
            "tier":    "blocked",
            "allowed": False,
            "reason":  reason
        }
