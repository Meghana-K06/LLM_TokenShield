import redis
import time
from config import get_settings

settings = get_settings()

class AuthLayer:
    def __init__(self):
        self.redis = redis.Redis(
            host=settings.REDIS_HOST,
            port=settings.REDIS_PORT,
            db=settings.REDIS_DB,
            decode_responses=True
        )
        self.quota_limit   = 100   # max requests per hour
        self.window_seconds = 3600  # 1 hour window

    def check(self, user_id: str, client_ip: str) -> dict:
        # ── Blacklist check ───────────────────────────────────────────
        if self.redis.sismember("blacklist:users", user_id):
            return self._deny(user_id, "user blacklisted")

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
        tier = "anonymous"
        if self.redis.sismember("users:authenticated", user_id):
            tier = "authenticated"
        if self.redis.sismember("users:trusted", user_id):
            tier = "trusted"

        return {
            "user_id": user_id,
            "tier":    tier,
            "allowed": True,
            "quota_used": count,
            "quota_limit": self.quota_limit
        }

    def blacklist_user(self, user_id: str):
        self.redis.sadd("blacklist:users", user_id)

    def blacklist_ip(self, ip: str):
        self.redis.sadd("blacklist:ips", ip)

    def _deny(self, user_id: str, reason: str) -> dict:
        return {
            "user_id": user_id,
            "tier":    "blocked",
            "allowed": False,
            "reason":  reason
        }

    
