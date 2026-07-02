import redis
import time
from config import get_settings

settings = get_settings()

class MetricsTracker:
    """
    Persists all counters in Redis so they survive backend restarts.
    """

    def __init__(self):
        self.redis = redis.Redis(
            host=settings.REDIS_HOST,
            port=settings.REDIS_PORT,
            db=settings.REDIS_DB,
            decode_responses=True
        )
        # Set start time only once (first ever boot)
        if not self.redis.exists("metrics:start_time"):
            self.redis.set("metrics:start_time", time.time())

    def increment(self, key: str):
        self.redis.incr(f"metrics:{key}")

    def get_all(self) -> dict:
        start_time = float(self.redis.get("metrics:start_time") or time.time())
        keys = [
            "total_requests",
            "successful_requests",
            "blocked_requests",
            "attacks_detected",
        ]
        result = {"uptime_seconds": round(time.time() - start_time, 2)}
        for k in keys:
            val = self.redis.get(f"metrics:{k}")
            result[k] = int(val) if val else 0
        return result
