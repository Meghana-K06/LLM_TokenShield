import redis
import hashlib
import json
import time
from config import get_settings

settings = get_settings()

class CorrelationEngine:
    """
    Tracks attack patterns across users, IPs, and timestamps.
    Detects coordinated campaigns and distributed attacks.
    """

    def __init__(self):
        self.redis = redis.Redis(
            host=settings.REDIS_HOST,
            port=settings.REDIS_PORT,
            db=settings.REDIS_DB,
            decode_responses=True
        )
        self.window_seconds  = 300   # 5 minute sliding window
        self.campaign_threshold = 3  # attacks to declare a campaign

    def check(self, user_id: str, client_ip: str, prompt: str) -> dict:
        prompt_hash    = self._hash_prompt(prompt)
        prompt_pattern = self._extract_pattern(prompt)
        now            = time.time()

        # Store this request fingerprint
        self._store_request(user_id, client_ip, prompt_hash, prompt_pattern, now)

        # Check for campaign
        campaign_result = self._detect_campaign(prompt_hash, prompt_pattern, now)

        # Check for distributed attack from multiple IPs
        distributed = self._detect_distributed(prompt_hash, now)

        if campaign_result["detected"] or distributed:
            campaign_id = self._get_or_create_campaign(prompt_hash)
            return {
                "campaign_detected": True,
                "campaign_id":       campaign_id,
                "confidence":        campaign_result["confidence"],
                "distributed":       distributed,
            }

        return {
            "campaign_detected": False,
            "campaign_id":       None,
            "confidence":        0.0,
            "distributed":       False,
        }

    # ── Internals ─────────────────────────────────────────────────────

    def _hash_prompt(self, prompt: str) -> str:
        """Full hash for exact matching."""
        return hashlib.sha256(prompt.strip().lower().encode()).hexdigest()[:16]

    def _extract_pattern(self, prompt: str) -> str:
        """
        Fuzzy pattern — first 6 words lowercased.
        Catches mutations of the same attack.
        """
        words = prompt.lower().split()[:6]
        return hashlib.md5(" ".join(words).encode()).hexdigest()[:12]

    def _store_request(self, user_id, client_ip, prompt_hash, pattern, now):
        """Store request fingerprint in Redis sorted set (score = timestamp)."""
        # Exact hash tracking
        self.redis.zadd(f"corr:hash:{prompt_hash}", {f"{user_id}:{client_ip}": now})
        self.redis.expire(f"corr:hash:{prompt_hash}", self.window_seconds)

        # Pattern tracking (fuzzy)
        self.redis.zadd(f"corr:pattern:{pattern}", {f"{user_id}:{client_ip}": now})
        self.redis.expire(f"corr:pattern:{pattern}", self.window_seconds)

        # Per-user request log
        self.redis.zadd(f"corr:user:{user_id}", {prompt_hash: now})
        self.redis.expire(f"corr:user:{user_id}", self.window_seconds)

    def _detect_campaign(self, prompt_hash: str, pattern: str, now: float) -> dict:
        """Check if same or similar prompt seen from multiple sources."""
        cutoff = now - self.window_seconds

        # Exact same prompt from multiple users
        exact_count = self.redis.zcount(
            f"corr:hash:{prompt_hash}", cutoff, now
        )

        # Similar pattern from multiple users
        pattern_count = self.redis.zcount(
            f"corr:pattern:{pattern}", cutoff, now
        )

        if exact_count >= self.campaign_threshold:
            confidence = min(0.95, 0.5 + (exact_count * 0.1))
            return {"detected": True, "confidence": round(confidence, 2)}

        if pattern_count >= self.campaign_threshold + 1:
            confidence = min(0.85, 0.4 + (pattern_count * 0.08))
            return {"detected": True, "confidence": round(confidence, 2)}

        return {"detected": False, "confidence": 0.0}

    def _detect_distributed(self, prompt_hash: str, now: float) -> bool:
        """Same prompt from 3+ different IPs = distributed attack."""
        cutoff  = now - self.window_seconds
        members = self.redis.zrangebyscore(
            f"corr:hash:{prompt_hash}", cutoff, now
        )
        unique_ips = set(m.split(":")[1] for m in members if ":" in m)
        return len(unique_ips) >= 3

    def _get_or_create_campaign(self, prompt_hash: str) -> str:
        """Get existing campaign ID or create new one."""
        key = f"campaign:id:{prompt_hash}"
        existing = self.redis.get(key)
        if existing:
            return existing
        campaign_id = f"CAMP-{prompt_hash[:8].upper()}"
        self.redis.setex(key, 3600, campaign_id)

        # Log campaign
        self.redis.lpush("campaigns:active", json.dumps({
            "campaign_id": campaign_id,
            "prompt_hash": prompt_hash,
            "detected_at": time.time()
        }))
        self.redis.ltrim("campaigns:active", 0, 99)  # keep last 100
        return campaign_id

    def get_active_campaigns(self) -> list:
        """For dashboard use."""
        raw = self.redis.lrange("campaigns:active", 0, 19)
        return [json.loads(r) for r in raw]
