import redis
import json
import time
from config import get_settings

settings = get_settings()

class ReputationEngine:
    """
    Maintains per-user trust scores.
    Tracks behavior over time with decay.
    """

    INITIAL_SCORE  = 0.7   # new users start at 0.7
    DECAY_RATE     = 0.02  # trust decays slightly over time
    SUCCESS_BOOST  = 0.05
    ABUSE_PENALTY  = 0.20
    CHALLENGE_FAIL = 0.15

    def get_score(self, user_id: str) -> dict:
        data = self._load(user_id)
        # Apply time decay
        score = self._apply_decay(data)
        tier  = self._get_tier(score)

        # Save decayed score back
        data["trust_score"] = score
        self._save(user_id, data)

        return {
            "trust_score":      round(score, 3),
            "tier":             tier,
            "total_requests":   data.get("total_requests", 0),
            "abuse_count":      data.get("abuse_count", 0),
            "avg_cost_score":   data.get("avg_cost_score", 0),
        }

    def record_success(self, user_id: str, cost_score: float):
        """Called after a successful clean request."""
        data  = self._load(user_id)
        score = data.get("trust_score", self.INITIAL_SCORE)

        # Boost trust slightly, more for low-cost requests
        boost  = self.SUCCESS_BOOST * (1 - cost_score / 200)
        score  = min(1.0, score + boost)

        # Update stats
        total = data.get("total_requests", 0) + 1
        avg   = (
            (data.get("avg_cost_score", 0) * (total - 1) + cost_score) / total
        )

        data.update({
            "trust_score":    score,
            "total_requests": total,
            "avg_cost_score": round(avg, 2),
            "last_seen":      time.time(),
        })
        self._save(user_id, data)

    def record_abuse(self, user_id: str):
        """Called when a user triggers a block."""
        data  = self._load(user_id)
        score = data.get("trust_score", self.INITIAL_SCORE)
        score = max(0.0, score - self.ABUSE_PENALTY)

        data.update({
            "trust_score": score,
            "abuse_count": data.get("abuse_count", 0) + 1,
            "last_abuse":  time.time(),
        })
        self._save(user_id, data)

        # Auto-blacklist if trust hits 0
        if score <= 0.05:
            self._flag_for_blacklist(user_id)

    def record_challenge_fail(self, user_id: str):
        data  = self._load(user_id)
        score = data.get("trust_score", self.INITIAL_SCORE)
        score = max(0.0, score - self.CHALLENGE_FAIL)
        data["trust_score"] = score
        self._save(user_id, data)

    # ── Internals ─────────────────────────────────────────────────────

    def _load(self, user_id: str) -> dict:
        r   = self._redis()
        raw = r.get(f"reputation:{user_id}")
        if raw:
            return json.loads(raw)
        return {
            "trust_score":    self.INITIAL_SCORE,
            "total_requests": 0,
            "abuse_count":    0,
            "avg_cost_score": 0,
            "last_seen":      time.time(),
            "created_at":     time.time(),
        }

    def _save(self, user_id: str, data: dict):
        r = self._redis()
        r.setex(
            f"reputation:{user_id}",
            86400 * 30,   # 30 days TTL
            json.dumps(data)
        )

        # Track this user in the master set (no TTL — permanent until reset)
        r.sadd("users:all_known", user_id)

    def _apply_decay(self, data: dict) -> float:
        """Trust decays slightly if user hasn't been seen recently."""
        score     = data.get("trust_score", self.INITIAL_SCORE)
        last_seen = data.get("last_seen", time.time())
        hours_gap = (time.time() - last_seen) / 3600

        # Decay after 24 hours of inactivity
        if hours_gap > 24:
            decay = self.DECAY_RATE * (hours_gap / 24)
            score = max(0.3, score - decay)  # floor at 0.3

        return round(score, 3)

    def _get_tier(self, score: float) -> str:
        if score >= 0.75: return "trusted"
        if score >= 0.45: return "authenticated"
        return "anonymous"

    def peek_tier(self, user_id: str) -> str:
        """
        Read-only tier lookup — applies decay for an accurate current
        score but does NOT write back to Redis. Used by other layers
        (e.g. AuthLayer) that need a consistent tier without triggering
        an extra save on every single request. The authoritative,
        state-mutating read still happens once per request via
        get_score() later in the pipeline.
        """
        data  = self._load(user_id)
        score = self._apply_decay(data)
        return self._get_tier(score)

    def _flag_for_blacklist(self, user_id: str):
        r = self._redis()
        r.sadd("blacklist:candidates", user_id)

    def _redis(self):
        return redis.Redis(
            host=settings.REDIS_HOST,
            port=settings.REDIS_PORT,
            db=settings.REDIS_DB,
            decode_responses=True
        )

    def get_all_scores(self) -> list:
        """For dashboard use — returns ALL known users, even ones whose Redis TTL expired data."""
        r = self._redis()

        # Get every user_id ever seen (permanent set)
        all_users = r.smembers("users:all_known")

        out = []
        for user_id in all_users:
            raw = r.get(f"reputation:{user_id}")
            is_blacklisted = bool(r.sismember("blacklist:users", user_id))
            blacklist_meta = None
            if is_blacklisted:
                meta_raw = r.get(f"blacklist:meta:{user_id}")
                if meta_raw:
                    blacklist_meta = json.loads(meta_raw)

            if raw:
                data = json.loads(raw)
                trust_score = data.get("trust_score", 0)
                out.append({
                    "user_id":         user_id,
                    "trust_score":     round(trust_score, 3),
                    "tier":            "blacklisted" if is_blacklisted else self._get_tier(trust_score),
                    "abuse_count":     data.get("abuse_count", 0),
                    "total_requests":  data.get("total_requests", 0),
                    "avg_cost_score":  data.get("avg_cost_score", 0),
                    "last_seen":       data.get("last_seen", 0),
                    "is_blacklisted":  is_blacklisted,
                    "blacklist_reason": blacklist_meta,
                })
            else:
                # User exists in master set but their reputation TTL expired
                out.append({
                    "user_id":        user_id,
                    "trust_score":    0.0,
                    "tier":           "blacklisted" if is_blacklisted else "expired",
                    "abuse_count":    0,
                    "total_requests": 0,
                    "avg_cost_score": 0,
                    "last_seen":      0,
                    "is_blacklisted": is_blacklisted,
                    "blacklist_reason": blacklist_meta,
                })

        # Sort: blacklisted first, then by trust score ascending
        return sorted(out, key=lambda x: (not x["is_blacklisted"], x["trust_score"]))
