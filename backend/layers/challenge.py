import jwt
import time
import uuid
from config import get_settings

settings = get_settings()

class ChallengeGenerator:
    """
    Issues JWT challenges to suspicious low-trust users.
    Triggered when trust_score < 0.4 AND cost_score > 70.
    """

    def evaluate(self, user_id: str, trust_score: float, cost_score: int) -> dict:
        should_challenge = (
            trust_score < settings.CHALLENGE_TRUST_THRESHOLD and
            cost_score  > settings.CHALLENGE_COST_THRESHOLD
        )

        if not should_challenge:
            return {
                "challenge_required": False,
                "challenge_jwt":      None,
            }

        token = self._generate_jwt(user_id)
        return {
            "challenge_required": True,
            "challenge_jwt":      token,
        }

    def _generate_jwt(self, user_id: str) -> str:
        payload = {
            "user_id":    user_id,
            "challenge":  str(uuid.uuid4()).replace("-", ""),
            "target":     "twinshield-poc",
            "issued_at":  time.time(),
            "exp":        time.time() + settings.JWT_EXPIRY_SECONDS,
        }
        return jwt.encode(
            payload,
            settings.JWT_SECRET,
            algorithm="HS256"
        )

    def decode_challenge(self, token: str) -> dict:
        """Decode and validate a challenge JWT."""
        try:
            payload = jwt.decode(
                token,
                settings.JWT_SECRET,
                algorithms=["HS256"]
            )
            return {"valid": True, "payload": payload}
        except jwt.ExpiredSignatureError:
            return {"valid": False, "reason": "challenge expired"}
        except jwt.InvalidTokenError as e:
            return {"valid": False, "reason": str(e)}
