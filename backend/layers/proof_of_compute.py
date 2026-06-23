import hashlib
import json
import time
import jwt
from config import get_settings

settings = get_settings()

class ProofOfCompute:
    """
    Verifies client solved a SHA256 proof-of-work challenge.

    Client must find a nonce N such that:
        SHA256(challenge_string + N) starts with '0000'

    Submission format (JSON string):
    {
        "jwt":   "<original challenge JWT>",
        "nonce": "<solution nonce>"
    }
    """

    PREFIX = "0000"   # difficulty target

    def verify(self, submission: str) -> dict:
        # Parse submission
        try:
            data  = json.loads(submission)
            token = data.get("jwt", "")
            nonce = str(data.get("nonce", ""))
        except (json.JSONDecodeError, AttributeError):
            return {"verified": False, "reason": "invalid submission format"}

        # Validate JWT
        try:
            payload = jwt.decode(
                token,
                settings.JWT_SECRET,
                algorithms=["HS256"]
            )
        except jwt.ExpiredSignatureError:
            return {"verified": False, "reason": "challenge JWT expired"}
        except jwt.InvalidTokenError:
            return {"verified": False, "reason": "invalid challenge JWT"}

        # Check freshness (must be solved within expiry window)
        issued_at = payload.get("issued_at", 0)
        age       = time.time() - issued_at
        if age > settings.JWT_EXPIRY_SECONDS:
            return {"verified": False, "reason": "challenge too old"}

        # Verify proof-of-work
        challenge_str = payload.get("challenge", "")
        candidate     = hashlib.sha256(
            f"{challenge_str}{nonce}".encode()
        ).hexdigest()

        if not candidate.startswith(self.PREFIX):
            return {
                "verified": False,
                "reason":   f"invalid nonce — hash does not start with {self.PREFIX}",
                "got":      candidate[:8]
            }

        return {
            "verified":   True,
            "user_id":    payload.get("user_id"),
            "solved_in":  round(age, 2),
        }

    @staticmethod
    def solve(challenge_jwt: str) -> dict:
        """
        Helper method — solves the proof-of-work locally.
        Used by the attack simulator and dashboard demos.
        """
        try:
            payload = jwt.decode(
                challenge_jwt,
                settings.JWT_SECRET,
                algorithms=["HS256"]
            )
        except jwt.InvalidTokenError as e:
            return {"solved": False, "reason": str(e)}

        challenge_str = payload.get("challenge", "")
        nonce         = 0
        start         = time.time()

        while True:
            candidate = hashlib.sha256(
                f"{challenge_str}{nonce}".encode()
            ).hexdigest()
            if candidate.startswith("0000"):
                elapsed = round(time.time() - start, 3)
                return {
                    "solved":      True,
                    "nonce":       nonce,
                    "hash":        candidate,
                    "time_seconds": elapsed,
                    "submission":  json.dumps({
                        "jwt":   challenge_jwt,
                        "nonce": nonce
                    })
                }
            nonce += 1
            if nonce > 10_000_000:
                return {"solved": False, "reason": "max iterations exceeded"}
