import sys
sys.path.insert(0, "/home/meghana/Desktop/twinshield/backend")

import pytest
import redis
from layers.reputation import ReputationEngine
from config import get_settings

settings = get_settings()
r = ReputationEngine()

_redis = redis.Redis(
    host=settings.REDIS_HOST,
    port=settings.REDIS_PORT,
    db=settings.REDIS_DB,
    decode_responses=True
)

# Every user_id this test file touches, kept in one place so cleanup
# can never drift out of sync with what the tests actually create.
TEST_USERS = [
    "pytest_new_user_001",
    "pytest_success_user",
    "pytest_abuse_user",
    "pytest_clamp_user",
    "pytest_floor_user",
    "pytest_tier_trusted",
    "pytest_tier_anon",
]


def _clear():
    for user in TEST_USERS:
        _redis.delete(f"reputation:{user}")
        _redis.srem("users:all_known", user)
        _redis.srem("blacklist:candidates", user)
        _redis.srem("blacklist:users", user)
        _redis.delete(f"blacklist:meta:{user}")


@pytest.fixture(autouse=True)
def clean_redis_state():
    """
    Runs before AND after every test in this file.

    Without this, test user_ids are hardcoded strings that persist in
    Redis (reputation keys carry a 30-day TTL), so a later pytest run
    inherits leftover state from an earlier run — a test asserting
    "a brand new user starts at 0.7 trust" silently becomes false once
    that user_id has abuse history from a previous run. Clearing before
    AND after means a crashed/interrupted run still leaves things clean
    for next time, not just successful runs.
    """
    _clear()
    yield
    _clear()


def test_new_user_default_score():
    result = r.get_score("pytest_new_user_001")
    assert result["trust_score"] >= 0.5
    assert result["tier"] in ["anonymous", "authenticated", "trusted"]

def test_success_increases_score():
    user = "pytest_success_user"
    initial = r.get_score(user)["trust_score"]
    r.record_success(user, 10)
    r.record_success(user, 10)
    after = r.get_score(user)["trust_score"]
    assert after > initial

def test_abuse_decreases_score():
    user = "pytest_abuse_user"
    r.record_success(user, 10)
    before = r.get_score(user)["trust_score"]
    r.record_abuse(user)
    after = r.get_score(user)["trust_score"]
    assert after < before

def test_score_clamped_to_one():
    user = "pytest_clamp_user"
    for _ in range(20):
        r.record_success(user, 5)
    result = r.get_score(user)
    assert result["trust_score"] <= 1.0

def test_score_never_below_zero():
    user = "pytest_floor_user"
    for _ in range(20):
        r.record_abuse(user)
    result = r.get_score(user)
    assert result["trust_score"] >= 0.0

def test_tier_trusted():
    user = "pytest_tier_trusted"
    for _ in range(10):
        r.record_success(user, 5)
    result = r.get_score(user)
    assert result["tier"] == "trusted"

def test_tier_anonymous_after_abuse():
    user = "pytest_tier_anon"
    for _ in range(5):
        r.record_abuse(user)
    result = r.get_score(user)
    assert result["tier"] in ["anonymous", "authenticated"]
