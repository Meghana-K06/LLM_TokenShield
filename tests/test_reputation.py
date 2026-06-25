import sys
sys.path.insert(0, "/home/meghana/Desktop/twinshield/backend")

import pytest
from layers.reputation import ReputationEngine

r = ReputationEngine()

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
