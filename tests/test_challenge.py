import sys
sys.path.insert(0, "/home/meghana/Desktop/twinshield/backend")

import pytest
import json
from layers.challenge import ChallengeGenerator
from layers.proof_of_compute import ProofOfCompute

cg  = ChallengeGenerator()
poc = ProofOfCompute()

def test_no_challenge_high_trust():
    result = cg.evaluate("user1", trust_score=0.9, cost_score=20)
    assert result["challenge_required"] == False

def test_challenge_triggered_low_trust_high_cost():
    result = cg.evaluate("user2", trust_score=0.2, cost_score=85)
    assert result["challenge_required"] == True
    assert result["challenge_jwt"] is not None

def test_challenge_not_triggered_low_trust_low_cost():
    result = cg.evaluate("user3", trust_score=0.2, cost_score=30)
    assert result["challenge_required"] == False

def test_challenge_not_triggered_high_trust_high_cost():
    result = cg.evaluate("user4", trust_score=0.9, cost_score=90)
    assert result["challenge_required"] == False

def test_proof_of_compute_solve_and_verify():
    challenge = cg.evaluate("user5", trust_score=0.2, cost_score=85)
    assert challenge["challenge_required"] == True

    solution = ProofOfCompute.solve(challenge["challenge_jwt"])
    assert solution["solved"] == True
    assert solution["nonce"] >= 0

    verified = poc.verify(solution["submission"])
    assert verified["verified"] == True

def test_invalid_submission_rejected():
    result = poc.verify('{"jwt": "fake", "nonce": 0}')
    assert result["verified"] == False

def test_wrong_nonce_rejected():
    challenge = cg.evaluate("user6", trust_score=0.2, cost_score=85)
    submission = json.dumps({
        "jwt":   challenge["challenge_jwt"],
        "nonce": 99999999
    })
    result = poc.verify(submission)
    assert result["verified"] == False
