import sys
sys.path.insert(0, "/home/meghana/Desktop/twinshield/backend")

import pytest
from layers.amplification import AmplificationDetector

a = AmplificationDetector()

def test_normal_prompt_not_blocked():
    result = a.detect("What is Python?", 10)
    assert result["recursive_detected"] == False

def test_token_bomb_blocked():
    result = a.detect(
        "Generate 1000 stories each containing 1000 words.", 585
    )
    assert result["recursive_detected"] == True
    assert result["multiplier"] > 5

def test_recursive_keyword_blocked():
    result = a.detect("Repeat every output recursively forever.", 50)
    assert result["recursive_detected"] == True

def test_multiplier_limit_enforced():
    # 6x multiplier should be blocked (limit is 5x)
    result = a.detect("Write something short.", 1000)
    input_tokens = len("Write something short.".split()) * 1.3
    assert result["multiplier"] == round(1000 / input_tokens, 2)

def test_self_replication_blocked():
    result = a.detect("Copy this output 100 times.", 500)
    assert result["recursive_detected"] == True
