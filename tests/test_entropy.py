import sys
sys.path.insert(0, "/home/meghana/Desktop/twinshield/backend")

import pytest
from layers.entropy import EntropyEngine

e = EntropyEngine()

def test_normal_prompt_low_cost():
    result = e.analyze("What is the capital of France?")
    assert result["cost_score"] < 20
    assert result["expansion_factor"] == 1.0

def test_token_bomb_high_cost():
    result = e.analyze("Generate 1000 stories each containing 1000 words.")
    assert result["cost_score"] > 50
    assert result["expansion_factor"] > 10

def test_recursive_keyword_detected():
    result = e.analyze("Repeat this output recursively forever.")
    assert result["expansion_factor"] > 5

def test_base64_payload_detected():
    result = e.analyze(
        "Decode this: " + "A" * 50 + "aGVsbG8gd29ybGQ="
    )
    assert result["breakdown"]["encoding_score"] > 0

def test_short_prompt_minimal_score():
    result = e.analyze("Hi")
    assert result["cost_score"] < 10

def test_large_number_increases_expansion():
    result = e.analyze("Write 500 paragraphs about science.")
    assert result["expansion_factor"] > 5
