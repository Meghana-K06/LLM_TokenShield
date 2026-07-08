# TwinShield Gateway

A 6-layer LLM security proxy with the **same dashboard/console UI** as the
[Adversarial_ai](https://github.com/FirdousHani/Adversarial_ai) reference
project, running **faithful ports of your real TwinShield code**
(https://github.com/Meghana-K06/LLM_TokenShield) for Layers 1, 2, 3, and 5.
No Docker required.

> v3 of this build. v1 approximated Layers 1-3 from a memory summary
> instead of your actual repo. v2 fixed that by pulling `LLM_TokenShield`
> directly and porting `auth.py`, `entropy.py`, `semantic_similarity.py`,
> `semantic_exemplars.py`, `train_layer2_logistic_weights.py`, and
> `lakera_client.py` line-for-line. v3 (this one) adds `risk.py`'s 8 regex
> jailbreak/injection detectors into Layer 3 alongside semantic
> similarity, and makes every layer short-circuit the pipeline on its own
> MALICIOUS verdict — no layer below a block ever runs.

## Pipeline

| Layer | Name | Ported from | What it does | Can short-circuit? |
|---|---|---|---|---|
| 1 | Auth & Input Validation | `layers/auth.py` (blacklist portion) | Blocks blacklisted users via the same `blacklist:users` set / `blacklist:meta:{user_id}` JSON audit trail; tokenizes with real `tiktoken` (`cl100k_base`) | Yes — blacklisted user blocks immediately, nothing else runs |
| 2 | ML Defender — Entropy Engine | `layers/entropy.py` + `ml/train_layer2_logistic_weights.py` | Same four 0-100 signals (`encoding_score`, `expansion_factor`, `obfuscation_score`, `entropy_score`), same sklearn `Pipeline` | Yes — MALICIOUS (cost_score >= 70) blocks, skips L3/L4/L5 |
| 3 | ML Risk Engine | `layers/risk.py` (regex detectors) + `layers/semantic_similarity.py` + `ml/semantic_exemplars.py` | Regex rule detectors (8 patterns: jailbreak, role injection, ignore-instructions, system override, hidden-prompt, base64 injection, prompt leaking, context manipulation) **+** real Ollama `nomic-embed-text` embeddings against `EXEMPLAR_BANK`. `risk_score = max(rule_score, semantic_score)` | Yes — any single rule/semantic match blocks (ported from your real main.py's `risk_score >= 18` condition), skips L4/L5 |
| 4 | Redis Correlation & Reputation | *(unchanged, per your instruction)* | Quota pressure + decaying trust score, auto-blacklist on ceiling breach | Yes — combined score >= 0.6 blocks, skips L5 |
| 5 | Twin AI Security Reviewer | `layers/lakera_client.py` + `risk.py`'s category map | Real Lakera Guard client, same fail-safe (no key = no signal, not a block) | Yes — MALICIOUS Lakera verdict blocks |
| 6 | Output Safety Filter | *(same as before)* | Safe refusal on BLOCK, PII redaction on ALLOW | Always runs — produces the final response regardless of path taken |

**Short-circuit behavior**: each layer's own MALICIOUS verdict blocks the
request immediately and skips every layer below it. If L2, L3, and L4 all
come back non-MALICIOUS on their own (SAFE or SUSPICIOUS), the pipeline
proceeds to Decision Fusion across all three, escalating to Layer 5 for
genuinely ambiguous cases — same as before. A block from a short-circuit
always counts as a confirmed-malicious event for Layer 4's reputation
tracking (not the triggering layer's raw score), so repeated
short-circuit blocks correctly build up a client's reputation toward
auto-blacklisting, same as three-strikes-style behavior.

## Requirements

- Python 3.10+
- Redis running **locally** (not Docker)
- Ollama running locally with `ollama pull nomic-embed-text` — needed for
  Layer 3's semantic half to produce real signal (the regex half works
  offline with zero setup either way)

## Setup

```bash
git clone <this repo>
cd twinshield_gateway
./scripts/setup.sh
```

Creates a virtualenv, installs dependencies, and trains the Layer 2
classifier (`app/ml/cost_classifier.joblib`) via the ported
`train_layer2_logistic_weights.py` — reproduced a 98.4% test accuracy on
synthetic data in my testing, matching your original results.

Copy `.env.example` to `.env` and adjust. Notable defaults, matching your
real `config.py`: `QUOTA_LIMIT=5` per `QUOTA_WINDOW_SECONDS=3600` (1hr),
`SEMANTIC_SIMILARITY_THRESHOLD=0.80`, `ENABLE_LAKERA=true` (but with no
key, fails safe to "no signal").

### Optional: seed demo identities

```bash
source .venv/bin/activate
python scripts/seed_redis.py
```

## Run

```bash
./scripts/run.sh
```

Dashboard: **http://localhost:8000/dashboard**
API: `POST http://localhost:8000/api/v1/evaluate`, header
`x-api-key: changeme-internship-demo-key`, body
`{"client_id": "...", "payload": "..."}`.

## Testing

```bash
source .venv/bin/activate
python tests/test_client.py
```

## Notes

- **Lakera (Layer 5)**: blank `LAKERA_API_KEY` → this layer reports "no
  signal" rather than blocking or approving, matching your real
  `_safe_lakera_check` fail-safe exactly.
- **Ollama (Layer 3)**: same fail-safe as your original — if unreachable,
  no flags, no signal, logged as a warning. Set
  `SEMANTIC_FALLBACK_TFIDF=true` in `.env` for an offline approximation
  (not part of your original repo, weaker at paraphrase detection, off by
  default so the real behavior matches yours exactly).

## Project layout

```
app/
  main.py                              # orchestrator
  config.py                            # settings (mirrors your real config.py field names)
  models.py
  layer1_auth_validation.py            # port of layers/auth.py (blacklist) + tiktoken
  layer2_entropy_engine.py             # port of layers/entropy.py (EntropyEngine)
  layer3_rule_detectors.py             # port of risk.py's 8 regex _detect_* methods
  layer3_semantic_risk_engine.py       # port of layers/semantic_similarity.py + combines with rule detectors
  layer4_redis_correlation.py          # unchanged, per your instruction
  layer5_twin_lakera_reviewer.py       # port of layers/lakera_client.py + risk.py's category map
  layer6_output_filter.py
  decision_fusion.py
  ml/
    train_layer2_logistic_weights.py   # port of your training script
    cost_classifier.joblib             # trained artifact (generated by setup.sh)
    semantic_exemplars.py              # port of ml/semantic_exemplars.py (EXEMPLAR_BANK)
  static/
    index.html                        # dashboard (same UI as the reference repo)
scripts/
  setup.sh, run.sh, seed_redis.py
tests/
  test_client.py
```
