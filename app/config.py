import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

# --- Service endpoints ---
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))

# Ollama embedding backend for Layer 3 (nomic-embed-text) — same model
# TwinShield's real semantic_similarity.py uses. Requires Ollama running
# locally with `ollama pull nomic-embed-text`.
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_EMBED_MODEL = os.getenv("OLLAMA_EMBED_MODEL", "nomic-embed-text")

# Lakera Guard API (Layer 5 — Twin AI Security Reviewer)
# Matches TwinShield's real config.py field names exactly.
ENABLE_LAKERA = os.getenv("ENABLE_LAKERA", "true").lower() == "true"
LAKERA_API_KEY = os.getenv("LAKERA_API_KEY", "")
LAKERA_API_URL = os.getenv("LAKERA_API_URL", "https://api.lakera.ai/v2/guard")
LAKERA_PROJECT_ID = os.getenv("LAKERA_PROJECT_ID", "")
LAKERA_TIMEOUT_SECONDS = float(os.getenv("LAKERA_TIMEOUT_SECONDS", "5.0"))

# --- Gateway security ---
API_KEY = os.getenv("API_KEY", "changeme-internship-demo-key")

# --- Layer 1: Auth & Input Validation ---
# 0/None = no ceiling (matches TwinShield's real Layer 1, which doesn't
# reject on size — cost is handled downstream). Set a positive int to
# enforce a hard token ceiling in this standalone demo if you want one.
MAX_PAYLOAD_TOKENS = int(os.getenv("MAX_PAYLOAD_TOKENS", "0"))
QUOTA_LIMIT = int(os.getenv("QUOTA_LIMIT", "5"))                    # requests per window, feeds Layer 4 (matches TwinShield's default)
QUOTA_WINDOW_SECONDS = int(os.getenv("QUOTA_WINDOW_SECONDS", "3600"))  # matches TwinShield's 1hr default

# --- Layer 2: ML Defender — Entropy Engine ---
# Direct port of TwinShield's backend/layers/entropy.py — scores 0-100,
# combined via a trained sklearn Pipeline (StandardScaler + LogisticRegression).
ENTROPY_MODEL_PATH = os.path.join(BASE_DIR, "ml", "cost_classifier.joblib")

# --- Layer 3: ML Risk Engine — Vector / Cosine Similarity ---
# Direct port of TwinShield's backend/layers/semantic_similarity.py.
# Default matches TwinShield exactly: real Ollama nomic-embed-text
# embeddings against ml/semantic_exemplars.py's EXEMPLAR_BANK. If Ollama
# is unreachable, TwinShield's real behavior is to fail safe (no flags,
# no signal from this layer) — set SEMANTIC_FALLBACK_TFIDF=true to
# instead use an offline TF-IDF approximation so this layer still says
# something useful when Ollama isn't running. Off by default to match
# your real system's behavior exactly.
SEMANTIC_SIMILARITY_THRESHOLD = float(os.getenv("SEMANTIC_SIMILARITY_THRESHOLD", "0.80"))
SEMANTIC_FALLBACK_TFIDF = os.getenv("SEMANTIC_FALLBACK_TFIDF", "false").lower() == "true"

# --- Decision Fusion weights (must sum to 1.0) ---
WEIGHT_ENTROPY_DEFENDER = 0.35   # Layer 2
WEIGHT_SEMANTIC_RISK = 0.40      # Layer 3
WEIGHT_REPUTATION = 0.25         # Layer 4

# --- Twin AI trigger ---
# confidence = agreement-weighted distance of fused score from the 0.5 boundary
# low confidence (ambiguous / borderline) => escalate to Layer 5 (Lakera Twin Reviewer)
TWIN_THRESHOLD = float(os.getenv("TWIN_THRESHOLD", "0.45"))

# --- Final block threshold (0 = benign .. 1 = malicious) ---
BLOCK_THRESHOLD = 0.6

# --- Layer 4: Redis Correlation & Reputation ---
MAX_REQUESTS_PER_WINDOW = QUOTA_LIMIT
WINDOW_SECONDS = QUOTA_WINDOW_SECONDS
REPUTATION_DECAY_ON_MALICIOUS = 0.25
REPUTATION_COOLDOWN_ON_CLEAN = 0.05
REPUTATION_TTL_SECONDS = 60 * 60 * 24  # 1 day

# Note: blacklist Redis key names (`blacklist:users`, `blacklist:meta:{id}`)
# live directly in layer1_auth_validation.py to match TwinShield's real
# backend/layers/auth.py exactly.
