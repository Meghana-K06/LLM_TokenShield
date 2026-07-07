from pydantic_settings import BaseSettings
from functools import lru_cache

class Settings(BaseSettings):
    #Quota
    QUOTA_LIMIT: int = 5          # requests per 1hr
    QUOTA_WINDOW_SECONDS: int = 3600 # 1hr

    # App
    APP_NAME: str = "TwinShield"
    APP_HOST: str = "0.0.0.0"
    APP_PORT: int = 8000
    DEBUG: bool = True

    # Redis
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0

    # Ollama
    OLLAMA_HOST: str = "http://localhost:11434"
    OLLAMA_TARGET_MODEL: str = "mistral"
    OLLAMA_DEFENDER_MODEL: str = "mistral"
    OLLAMA_EMBEDDING_MODEL: str = "nomic-embed-text"

    # Layer 3: Lakera Guard (cloud detector, runs alongside local detectors)
    ENABLE_LAKERA: bool = True
    LAKERA_API_KEY: str = ""             # set in .env, never commit this
    LAKERA_API_URL: str = "https://api.lakera.ai/v2/guard"
    LAKERA_PROJECT_ID: str = ""          # optional, uses default policy if blank
    LAKERA_TIMEOUT_SECONDS: float = 5.0  # short timeout so a slow/dead API doesn't stall the request

    # Layer 3: semantic similarity detector (embedding-based, local/offline)
    ENABLE_SEMANTIC_DETECTION: bool = True
    SEMANTIC_SIMILARITY_THRESHOLD: float = 0.80  # cosine similarity to flag a match
    SEMANTIC_SCORE_WEIGHT: float = 30.0          # (currently unused by risk.py's max-score logic, kept for reference)

    # JWT
    JWT_SECRET: str = "twinshield-secret-key-change-in-prod"
    JWT_EXPIRY_SECONDS: int = 300

    # Thresholds
    MAX_AMPLIFICATION_MULTIPLIER: float = 5.0
    CHALLENGE_TRUST_THRESHOLD: float = 0.4
    CHALLENGE_COST_THRESHOLD: int = 70
    TOKEN_BUDGET_LOW: int = 5000
    TOKEN_BUDGET_MEDIUM: int = 2000
    TOKEN_BUDGET_HIGH: int = 500

    class Config:
        env_file = ".env"

@lru_cache()
def get_settings() -> Settings:
    return Settings()
