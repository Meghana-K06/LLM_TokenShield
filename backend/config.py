from pydantic_settings import BaseSettings
from functools import lru_cache

class Settings(BaseSettings):
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
