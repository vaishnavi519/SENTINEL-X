"""
SENTINEL-X — Application Configuration
========================================
Loads settings from environment variables and/or a .env file.
Values in .env override the defaults defined here.
Values set directly in the environment override .env.

Usage:
    from app.config import get_settings
    settings = get_settings()
    print(settings.max_input_chars)
"""

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


# Absolute path to the backend/ directory
BACKEND_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    """
    All configurable settings for SENTINEL-X.

    Priority (highest → lowest):
        1. Actual environment variables
        2. Values in .env file
        3. Default values defined below

    NOTE: Risk weights are documented as provisional.
    They should be tuned experimentally during Phase 7 evaluation.
    """

    # ── Application ────────────────────────────────────────────
    app_name: str = "SENTINEL-X"
    app_version: str = "0.1.0"
    debug: bool = False

    # ── Server ─────────────────────────────────────────────────
    host: str = "0.0.0.0"
    port: int = 8000

    # ── Security Controls ──────────────────────────────────────
    max_input_chars: int = Field(default=10_000, gt=0, le=100_000)
    request_rate_limit: str = "60/minute"

    # ── Database ───────────────────────────────────────────────
    database_url: str = f"sqlite+aiosqlite:///{BACKEND_DIR}/sentinel_x.db"

    # ── Risk Engine Weights ────────────────────────────────────
    # IMPORTANT: Provisional values. Not scientifically optimized.
    # Tune via Phase 7 experimental evaluation.
    weight_injection: float = Field(default=0.30, ge=0.0, le=1.0)
    weight_pii: float = Field(default=0.15, ge=0.0, le=1.0)
    weight_secrets: float = Field(default=0.20, ge=0.0, le=1.0)
    weight_toxicity: float = Field(default=0.15, ge=0.0, le=1.0)
    weight_intent: float = Field(default=0.10, ge=0.0, le=1.0)
    weight_session: float = Field(default=0.10, ge=0.0, le=1.0)

    # ── Risk Thresholds (0–100 scale) ──────────────────────────
    risk_low_max: int = 20        # 0–20   → LOW
    risk_moderate_max: int = 40   # 21–40  → MODERATE
    risk_high_max: int = 60       # 41–60  → HIGH
    risk_very_high_max: int = 80  # 61–80  → VERY_HIGH
                                  # 81–100 → CRITICAL

    # ── Prompt Injection Detector ───────────────────────────────
    injection_layer2_threshold: float = Field(default=0.65, ge=0.0, le=1.0)

    # ── Session Risk State Machine ──────────────────────────────
    session_watch_threshold: int = 30
    session_high_risk_threshold: int = 50
    session_restricted_threshold: int = 70
    session_quarantined_threshold: int = 85
    session_terminated_threshold: int = 95

    # ── LLM ────────────────────────────────────────────────────
    default_llm_provider: str = "mock"   # mock | groq | gemini
    llm_timeout_seconds: float = 30.0

    # Optional API keys — never required (mock works without them)
    groq_api_key: str = ""
    gemini_api_key: str = ""

    # ── Logging ────────────────────────────────────────────────
    log_level: str = "INFO"
    log_raw_input: bool = False  # NEVER log raw user content by default

    model_config = SettingsConfigDict(
        env_file=str(BACKEND_DIR / ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    def risk_level_for_score(self, score: float) -> str:
        """Convert a numeric risk score (0-100) to a risk level label."""
        if score <= self.risk_low_max:
            return "LOW"
        elif score <= self.risk_moderate_max:
            return "MODERATE"
        elif score <= self.risk_high_max:
            return "HIGH"
        elif score <= self.risk_very_high_max:
            return "VERY_HIGH"
        else:
            return "CRITICAL"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """
    Return the cached application settings.
    The settings object is created once and reused for the lifetime of the process.
    Call `get_settings.cache_clear()` in tests to reset between test cases.
    """
    return Settings()
