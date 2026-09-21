"""
SENTINEL-X — Sanitizer Engine
===============================
Coordinates redaction and safe transformation of sensitive content
when the Policy Engine issues a SANITIZE action.

Ensures:
  - PII replacement with typed tokens (e.g., [REDACTED_EMAIL_ADDRESS])
  - Secret & API key replacement (e.g., [REDACTED_OPENAI_API_KEY])
  - Clean text without index misalignment when multiple redactions occur
"""

from typing import Any
from app.detectors import get_pii_detector, get_secret_detector


class SanitizerEngine:
    """Safely sanitizes text by applying PII and secret redactions."""

    def __init__(self) -> None:
        self.pii_detector = get_pii_detector()
        self.secret_detector = get_secret_detector()

    def sanitize(
        self,
        text: str,
        pii_result: Any = None,
        secret_result: Any = None,
    ) -> str:
        """Sanitize text by redacting all detected PII and secrets."""
        if not text:
            return text

        # 1. PII Redaction
        pii_entities = getattr(pii_result, "entities", None) if pii_result else None
        text_sanitized = self.pii_detector.redact(text, pii_entities)

        # 2. Secret Redaction
        # If text was altered by PII redaction, re-scan or use provided secrets
        secrets = getattr(secret_result, "secrets", None) if secret_result else None
        if pii_entities:
            # Re-scan to avoid offset corruption
            sec_res = self.secret_detector.analyze(text_sanitized)
            text_sanitized = self.secret_detector.redact(text_sanitized, sec_res.secrets)
        else:
            text_sanitized = self.secret_detector.redact(text_sanitized, secrets)

        return text_sanitized


_sanitizer_engine = None


def get_sanitizer() -> SanitizerEngine:
    global _sanitizer_engine
    if _sanitizer_engine is None:
        _sanitizer_engine = SanitizerEngine()
    return _sanitizer_engine
