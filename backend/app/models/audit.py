"""
SENTINEL-X — Audit Log ORM Model
===================================
Records every security-relevant request processed by SENTINEL-X.

Security notes:
  - Raw PII and secrets are NEVER stored. Only redacted versions.
  - Raw user input is only stored if log_raw_input=True AND it has
    been fully sanitized first (PII/secret redacted).
  - The log itself is a sensitive artifact and should be protected.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    Integer,
    JSON,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AuditLog(Base):
    """
    One row per request processed through the SENTINEL-X pipeline.

    Columns are intentionally wide to avoid joins during log analysis.
    """

    __tablename__ = "audit_log"

    # ── Identity ──────────────────────────────────────────────
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    request_id: Mapped[str] = mapped_column(
        String(36),
        nullable=False,
        index=True,
        default=lambda: str(uuid.uuid4()),
        comment="UUID assigned to this request. Returned in API responses.",
    )
    session_id: Mapped[str] = mapped_column(
        String(36),
        nullable=False,
        index=True,
        comment="Session UUID. Tracks multi-turn conversations.",
    )

    # ── Timing ────────────────────────────────────────────────
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        index=True,
        comment="UTC timestamp when the request was received.",
    )
    total_latency_ms: Mapped[float] = mapped_column(
        Float,
        nullable=True,
        comment="Total end-to-end latency in milliseconds.",
    )
    security_latency_ms: Mapped[float] = mapped_column(
        Float,
        nullable=True,
        comment="Security pipeline latency only (excludes LLM time).",
    )

    # ── Input ─────────────────────────────────────────────────
    # NOTE: We store a *sanitized* snapshot of the input, not the raw value.
    input_sanitized: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Input after PII/secret redaction. Only stored if log_raw_input=True.",
    )
    input_char_count: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        comment="Character count of the original input (before normalization).",
    )
    input_source: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="USER_INPUT",
        comment="Source classification: USER_INPUT | SYSTEM | TOOL_OUTPUT | RAG_DOCUMENT",
    )

    # ── Normalization Flags ────────────────────────────────────
    normalization_flags: Mapped[list | None] = mapped_column(
        JSON,
        nullable=True,
        comment="List of suspicious encoding flags detected by the normalizer.",
    )

    # ── Detector Results ──────────────────────────────────────
    injection_detected: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    injection_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    injection_category: Mapped[str | None] = mapped_column(String(50), nullable=True)
    injection_severity: Mapped[str | None] = mapped_column(String(20), nullable=True)

    pii_detected: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    pii_types: Mapped[list | None] = mapped_column(JSON, nullable=True)

    secrets_detected: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    secret_types: Mapped[list | None] = mapped_column(JSON, nullable=True)

    toxicity_detected: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    toxicity_category: Mapped[str | None] = mapped_column(String(50), nullable=True)
    toxicity_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)

    intent_category: Mapped[str | None] = mapped_column(String(50), nullable=True)
    intent_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)

    # ── Risk Engine ────────────────────────────────────────────
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    risk_level: Mapped[str | None] = mapped_column(String(20), nullable=True)
    contributing_factors: Mapped[list | None] = mapped_column(JSON, nullable=True)

    # ── Session State ─────────────────────────────────────────
    session_risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    session_state: Mapped[str | None] = mapped_column(String(30), nullable=True)

    # ── Policy Engine ─────────────────────────────────────────
    decision: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="ALLOW",
        index=True,
        comment="Final decision: ALLOW | SANITIZE | QUARANTINE | BLOCK",
    )
    triggered_policies: Mapped[list | None] = mapped_column(JSON, nullable=True)

    # ── LLM ───────────────────────────────────────────────────
    llm_provider: Mapped[str | None] = mapped_column(String(30), nullable=True)
    llm_latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)

    # ── Output ────────────────────────────────────────────────
    output_scan_passed: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    output_pii_detected: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    output_secrets_detected: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    output_canary_triggered: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # ── Tool Calls ────────────────────────────────────────────
    tool_call_requested: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    tool_call_blocked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    tool_name: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # ── Error Handling ────────────────────────────────────────
    pipeline_error: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "request_id": self.request_id,
            "session_id": self.session_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "total_latency_ms": self.total_latency_ms,
            "security_latency_ms": self.security_latency_ms,
            "input_char_count": self.input_char_count,
            "input_source": self.input_source,
            "normalization_flags": self.normalization_flags,
            "injection_detected": self.injection_detected,
            "injection_confidence": self.injection_confidence,
            "injection_category": self.injection_category,
            "injection_severity": self.injection_severity,
            "pii_detected": self.pii_detected,
            "pii_types": self.pii_types,
            "secrets_detected": self.secrets_detected,
            "secret_types": self.secret_types,
            "toxicity_detected": self.toxicity_detected,
            "intent_category": self.intent_category,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "contributing_factors": self.contributing_factors,
            "session_risk_score": self.session_risk_score,
            "session_state": self.session_state,
            "decision": self.decision,
            "triggered_policies": self.triggered_policies,
            "llm_provider": self.llm_provider,
            "llm_latency_ms": self.llm_latency_ms,
            "output_scan_passed": self.output_scan_passed,
        }

    def __repr__(self) -> str:
        return (
            f"<AuditLog id={self.id} request_id={self.request_id!r} "
            f"decision={self.decision!r} risk={self.risk_score}>"
        )
