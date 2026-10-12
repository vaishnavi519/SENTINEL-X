"""
SENTINEL-X — Quarantine ORM Model
===================================
Records requests that have been quarantined due to high risk.
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

class QuarantineRecord(Base):
    __tablename__ = "quarantine_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    q_id: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        unique=True,
        index=True,
        default=lambda: f"Q-{uuid.uuid4().hex[:8].upper()}",
    )
    request_id: Mapped[str] = mapped_column(String(36), nullable=False)
    session_id: Mapped[str] = mapped_column(String(36), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
    )
    
    input_text: Mapped[str] = mapped_column(Text, nullable=False)
    input_source: Mapped[str] = mapped_column(String(50), nullable=False)
    
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    threats: Mapped[list | None] = mapped_column(JSON, nullable=True)
    decision_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="QUARANTINED", # QUARANTINED | RELEASED | REJECTED
    )
    
    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "q_id": self.q_id,
            "request_id": self.request_id,
            "session_id": self.session_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "input_text": self.input_text,
            "input_source": self.input_source,
            "risk_score": self.risk_score,
            "threats": self.threats,
            "decision_reason": self.decision_reason,
            "status": self.status,
        }
