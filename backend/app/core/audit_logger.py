"""
SENTINEL-X — Audit Logger & Telemetry Engine
=============================================
Manages secure persistence and aggregation of all security transactions.
Provides forensic queries and dashboard telemetry metrics.
"""

from typing import Any
from sqlalchemy import select, func, desc

from app.db.database import get_db_session
from app.models.audit import AuditLog


class AuditLogger:
    """Handles structured persistence and analytics for security logs."""

    @staticmethod
    async def record_event(data: dict[str, Any]) -> None:
        """Persist a single security transaction asynchronously."""
        try:
            async with get_db_session() as session:
                entry = AuditLog(**data)
                session.add(entry)
        except Exception:
            # Audit log errors must never crash the application
            pass

    @staticmethod
    async def query_logs(
        limit: int = 50,
        offset: int = 0,
        decision: str | None = None,
        session_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Retrieve historical security events with optional filtering."""
        async with get_db_session() as session:
            stmt = select(AuditLog).order_by(desc(AuditLog.timestamp))
            if decision:
                stmt = stmt.where(AuditLog.decision == decision.upper())
            if session_id:
                stmt = stmt.where(AuditLog.session_id == session_id)
            stmt = stmt.limit(limit).offset(offset)

            result = await session.execute(stmt)
            records = result.scalars().all()
            return [r.to_dict() for r in records]

    @staticmethod
    async def get_summary_stats() -> dict[str, Any]:
        """Aggregate high-level metrics for dashboard telemetry."""
        async with get_db_session() as session:
            total_reqs = await session.scalar(select(func.count(AuditLog.id))) or 0
            blocks = await session.scalar(select(func.count(AuditLog.id)).where(AuditLog.decision == "BLOCK")) or 0
            sanitizes = await session.scalar(select(func.count(AuditLog.id)).where(AuditLog.decision == "SANITIZE")) or 0
            quarantines = await session.scalar(select(func.count(AuditLog.id)).where(AuditLog.decision == "QUARANTINE")) or 0
            allows = await session.scalar(select(func.count(AuditLog.id)).where(AuditLog.decision == "ALLOW")) or 0

            avg_latency = await session.scalar(select(func.avg(AuditLog.security_latency_ms))) or 0.0
            avg_risk = await session.scalar(select(func.avg(AuditLog.risk_score))) or 0.0

            # Threat distribution
            injections = await session.scalar(select(func.count(AuditLog.id)).where(AuditLog.injection_detected == True)) or 0
            pii = await session.scalar(select(func.count(AuditLog.id)).where(AuditLog.pii_detected == True)) or 0
            secrets = await session.scalar(select(func.count(AuditLog.id)).where(AuditLog.secrets_detected == True)) or 0
            toxicity = await session.scalar(select(func.count(AuditLog.id)).where(AuditLog.toxicity_detected == True)) or 0

            return {
                "total_requests": total_reqs,
                "decisions": {
                    "ALLOW": allows,
                    "SANITIZE": sanitizes,
                    "QUARANTINE": quarantines,
                    "BLOCK": blocks,
                },
                "threat_counts": {
                    "prompt_injection": injections,
                    "pii_leakage": pii,
                    "secret_exposure": secrets,
                    "toxicity_and_harm": toxicity,
                },
                "performance": {
                    "avg_security_latency_ms": round(float(avg_latency), 2),
                    "avg_risk_score": round(float(avg_risk), 2),
                },
            }
