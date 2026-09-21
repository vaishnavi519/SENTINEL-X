"""
SENTINEL-X — Audit & Telemetry API Router
===========================================
Exposes historical security events and real-time dashboard statistics.

Endpoints:
  GET /api/v1/audit/logs    → Paginated security audit event trail
  GET /api/v1/audit/stats   → High-level metrics for dashboard cards
  GET /api/v1/audit/session/{session_id} → Multi-turn session risk progression
"""

from typing import Any
from fastapi import APIRouter, Query

from app.core.audit_logger import AuditLogger
from app.core.session_risk import get_session_tracker

router = APIRouter(prefix="/audit", tags=["Audit & Telemetry"])


@router.get("/logs", summary="Get Security Audit Logs")
async def get_logs(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    decision: str | None = Query(default=None),
    session_id: str | None = Query(default=None),
) -> dict[str, Any]:
    logs = await AuditLogger.query_logs(
        limit=limit,
        offset=offset,
        decision=decision,
        session_id=session_id,
    )
    return {"count": len(logs), "offset": offset, "limit": limit, "data": logs}


@router.get("/stats", summary="Get Dashboard Telemetry Metrics")
async def get_stats() -> dict[str, Any]:
    return await AuditLogger.get_summary_stats()


@router.get("/session/{session_id}", summary="Get Session Threat Progression")
async def get_session_history(session_id: str) -> dict[str, Any]:
    tracker = get_session_tracker()
    session = tracker.get_or_create(session_id)
    return {
        "session_id": session.session_id,
        "state": session.state,
        "accumulated_risk": round(session.accumulated_risk, 2),
        "request_count": session.request_count,
        "history": [
            {
                "timestamp": turn.timestamp,
                "risk_score": turn.risk_score,
                "decision": turn.decision,
                "threats": turn.threats,
            }
            for turn in session.history
        ],
    }
