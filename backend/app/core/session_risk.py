"""
SENTINEL-X — Adaptive Session Risk Engine
===========================================
Maintains multi-turn state machines to track cumulative user risk
and detect progressive / distributed prompt injection attacks.

State Machine:
  NORMAL ──(≥30)──► WATCH ──(≥50)──► HIGH_RISK ──(≥70)──► RESTRICTED ──(≥85)──► QUARANTINED
     ▲                │                 │                    │                       │
     └───(decay)──────┴──────(decay)────┴──────(decay)───────┴───────────────────────┘

Features:
  - Exponential moving accumulation: 60% historical risk + 40% current interaction risk
  - Benign decay: successful clean interactions reduce accumulated risk over time
  - Session history buffer: stores recent threat signals for forensic explainability
"""

from dataclasses import dataclass, field
import time
from typing import Any
from app.config import get_settings


@dataclass
class SessionTurn:
    timestamp: float
    risk_score: float
    decision: str
    threats: list[str] = field(default_factory=list)


@dataclass
class SessionRecord:
    session_id: str
    state: str = "NORMAL"  # NORMAL | WATCH | HIGH_RISK | RESTRICTED | QUARANTINED
    accumulated_risk: float = 0.0
    request_count: int = 0
    history: list[SessionTurn] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    last_active: float = field(default_factory=time.time)


class SessionRiskTracker:
    """Manages adaptive session risk state machines across conversation turns."""

    def __init__(self) -> None:
        self.settings = get_settings()
        self._sessions: dict[str, SessionRecord] = {}

    def get_or_create(self, session_id: str) -> SessionRecord:
        if session_id not in self._sessions:
            self._sessions[session_id] = SessionRecord(session_id=session_id)
        return self._sessions[session_id]

    def record_turn(
        self,
        session_id: str,
        risk_score: float,
        decision: str,
        threats: list[str] | None = None,
    ) -> SessionRecord:
        session = self.get_or_create(session_id)
        session.request_count += 1
        session.last_active = time.time()

        threat_list = threats or []

        # If clean turn, apply decay
        if risk_score < self.settings.risk_low_max:
            # 15% decay on benign query
            session.accumulated_risk = max(0.0, session.accumulated_risk * 0.85)
        else:
            # Threat accumulation
            session.accumulated_risk = (
                0.60 * session.accumulated_risk + 0.40 * risk_score
            )

        # Transition State Machine
        acc = session.accumulated_risk
        if acc >= self.settings.session_quarantined_threshold:
            session.state = "QUARANTINED"
        elif acc >= self.settings.session_restricted_threshold:
            session.state = "RESTRICTED"
        elif acc >= self.settings.session_high_risk_threshold:
            session.state = "HIGH_RISK"
        elif acc >= self.settings.session_watch_threshold:
            session.state = "WATCH"
        else:
            session.state = "NORMAL"

        session.history.append(
            SessionTurn(
                timestamp=time.time(),
                risk_score=risk_score,
                decision=decision,
                threats=threat_list,
            )
        )
        if len(session.history) > 20:
            session.history.pop(0)

        return session

    def reset(self, session_id: str) -> SessionRecord:
        """Reset session to pristine NORMAL state."""
        rec = SessionRecord(session_id=session_id)
        self._sessions[session_id] = rec
        return rec


_session_tracker = None


def get_session_tracker() -> SessionRiskTracker:
    global _session_tracker
    if _session_tracker is None:
        _session_tracker = SessionRiskTracker()
    return _session_tracker
