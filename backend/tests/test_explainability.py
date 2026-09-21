"""
SENTINEL-X — Explainability & Audit Tests
==========================================
Unit tests for app.core.explainability, app.core.receipt_generator,
and app.core.audit_logger.

Coverage:
  - ExplainabilityEngine narrative summaries and percentage influence calculation
  - Remediation recommendations for security threats
  - ReceiptGenerator cryptographic SHA-256 signing and verification
  - AuditLogger query operations and metric aggregations
  - Audit REST endpoints
"""

import pytest
from httpx import ASGITransport, AsyncClient

from app.core.explainability import ExplainabilityEngine
from app.core.receipt_generator import ReceiptGenerator
from app.core.audit_logger import AuditLogger
from app.schemas.response import PolicyDecision, RiskFactor, RiskResult
from app.main import create_app


@pytest.fixture
def explainability_engine():
    return ExplainabilityEngine()


@pytest.fixture
def receipt_generator():
    return ReceiptGenerator()


class TestExplainabilityAndReceipts:
    """Test explainability summaries and tamper-evident receipts."""

    def test_explainability_narrative_and_rankings(self, explainability_engine):
        decision = PolicyDecision(
            action="BLOCK",
            triggered_policies=["P-001 (Direct Prompt Injection)"],
            reason="High-confidence prompt injection attack detected.",
        )
        risk = RiskResult(
            score=75.0,
            level="VERY_HIGH",
            contributing_factors=[
                RiskFactor(name="Prompt Injection", contribution=60.0, description="Direct override"),
                RiskFactor(name="Source Trust", contribution=15.0, description="Untrusted external"),
            ],
        )
        explanation = explainability_engine.explain(
            decision=decision,
            risk=risk,
            threat_labels=["INJECTION:INSTRUCTION_OVERRIDE"],
        )
        assert "BLOCKED" in explanation.summary
        assert len(explanation.top_factors) == 2
        # Verify percentage influence
        assert explanation.top_factors[0]["percentage_influence"] == 80.0
        assert explanation.top_factors[1]["percentage_influence"] == 20.0
        assert len(explanation.recommendations) >= 1

    def test_receipt_signature_and_verification(self, receipt_generator):
        decision = PolicyDecision(action="ALLOW", triggered_policies=[], reason="Safe")
        risk = RiskResult(score=10.0, level="LOW")

        receipt = receipt_generator.generate(
            request_id="req-1234",
            session_id="sess-5678",
            decision=decision,
            risk=risk,
            threats_detected=[],
            pii_detected=False,
            secrets_detected=False,
            latency_ms=25.4,
        )
        assert receipt_generator.verify(receipt) is True
        assert "[Sig:" in receipt.explanation


@pytest.mark.asyncio
class TestAuditEndpoints:
    """Test audit logging queries and summary stats API."""

    async def test_audit_api_queries(self):
        app = create_app()
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # 1. Stats endpoint
            stats_resp = await client.get("/api/v1/audit/stats")
            assert stats_resp.status_code == 200
            stats = stats_resp.json()
            assert "total_requests" in stats
            assert "decisions" in stats

            # 2. Logs endpoint
            logs_resp = await client.get("/api/v1/audit/logs?limit=10")
            assert logs_resp.status_code == 200
            logs_data = logs_resp.json()
            assert "data" in logs_data

            # 3. Session history endpoint
            sess_resp = await client.get("/api/v1/audit/session/non-existent-session")
            assert sess_resp.status_code == 200
            sess_data = sess_resp.json()
            assert sess_data["state"] == "NORMAL"
