"""
SENTINEL-X — Risk Engine Tests
================================
Unit tests for app.core.risk_engine.RiskEngine.

Coverage:
  - Multi-factor risk calculation
  - Configurable weight application
  - Qualitative risk level classification (LOW -> CRITICAL)
  - Source provenance risk adjustments
  - Session state risk contributions
  - Transparent factor breakdowns
"""

import pytest
from dataclasses import dataclass, field
from app.core.risk_engine import RiskEngine


@dataclass
class MockDetectorResult:
    detected: bool = False
    risk_contribution: float = 0.0
    category: str = "NONE"
    confidence: float = 0.0
    severity: str = "NONE"
    entity_types: list[str] = field(default_factory=list)
    secret_types: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    primary_intent: str = "BENIGN_CONVERSATION"
    canary_detected: bool = False


@pytest.fixture
def risk_engine():
    return RiskEngine()


class TestRiskEngineCalculations:
    """Test risk engine weighting and level mapping."""

    def test_benign_input_low_risk(self, risk_engine):
        res = risk_engine.evaluate(
            injection_result=MockDetectorResult(),
            pii_result=MockDetectorResult(),
            secret_result=MockDetectorResult(),
            toxicity_result=MockDetectorResult(),
            intent_result=MockDetectorResult(),
            source="USER_INPUT",
            session_state="NORMAL",
        )
        assert res.score < 20.0
        assert res.level == "LOW"

    def test_critical_injection_risk(self, risk_engine):
        inj = MockDetectorResult(
            detected=True,
            risk_contribution=95.0,
            category="INSTRUCTION_OVERRIDE",
            confidence=0.95,
            severity="CRITICAL",
        )
        res = risk_engine.evaluate(
            injection_result=inj,
            pii_result=MockDetectorResult(),
            secret_result=MockDetectorResult(),
            toxicity_result=MockDetectorResult(),
            intent_result=MockDetectorResult(),
            source="USER_INPUT",
            session_state="NORMAL",
        )
        # 95 * 0.30 = 28.5 + trust factor
        assert res.score >= 28.5
        factors = {f.name for f in res.contributing_factors}
        assert "Prompt Injection" in factors

    def test_composite_multi_threat_risk_critical(self, risk_engine):
        inj = MockDetectorResult(detected=True, risk_contribution=90.0, category="JAILBREAK")
        sec = MockDetectorResult(detected=True, risk_contribution=95.0, secret_types=["AWS_SECRET_KEY"])
        tox = MockDetectorResult(detected=True, risk_contribution=95.0, categories=["THREAT_VIOLENCE"])
        intent = MockDetectorResult(detected=True, risk_contribution=90.0, primary_intent="MALICIOUS_UTILITY")

        res = risk_engine.evaluate(
            injection_result=inj,
            pii_result=MockDetectorResult(),
            secret_result=sec,
            toxicity_result=tox,
            intent_result=intent,
            source="EXTERNAL_WEB",
            session_state="HIGH_RISK",
        )
        assert res.score >= 80.0
        assert res.level == "CRITICAL"
        assert len(res.contributing_factors) >= 5

    def test_source_trust_influences_score(self, risk_engine):
        # System source (trust 0.90) vs External Web (trust 0.20)
        res_system = risk_engine.evaluate(
            injection_result=MockDetectorResult(),
            pii_result=MockDetectorResult(),
            secret_result=MockDetectorResult(),
            toxicity_result=MockDetectorResult(),
            intent_result=MockDetectorResult(),
            source="SYSTEM",
        )
        res_external = risk_engine.evaluate(
            injection_result=MockDetectorResult(),
            pii_result=MockDetectorResult(),
            secret_result=MockDetectorResult(),
            toxicity_result=MockDetectorResult(),
            intent_result=MockDetectorResult(),
            source="EXTERNAL_WEB",
        )
        assert res_external.score > res_system.score

    def test_session_state_influences_score(self, risk_engine):
        res_normal = risk_engine.evaluate(
            injection_result=MockDetectorResult(),
            pii_result=MockDetectorResult(),
            secret_result=MockDetectorResult(),
            toxicity_result=MockDetectorResult(),
            intent_result=MockDetectorResult(),
            session_state="NORMAL",
        )
        res_quarantined = risk_engine.evaluate(
            injection_result=MockDetectorResult(),
            pii_result=MockDetectorResult(),
            secret_result=MockDetectorResult(),
            toxicity_result=MockDetectorResult(),
            intent_result=MockDetectorResult(),
            session_state="QUARANTINED",
        )
        assert res_quarantined.score > res_normal.score
