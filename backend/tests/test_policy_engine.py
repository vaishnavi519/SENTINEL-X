"""
SENTINEL-X — Policy Engine Tests
==================================
Unit tests for app.core.policy_engine.PolicyEngine.

Coverage:
  - ALLOW, SANITIZE, QUARANTINE, and BLOCK decision policies
  - Action precedence escalation (BLOCK > QUARANTINE > SANITIZE > ALLOW)
  - Input pipeline policies vs Output pipeline policies
  - Canary token exfiltration defense
  - Quarantined session enforcement
  - Triggered policy identifiers and reasons
"""

import pytest
from dataclasses import dataclass, field
from app.core.policy_engine import PolicyEngine
from app.schemas.response import RiskResult


@dataclass
class MockDetectorResult:
    detected: bool = False
    category: str = "NONE"
    confidence: float = 0.0
    severity: str = "NONE"
    score: float = 0.0
    categories: list[str] = field(default_factory=list)
    secret_types: list[str] = field(default_factory=list)
    entity_types: list[str] = field(default_factory=list)
    primary_intent: str = "BENIGN_CONVERSATION"
    is_malicious: bool = False
    canary_detected: bool = False


@pytest.fixture
def policy_engine():
    return PolicyEngine()


class TestPolicyEngineDecisions:
    """Test policy decisions across various threat scenarios."""

    def test_benign_allows(self, policy_engine):
        risk = RiskResult(score=10.0, level="LOW")
        decision = policy_engine.evaluate(
            risk=risk,
            injection_result=MockDetectorResult(),
            pii_result=MockDetectorResult(),
            secret_result=MockDetectorResult(),
            toxicity_result=MockDetectorResult(),
            intent_result=MockDetectorResult(),
        )
        assert decision.action == "ALLOW"
        assert len(decision.triggered_policies) == 0

    def test_direct_injection_blocks(self, policy_engine):
        risk = RiskResult(score=65.0, level="HIGH")
        inj = MockDetectorResult(detected=True, severity="CRITICAL", confidence=0.92, category="INJECTION")
        decision = policy_engine.evaluate(
            risk=risk,
            injection_result=inj,
            pii_result=MockDetectorResult(),
            secret_result=MockDetectorResult(),
            toxicity_result=MockDetectorResult(),
            intent_result=MockDetectorResult(),
        )
        assert decision.action == "BLOCK"
        assert any("P-001" in p for p in decision.triggered_policies)

    def test_canary_honeytoken_blocks(self, policy_engine):
        risk = RiskResult(score=50.0, level="HIGH")
        sec = MockDetectorResult(detected=True, canary_detected=True, severity="CRITICAL")
        decision = policy_engine.evaluate(
            risk=risk,
            injection_result=MockDetectorResult(),
            pii_result=MockDetectorResult(),
            secret_result=sec,
            toxicity_result=MockDetectorResult(),
            intent_result=MockDetectorResult(),
        )
        assert decision.action == "BLOCK"
        assert any("P-010" in p or "Canary" in p for p in decision.triggered_policies)

    def test_pii_in_input_sanitizes(self, policy_engine):
        risk = RiskResult(score=25.0, level="MODERATE")
        pii = MockDetectorResult(detected=True, entity_types=["EMAIL_ADDRESS"])
        decision = policy_engine.evaluate(
            risk=risk,
            injection_result=MockDetectorResult(),
            pii_result=pii,
            secret_result=MockDetectorResult(),
            toxicity_result=MockDetectorResult(),
            intent_result=MockDetectorResult(),
            is_output_scan=False,
        )
        assert decision.action == "SANITIZE"
        assert any("P-004" in p for p in decision.triggered_policies)

    def test_pii_in_output_blocks(self, policy_engine):
        # In output firewall, PII must NOT be allowed out
        risk = RiskResult(score=30.0, level="MODERATE")
        pii = MockDetectorResult(detected=True, entity_types=["IN_AADHAAR"])
        decision = policy_engine.evaluate(
            risk=risk,
            injection_result=MockDetectorResult(),
            pii_result=pii,
            secret_result=MockDetectorResult(),
            toxicity_result=MockDetectorResult(),
            intent_result=MockDetectorResult(),
            is_output_scan=True,
        )
        assert decision.action == "BLOCK"
        assert any("P-008" in p for p in decision.triggered_policies)

    def test_quarantined_session_blocks_even_clean_prompt(self, policy_engine):
        risk = RiskResult(score=10.0, level="LOW")
        decision = policy_engine.evaluate(
            risk=risk,
            injection_result=MockDetectorResult(),
            pii_result=MockDetectorResult(),
            secret_result=MockDetectorResult(),
            toxicity_result=MockDetectorResult(),
            intent_result=MockDetectorResult(),
            session_state="QUARANTINED",
        )
        assert decision.action == "BLOCK"
        assert any("P-014" in p for p in decision.triggered_policies)

    def test_block_precedence_over_sanitize(self, policy_engine):
        # Prompt contains BOTH PII (sanitize) and Direct Injection (block)
        risk = RiskResult(score=85.0, level="CRITICAL")
        inj = MockDetectorResult(detected=True, severity="CRITICAL", confidence=0.90)
        pii = MockDetectorResult(detected=True, entity_types=["EMAIL_ADDRESS"])
        decision = policy_engine.evaluate(
            risk=risk,
            injection_result=inj,
            pii_result=pii,
            secret_result=MockDetectorResult(),
            toxicity_result=MockDetectorResult(),
            intent_result=MockDetectorResult(),
        )
        assert decision.action == "BLOCK"
