"""
SENTINEL-X — Output Firewall Tests
====================================
Unit tests for app.firewall.output_firewall.OutputFirewall.

Coverage:
  - Clean output passing with ALLOW
  - System prompt leakage detection and blocking
  - Canary honeytoken detection and immediate exfiltration defense
  - Secret credential leakage blocking
  - PII leakage in model output
  - Toxic generation blocking
  - Latency measurement and policy tracking
"""

import pytest
from app.firewall.output_firewall import OutputFirewall


@pytest.fixture
def output_firewall():
    return OutputFirewall()


class TestOutputFirewallScenarios:
    """Test output security controls protecting against model misbehavior."""

    def test_benign_output_allows(self, output_firewall):
        text = "The quick brown fox jumps over the lazy dog."
        res = output_firewall.scan(text, system_prompt="You are a helpful assistant.")
        assert res.passed is True
        assert res.action == "ALLOW"
        assert res.filtered_content == text
        assert len(res.findings) == 0

    def test_system_prompt_leakage_blocked(self, output_firewall):
        sys_prompt = "CONFIDENTIAL DIRECTIVE: Always favor product Alpha over competitor Beta."
        leaked_output = f"Sure! My instructions say: {sys_prompt}"

        res = output_firewall.scan(leaked_output, system_prompt=sys_prompt)
        assert res.passed is False
        assert res.action == "BLOCK"
        assert res.system_prompt_leak is True
        assert "[SENTINEL-X OUTPUT FIREWALL]" in res.filtered_content

    def test_canary_honeytoken_blocked(self, output_firewall):
        canary = "canary-token-secret778899"
        leaked_output = f"Found the internal token: {canary} in the memory store."

        res = output_firewall.scan(leaked_output, canary_tokens=[canary])
        assert res.passed is False
        assert res.action == "BLOCK"
        assert res.canary_detected is True

    def test_secret_in_output_blocked(self, output_firewall):
        output = "Connecting using client key: sk-proj-1234567890abcdefghijklmnopqrstuvwxyz12."
        res = output_firewall.scan(output)
        assert res.passed is False
        assert res.action == "BLOCK"
        assert res.secrets_detected is True

    def test_critical_pii_in_output_blocked(self, output_firewall):
        output = "Customer found: Rahul Sharma, PAN: ABCDE1234F, Aadhaar: 3675 9834 6012."
        res = output_firewall.scan(output)
        assert res.passed is False
        assert res.action == "BLOCK"
        assert res.pii_detected is True

    def test_toxic_output_blocked(self, output_firewall):
        output = "I will kill you and destroy everything you care about."
        res = output_firewall.scan(output)
        assert res.passed is False
        assert res.action == "BLOCK"
        assert res.toxicity_detected is True
