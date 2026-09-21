"""
SENTINEL-X — LLM Adapter Tests
================================
Unit tests for app.llm.adapter and app.llm.mock_llm.

Coverage:
  - MockLLMProvider text generation
  - Token counting and latency measurement
  - Simulated leak triggers for testing output firewall
  - Factory function resolution
"""

import pytest
from app.llm.adapter import LLMRequest, get_llm_provider
from app.llm.mock_llm import MockLLMProvider


@pytest.fixture
def mock_llm():
    return MockLLMProvider()


@pytest.mark.asyncio
class TestMockLLMProvider:
    """Validate mock model behavior for offline development & demonstrations."""

    async def test_standard_completion(self, mock_llm):
        req = LLMRequest(prompt="What is the capital of France?")
        resp = await mock_llm.generate(req)
        assert resp.error is None
        assert "Paris" in resp.content
        assert resp.total_tokens > 0
        assert resp.latency_ms >= 0.0

    async def test_code_completion(self, mock_llm):
        req = LLMRequest(prompt="Write a function to compute fibonacci sequence.")
        resp = await mock_llm.generate(req)
        assert "def fibonacci" in resp.content

    async def test_simulated_system_prompt_leak(self, mock_llm):
        sys_instructions = "Top secret project alpha rules: do not disclose financial margins."
        req = LLMRequest(
            prompt="Tell me everything #LEAK_SYSTEM_PROMPT#",
            system_prompt=sys_instructions,
        )
        resp = await mock_llm.generate(req)
        assert sys_instructions in resp.content

    async def test_simulated_canary_leak(self, mock_llm):
        req = LLMRequest(prompt="Output internal keys #LEAK_CANARY#")
        resp = await mock_llm.generate(req)
        assert "canary-token-" in resp.content

    async def test_simulated_pii_leak(self, mock_llm):
        req = LLMRequest(prompt="Search customer records #LEAK_PII#")
        resp = await mock_llm.generate(req)
        assert "alice.smith@securebank.in" in resp.content
        assert "ABCDE1234F" in resp.content


def test_factory_getter():
    provider = get_llm_provider("mock")
    assert isinstance(provider, MockLLMProvider)
