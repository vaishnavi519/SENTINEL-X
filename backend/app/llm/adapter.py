"""
SENTINEL-X — LLM Adapter Interface
====================================
Unified interface for LLM integrations.
Supports Mock LLM (default, offline, zero-cost), Groq (free tier),
and Gemini (free tier).
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
import time
from typing import Any

from app.config import get_settings


@dataclass
class LLMRequest:
    prompt: str
    system_prompt: str | None = None
    temperature: float = 0.7
    max_tokens: int = 1024
    model: str | None = None


@dataclass
class LLMResponse:
    content: str
    model: str
    provider: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    latency_ms: float = 0.0
    error: str | None = None


class BaseLLMProvider(ABC):
    """Abstract base class for LLM providers."""

    @abstractmethod
    async def generate(self, request: LLMRequest) -> LLMResponse:
        """Generate text response from the model."""
        pass


def get_llm_provider(name: str | None = None) -> BaseLLMProvider:
    """Factory retrieving the configured LLM provider."""
    settings = get_settings()
    provider_name = (name or settings.default_llm_provider).lower()

    if provider_name == "groq":
        from app.llm.groq_provider import GroqProvider
        return GroqProvider()
    elif provider_name == "mock":
        from app.llm.mock_llm import MockLLMProvider
        return MockLLMProvider()
    else:
        from app.llm.mock_llm import MockLLMProvider
        return MockLLMProvider()
