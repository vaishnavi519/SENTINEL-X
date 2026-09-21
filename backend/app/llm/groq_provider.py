"""
SENTINEL-X — Groq Cloud LLM Provider (Optional Free Tier)
==========================================================
Integration with Groq Cloud free-tier API (Llama 3.1 8B / Mixtral).
Falls back seamlessly to MockLLMProvider if no API key is configured
or if network requests fail.
"""

import os
import time
import httpx

from app.config import get_settings
from app.llm.adapter import BaseLLMProvider, LLMRequest, LLMResponse
from app.llm.mock_llm import MockLLMProvider


class GroqProvider(BaseLLMProvider):
    """Groq Cloud API integration using httpx."""

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key or os.getenv("GROQ_API_KEY", "")
        self.base_url = "https://api.groq.com/openai/v1/chat/completions"
        self._fallback = MockLLMProvider()

    async def generate(self, request: LLMRequest) -> LLMResponse:
        if not self.api_key:
            # Silent zero-cost fallback
            resp = await self._fallback.generate(request)
            resp.provider = "groq_fallback_mock"
            return resp

        start_time = time.perf_counter()
        messages = []
        if request.system_prompt:
            messages.append({"role": "system", "content": request.system_prompt})
        messages.append({"role": "user", "content": request.prompt})

        payload = {
            "model": request.model or "llama-3.1-8b-instant",
            "messages": messages,
            "temperature": request.temperature,
            "max_tokens": request.max_tokens,
        }

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(self.base_url, json=payload, headers=headers)
                if response.status_code == 200:
                    data = response.json()
                    content = data["choices"][0]["message"]["content"]
                    usage = data.get("usage", {})
                    latency_ms = (time.perf_counter() - start_time) * 1000

                    return LLMResponse(
                        content=content,
                        model=data.get("model", "llama-3.1-8b-instant"),
                        provider="groq",
                        prompt_tokens=usage.get("prompt_tokens", 0),
                        completion_tokens=usage.get("completion_tokens", 0),
                        total_tokens=usage.get("total_tokens", 0),
                        latency_ms=round(latency_ms, 2),
                    )
                else:
                    # On error, fallback smoothly
                    resp = await self._fallback.generate(request)
                    resp.error = f"Groq API returned status {response.status_code}"
                    return resp
        except Exception as exc:
            resp = await self._fallback.generate(request)
            resp.error = f"Groq request exception: {exc}"
            return resp
