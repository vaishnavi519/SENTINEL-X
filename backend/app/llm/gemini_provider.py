"""
SENTINEL-X — Google Gemini Provider
====================================
Integration with Google Gemini API using the official google-genai SDK.

The SDK correctly handles all API key formats (including the newer AQ.
prefix keys from Google AI Studio) and routes requests to the Gemini
Developer API at generativelanguage.googleapis.com.

Does NOT silently fall back to MockLLM.  When Gemini is configured but
fails, a clear error is returned so the user knows the real LLM is
unavailable.
"""

import asyncio
import time

from google import genai
from google.genai import types as genai_types

from app.config import get_settings
from app.llm.adapter import BaseLLMProvider, LLMRequest, LLMResponse


class GeminiProvider(BaseLLMProvider):
    """Google Gemini API integration via the official google-genai SDK."""

    def __init__(self, api_key: str | None = None) -> None:
        settings = get_settings()
        self.api_key = api_key or settings.gemini_api_key or ""

        if self.api_key:
            # Create the client pointing at the Gemini Developer API
            # (NOT Vertex AI — no vertexai=True, no GOOGLE_GENAI_USE_VERTEXAI)
            self._client = genai.Client(api_key=self.api_key)
            print(
                f"[SENTINEL-X] GeminiProvider initialized (google-genai SDK). "
                f"Key present: True, prefix: {self.api_key[:4]}..."
            )
        else:
            self._client = None
            print(
                "[SENTINEL-X] GeminiProvider initialized. "
                "NO API KEY FOUND — Gemini calls will return an error."
            )

    async def generate(self, request: LLMRequest) -> LLMResponse:
        # ── Guard: no key configured ──────────────────────────────────────
        if not self._client:
            return LLMResponse(
                content=(
                    "Gemini API key is not configured. "
                    "Please set GEMINI_API_KEY in backend/.env."
                ),
                model="none",
                provider="gemini_error",
                error="missing_api_key",
            )

        start_time = time.perf_counter()
        model_name = request.model or "gemini-3.8-flash"

        try:
            # Build config
            config = genai_types.GenerateContentConfig(
                temperature=request.temperature,
                max_output_tokens=request.max_tokens,
            )

            # Attach system instruction if provided
            if request.system_prompt:
                config.system_instruction = request.system_prompt

            print(f"[SENTINEL-X] Calling Gemini API (SDK): {model_name}")

            # The SDK's generate_content is synchronous; run in a thread
            # so we don't block the FastAPI async event loop.
            response = await asyncio.to_thread(
                self._client.models.generate_content,
                model=model_name,
                contents=request.prompt,
                config=config,
            )

            latency_ms = (time.perf_counter() - start_time) * 1000

            # Extract text from response — handle thinking models where
            # response.text may be None because the response contains
            # both "thought" parts and regular text parts.
            content = ""
            try:
                content = response.text or ""
            except (ValueError, AttributeError):
                pass

            if not content and response.candidates:
                # Manually extract non-thought text parts
                for part in response.candidates[0].content.parts:
                    if hasattr(part, "thought") and part.thought:
                        continue  # Skip thinking/reasoning parts
                    if hasattr(part, "text") and part.text:
                        content += part.text


            # Extract token usage when available
            prompt_tokens = 0
            completion_tokens = 0
            total_tokens = 0
            if response.usage_metadata:
                prompt_tokens = response.usage_metadata.prompt_token_count or 0
                completion_tokens = response.usage_metadata.candidates_token_count or 0
                total_tokens = response.usage_metadata.total_token_count or 0

            print(f"[SENTINEL-X] Gemini response OK ({latency_ms:.0f}ms)")

            return LLMResponse(
                content=content,
                model=model_name,
                provider="gemini",
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=total_tokens,
                latency_ms=round(latency_ms, 2),
            )

        except Exception as exc:
            latency_ms = (time.perf_counter() - start_time) * 1000
            error_msg = f"Gemini API error: {exc}"
            print(f"[SENTINEL-X] {error_msg}")
            return LLMResponse(
                content=f"Gemini LLM is currently unavailable. Error: {type(exc).__name__}",
                model=model_name,
                provider="gemini_error",
                latency_ms=round(latency_ms, 2),
                error=error_msg,
            )


