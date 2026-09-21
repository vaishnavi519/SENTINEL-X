"""
SENTINEL-X — Chat & LLM Proxy Endpoint
========================================
POST /api/v1/chat

The full end-to-end security firewall lifecycle:
  Input Pipeline ──► Policy Check ──► LLM Call ──► Output Firewall ──► User Response
       │                  │                              │
     (Scan)         (Block/Quarantine)                 (Scan)
"""

import time
import uuid

from fastapi import APIRouter, HTTPException, Request
from fastapi import status as http_status

from app.config import get_settings
from app.api.analyze import analyze_input
from app.schemas.request import AnalyzeInputRequest, ChatRequest
from app.schemas.response import ChatResponse
from app.llm.adapter import LLMRequest, get_llm_provider
from app.firewall.output_firewall import get_output_firewall

router = APIRouter()


@router.post(
    "/chat",
    response_model=ChatResponse,
    summary="Chat through SENTINEL-X Firewall",
    description=(
        "Full end-to-end protected chat flow. Evaluates user input through the "
        "input firewall, queries the LLM if safe, and inspects the output through "
        "the output firewall before returning the final response."
    ),
    tags=["Chat"],
)
async def chat_endpoint(
    request_body: ChatRequest,
    request: Request,
) -> ChatResponse:
    start_time = time.perf_counter()
    request_id = str(uuid.uuid4())
    session_id = request_body.session_id

    try:
        # ── Step 1: Input Security Analysis ───────────────────────────────────
        input_req = AnalyzeInputRequest(
            text=request_body.text,
            session_id=session_id,
            source=request_body.source,
        )
        input_analysis = await analyze_input(input_req, request)

        # ── Step 2: Policy Enforcement on Input ───────────────────────────────
        if input_analysis.decision in ("BLOCK", "QUARANTINE"):
            total_latency_ms = (time.perf_counter() - start_time) * 1000
            return ChatResponse(
                request_id=request_id,
                session_id=session_id,
                decision=input_analysis.decision,
                response=None,
                llm_provider=None,
                llm_latency_ms=None,
                input_analysis=input_analysis,
                output_scan_passed=None,
                receipt=input_analysis.receipt,
                total_latency_ms=round(total_latency_ms, 2),
            )

        # Prompt to send to LLM (sanitized or original)
        llm_prompt = input_analysis.sanitized_text or request_body.text

        # ── Step 3: LLM Call ──────────────────────────────────────────────────
        llm_provider = get_llm_provider()
        llm_req = LLMRequest(
            prompt=llm_prompt,
            system_prompt=request_body.system_prompt,
        )
        llm_res = await llm_provider.generate(llm_req)

        # ── Step 4: Output Firewall Scan ──────────────────────────────────────
        output_firewall = get_output_firewall()
        output_scan = output_firewall.scan(
            output_text=llm_res.content,
            system_prompt=request_body.system_prompt,
        )

        final_decision = input_analysis.decision
        final_content = output_scan.filtered_content

        if not output_scan.passed:
            final_decision = "BLOCK"

        total_latency_ms = (time.perf_counter() - start_time) * 1000

        return ChatResponse(
            request_id=request_id,
            session_id=session_id,
            decision=final_decision,
            response=final_content,
            llm_provider=llm_res.provider,
            llm_latency_ms=llm_res.latency_ms,
            input_analysis=input_analysis,
            output_scan_passed=output_scan.passed,
            receipt=input_analysis.receipt,
            total_latency_ms=round(total_latency_ms, 2),
        )

    except Exception as exc:
        raise HTTPException(
            status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Security pipeline exception: {exc}",
        )
