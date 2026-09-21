"""
SENTINEL-X — API Response Schemas
====================================
Pydantic models for all outbound API responses.

Security note:
  These schemas define EXACTLY what is returned to the client.
  They must NEVER include raw PII, secrets, or system internals.
  Evidence strings are sanitized before inclusion.
"""

from typing import Any, Literal

from pydantic import BaseModel, Field


# ── Detector Sub-Results ──────────────────────────────────────────────────────

class NormalizationInfo(BaseModel):
    """Summary of what the Input Normalizer detected."""
    flags: list[str] = Field(
        default_factory=list,
        description="Encoding/obfuscation flags detected (e.g., BASE64_ENCODED, ZERO_WIDTH_CHARS).",
    )
    suspicious: bool = Field(
        default=False,
        description="True if any suspicious encoding was detected.",
    )
    decoded_variants_checked: int = Field(
        default=0,
        description="Number of decoded variants that were also passed through detectors.",
    )


class InjectionResult(BaseModel):
    """Result from the Prompt Injection Detector."""
    detected: bool
    confidence: float = Field(ge=0.0, le=1.0)
    category: Literal["BENIGN", "SUSPICIOUS", "INJECTION", "JAILBREAK", "CRITICAL"]
    severity: Literal["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    attack_types: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(
        default_factory=list,
        description="Human-readable evidence strings. Never includes raw user input.",
    )
    layer1_triggered: bool = False
    layer2_triggered: bool = False
    layer3_triggered: bool = False
    latency_ms: float = 0.0


class PIIResult(BaseModel):
    """Result from the PII Detector."""
    detected: bool
    pii_types: list[str] = Field(default_factory=list)
    count: int = 0
    redacted_text: str | None = None
    latency_ms: float = 0.0


class SecretResult(BaseModel):
    """Result from the Secret Detector."""
    detected: bool
    secret_types: list[str] = Field(default_factory=list)
    count: int = 0
    latency_ms: float = 0.0


class ToxicityResult(BaseModel):
    """Result from the Toxicity Detector."""
    detected: bool
    category: str | None = None
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    severity: Literal["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"] = "NONE"
    latency_ms: float = 0.0


class IntentResult(BaseModel):
    """Result from the Intent Analyzer."""
    category: str
    confidence: float = Field(ge=0.0, le=1.0)
    is_suspicious: bool = False
    latency_ms: float = 0.0


# ── Risk & Policy ─────────────────────────────────────────────────────────────

class RiskFactor(BaseModel):
    """One contributing factor to the overall risk score."""
    name: str
    contribution: float = Field(ge=0.0, le=100.0)
    description: str


class RiskResult(BaseModel):
    """Output from the Risk Engine."""
    score: float = Field(ge=0.0, le=100.0, description="Risk score 0–100.")
    level: Literal["LOW", "MODERATE", "HIGH", "VERY_HIGH", "CRITICAL"]
    contributing_factors: list[RiskFactor] = Field(default_factory=list)


class PolicyDecision(BaseModel):
    """Output from the Policy Engine."""
    action: Literal["ALLOW", "SANITIZE", "QUARANTINE", "BLOCK"]
    triggered_policies: list[str] = Field(default_factory=list)
    reason: str


# ── Session ────────────────────────────────────────────────────────────────────

class SessionInfo(BaseModel):
    """Current session risk state."""
    session_id: str
    state: Literal["NORMAL", "WATCH", "HIGH_RISK", "RESTRICTED", "QUARANTINED"]
    accumulated_risk: float
    request_count: int


# ── Security Receipt ──────────────────────────────────────────────────────────

class SecurityReceipt(BaseModel):
    """
    A structured security receipt summarizing what happened.
    This is the primary human-readable output for each request.

    Security note: Evidence strings are sanitized and do NOT
    include raw user input or any sensitive data being protected.
    """
    request_id: str
    session_id: str
    timestamp: str
    decision: Literal["ALLOW", "SANITIZE", "QUARANTINE", "BLOCK"]
    risk_score: float
    risk_level: str
    threats_detected: list[str]
    triggered_policies: list[str]
    pii_detected: bool
    secrets_detected: bool
    explanation: str
    latency_ms: float


# ── Top-Level Responses ───────────────────────────────────────────────────────

class AnalyzeInputResponse(BaseModel):
    """
    Response for POST /api/v1/analyze/input

    Returns the full security analysis of a user input without
    sending it to the LLM. Useful for testing and the Attack Lab.
    """
    request_id: str
    session_id: str
    decision: Literal["ALLOW", "SANITIZE", "QUARANTINE", "BLOCK"]

    # Input analysis
    normalization: NormalizationInfo
    injection: InjectionResult
    pii: PIIResult
    secrets: SecretResult
    toxicity: ToxicityResult
    intent: IntentResult

    # Decision
    risk: RiskResult
    policy: PolicyDecision
    session: SessionInfo

    # Receipt
    receipt: SecurityReceipt

    # Sanitized input (if action=SANITIZE) or None
    sanitized_text: str | None = None

    # Timing
    total_latency_ms: float
    security_latency_ms: float


class ChatResponse(BaseModel):
    """
    Response for POST /api/v1/chat

    Full pipeline result including LLM response (if allowed).
    """
    request_id: str
    session_id: str
    decision: Literal["ALLOW", "SANITIZE", "QUARANTINE", "BLOCK"]

    # LLM response (None if blocked/quarantined)
    response: str | None = None
    llm_provider: str | None = None
    llm_latency_ms: float | None = None

    # Security analysis
    input_analysis: AnalyzeInputResponse
    output_scan_passed: bool | None = None

    # Receipt
    receipt: SecurityReceipt

    total_latency_ms: float


class HealthResponse(BaseModel):
    """Response for GET /health"""
    status: Literal["ok", "degraded", "error"]
    version: str
    detectors: dict[str, str]   # detector_name → "ok" | "unavailable"
    database: str               # "ok" | "error"
    uptime_seconds: float | None = None
