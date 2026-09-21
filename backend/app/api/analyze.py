"""
SENTINEL-X — Input Analysis Endpoint
=======================================
POST /api/v1/analyze/input

Runs the full input security pipeline and returns a structured
security analysis. The LLM is NOT called — this endpoint is used
for testing, the Attack Lab, and the frontend Inspector.

Pipeline:
    1. InputNormalizer   → cleaned text + encoding flags
    2. InjectionDetector → injection / jailbreak detection (Layers 1, 2, 3)
    3. PIIDetector       → PII discovery + redaction (Global + Indian)
    4. SecretDetector    → Credentials, tokens, keys + Canary tokens
    5. ToxicityDetector  → Harmful language, hate speech, threats
    6. IntentAnalyzer    → Operational intent classification
    7. RiskEngine        → Weighted multi-factor risk scoring
    8. PolicyEngine      → ALLOW / SANITIZE / QUARANTINE / BLOCK decisions
    9. SanitizerEngine   → Coordinated sensitive content redaction
    10. SessionRisk      → Adaptive state machine progression
    11. AuditLogger      → Write structured event to SQLite
    12. SecurityReceipt  → Cryptographic/structured proof of decision
"""

import time
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request
from fastapi import status as http_status

from app.config import get_settings
from app.detectors import (
    get_normalizer,
    get_injection_detector,
    get_pii_detector,
    get_secret_detector,
    get_toxicity_detector,
    get_intent_analyzer,
)
from app.core.risk_engine import get_risk_engine
from app.core.policy_engine import get_policy_engine
from app.core.sanitizer import get_sanitizer
from app.core.session_risk import get_session_tracker
from app.schemas.request import AnalyzeInputRequest
from app.schemas.response import (
    AnalyzeInputResponse,
    InjectionResult,
    IntentResult,
    NormalizationInfo,
    PIIResult,
    PolicyDecision,
    RiskFactor,
    RiskResult,
    SecretResult,
    SecurityReceipt,
    SessionInfo,
    ToxicityResult,
)

router = APIRouter()


def _build_receipt(
    request_id: str,
    session_id: str,
    decision: str,
    risk: RiskResult,
    injection_raw,
    pii_raw,
    secret_raw,
    toxicity_raw,
    intent_raw,
    policy: PolicyDecision,
    total_latency: float,
) -> SecurityReceipt:
    threats = []
    if injection_raw.detected:
        threats.append(f"INJECTION:{injection_raw.category}")
    if secret_raw.detected:
        threats.extend([f"SECRET:{s}" for s in secret_raw.secret_types])
    if pii_raw.detected:
        threats.extend([f"PII:{p}" for p in pii_raw.entity_types])
    if toxicity_raw.detected:
        threats.extend([f"TOXICITY:{t}" for t in toxicity_raw.categories])
    if intent_raw.is_malicious:
        threats.append(f"INTENT:{intent_raw.primary_intent}")

    explanation = policy.reason
    if injection_raw.evidence:
        explanation += " Evidence: " + "; ".join(injection_raw.evidence[:2])

    return SecurityReceipt(
        request_id=request_id,
        session_id=session_id,
        timestamp=datetime.now(timezone.utc).isoformat(),
        decision=decision,
        risk_score=risk.score,
        risk_level=risk.level,
        threats_detected=threats,
        triggered_policies=policy.triggered_policies,
        pii_detected=pii_raw.detected,
        secrets_detected=secret_raw.detected,
        explanation=explanation,
        latency_ms=round(total_latency, 2),
    )


# ── Endpoint ──────────────────────────────────────────────────────────────────

@router.post(
    "/analyze/input",
    response_model=AnalyzeInputResponse,
    summary="Analyze Input",
    description="Run the full SENTINEL-X input security pipeline on the provided text.",
    tags=["Security"],
)
async def analyze_input(
    request_body: AnalyzeInputRequest,
    request: Request,
) -> AnalyzeInputResponse:
    pipeline_start = time.perf_counter()
    request_id = str(uuid.uuid4())
    session_id = request_body.session_id

    try:
        # ── Step 1: Input Normalization ───────────────────────────────────────
        normalizer = get_normalizer()
        norm = normalizer.normalize(request_body.text)

        norm_info = NormalizationInfo(
            flags=norm.flags,
            suspicious=norm.suspicious,
            decoded_variants_checked=len(norm.decoded_variants),
        )

        analysis_text = norm.leet_normalized or norm.normalized

        # ── Step 2: Prompt Injection Detection ───────────────────────────────
        inj_detector = get_injection_detector()
        injection_raw = inj_detector.analyze(
            text=analysis_text,
            decoded_variants=norm.decoded_variants,
        )

        injection = InjectionResult(
            detected=injection_raw.detected,
            confidence=round(injection_raw.confidence, 4),
            category=injection_raw.category,
            severity=injection_raw.severity,
            attack_types=injection_raw.attack_types,
            evidence=injection_raw.evidence,
            layer1_triggered=injection_raw.layer1_triggered,
            layer2_triggered=injection_raw.layer2_triggered,
            layer3_triggered=injection_raw.layer3_triggered,
            latency_ms=round(injection_raw.latency_ms, 2),
        )

        # ── Step 3: PII Detection ─────────────────────────────────────────────
        pii_detector = get_pii_detector()
        pii_raw = pii_detector.analyze(norm.normalized)
        pii = PIIResult(
            detected=pii_raw.detected,
            pii_types=pii_raw.entity_types,
            count=len(pii_raw.entities),
            redacted_text=pii_raw.redacted_text if pii_raw.detected else None,
            latency_ms=round(pii_raw.latency_ms, 2),
        )

        # ── Step 4: Secret Detection ──────────────────────────────────────────
        secret_detector = get_secret_detector()
        secret_raw = secret_detector.analyze(norm.normalized)
        secrets = SecretResult(
            detected=secret_raw.detected,
            secret_types=secret_raw.secret_types,
            count=len(secret_raw.secrets),
            latency_ms=round(secret_raw.latency_ms, 2),
        )

        # ── Step 5: Toxicity Detection ────────────────────────────────────────
        toxicity_detector = get_toxicity_detector()
        toxicity_raw = toxicity_detector.analyze(norm.normalized)
        toxicity = ToxicityResult(
            detected=toxicity_raw.detected,
            category=toxicity_raw.categories[0] if toxicity_raw.categories else None,
            confidence=round(toxicity_raw.score, 4) if toxicity_raw.detected else None,
            severity=toxicity_raw.severity,
            latency_ms=round(toxicity_raw.latency_ms, 2),
        )

        # ── Step 6: Intent Analysis ───────────────────────────────────────────
        intent_analyzer = get_intent_analyzer()
        intent_raw = intent_analyzer.analyze(norm.normalized)
        intent = IntentResult(
            category=intent_raw.primary_intent,
            confidence=round(intent_raw.confidence, 4),
            is_suspicious=intent_raw.is_malicious,
            latency_ms=round(intent_raw.latency_ms, 2),
        )

        # ── Step 7: Session Risk Lookup ───────────────────────────────────────
        session_tracker = get_session_tracker()
        session_record = session_tracker.get_or_create(session_id)

        # ── Step 8: Multi-Signal Risk Engine ──────────────────────────────────
        risk_engine = get_risk_engine()
        risk = risk_engine.evaluate(
            injection_result=injection_raw,
            pii_result=pii_raw,
            secret_result=secret_raw,
            toxicity_result=toxicity_raw,
            intent_result=intent_raw,
            source=request_body.source,
            session_state=session_record.state,
        )

        # ── Step 9: Policy Engine ─────────────────────────────────────────────
        policy_engine = get_policy_engine()
        policy = policy_engine.evaluate(
            risk=risk,
            injection_result=injection_raw,
            pii_result=pii_raw,
            secret_result=secret_raw,
            toxicity_result=toxicity_raw,
            intent_result=intent_raw,
            session_state=session_record.state,
            is_output_scan=False,
        )
        decision = policy.action

        # ── Step 10: Sanitization (if SANITIZE) ────────────────────────────────
        sanitized_text = None
        if decision == "SANITIZE":
            sanitizer = get_sanitizer()
            sanitized_text = sanitizer.sanitize(
                norm.normalized,
                pii_result=pii_raw,
                secret_result=secret_raw,
            )

        # ── Step 11: Update Session Risk ──────────────────────────────────────
        threat_labels = []
        if injection_raw.detected:
            threat_labels.append(injection_raw.category)
        if secret_raw.canary_detected:
            threat_labels.append("CANARY_TOKEN")

        updated_session = session_tracker.record_turn(
            session_id=session_id,
            risk_score=risk.score,
            decision=decision,
            threats=threat_labels,
        )
        session_info = SessionInfo(
            session_id=session_id,
            state=updated_session.state,
            accumulated_risk=round(updated_session.accumulated_risk, 2),
            request_count=updated_session.request_count,
        )

        # ── Step 12: Audit Logging ────────────────────────────────────────────
        total_latency_ms = (time.perf_counter() - pipeline_start) * 1000
        security_latency_ms = total_latency_ms

        try:
            from app.db.database import get_db_session
            from app.models.audit import AuditLog
            async with get_db_session() as db:
                log_entry = AuditLog(
                    request_id=request_id,
                    session_id=session_id,
                    total_latency_ms=round(total_latency_ms, 2),
                    security_latency_ms=round(security_latency_ms, 2),
                    input_char_count=norm.char_count,
                    input_source=request_body.source,
                    normalization_flags=norm.flags if norm.flags else None,
                    injection_detected=injection_raw.detected,
                    injection_confidence=injection_raw.confidence if injection_raw.detected else None,
                    injection_category=injection_raw.category if injection_raw.detected else None,
                    injection_severity=injection_raw.severity,
                    pii_detected=pii_raw.detected,
                    secrets_detected=secret_raw.detected,
                    toxicity_detected=toxicity_raw.detected,
                    intent_category=intent.category,
                    risk_score=risk.score,
                    risk_level=risk.level,
                    contributing_factors=[f.model_dump() for f in risk.contributing_factors],
                    session_risk_score=updated_session.accumulated_risk,
                    session_state=updated_session.state,
                    decision=decision,
                    triggered_policies=policy.triggered_policies if policy.triggered_policies else None,
                    output_scan_passed=None,
                )
                db.add(log_entry)
        except Exception:
            pass

        # ── Step 13: Build Security Receipt ───────────────────────────────────
        receipt = _build_receipt(
            request_id=request_id,
            session_id=session_id,
            decision=decision,
            risk=risk,
            injection_raw=injection_raw,
            pii_raw=pii_raw,
            secret_raw=secret_raw,
            toxicity_raw=toxicity_raw,
            intent_raw=intent_raw,
            policy=policy,
            total_latency=total_latency_ms,
        )

        return AnalyzeInputResponse(
            request_id=request_id,
            session_id=session_id,
            decision=decision,
            normalization=norm_info,
            injection=injection,
            pii=pii,
            secrets=secrets,
            toxicity=toxicity,
            intent=intent,
            risk=risk,
            policy=policy,
            session=session_info,
            receipt=receipt,
            sanitized_text=sanitized_text,
            total_latency_ms=round(total_latency_ms, 2),
            security_latency_ms=round(security_latency_ms, 2),
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=http_status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal security pipeline error: {type(exc).__name__}",
        )
