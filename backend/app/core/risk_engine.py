"""
SENTINEL-X — Risk Engine
==========================
Computes a composite security risk score (0.0 to 100.0) from all detector
signals, source provenance, and session threat history.

Architecture:
  - Weighted combination using tunable coefficients from config/settings.yaml:
      Risk = (w_inj * Injection) + (w_pii * PII) + (w_sec * Secrets) +
             (w_tox * Toxicity) + (w_int * Intent) + (w_sess * Session) +
             SourceTrustAdjustment
  - Normalizes scores and maps to qualitative risk levels:
      0–20   → LOW
      21–40  → MODERATE
      41–60  → HIGH
      61–80  → VERY_HIGH
      81–100 → CRITICAL
  - Full transparency: produces fine-grained RiskFactor explainability elements.
"""

from typing import Any
from app.config import get_settings
from app.schemas.response import RiskFactor, RiskResult


_SOURCE_TRUST = {
    "USER_INPUT": 0.60,
    "TOOL_OUTPUT": 0.50,
    "RAG_DOCUMENT": 0.30,
    "EXTERNAL_WEB": 0.20,
    "SYSTEM": 0.90,
}


class RiskEngine:
    """Computes comprehensive multi-factor risk scores and breakdowns."""

    def __init__(self) -> None:
        self.settings = get_settings()

    def evaluate(
        self,
        injection_result: Any,
        pii_result: Any,
        secret_result: Any,
        toxicity_result: Any,
        intent_result: Any,
        source: str = "USER_INPUT",
        session_state: str = "NORMAL",
    ) -> RiskResult:
        factors: list[RiskFactor] = []

        # 1. Prompt Injection (w_inj = 0.30 default)
        inj_raw = getattr(injection_result, "risk_contribution", 0.0)
        inj_contrib = inj_raw * self.settings.weight_injection
        if inj_contrib > 0:
            cat = getattr(injection_result, "category", "INJECTION")
            conf = getattr(injection_result, "confidence", 0.0)
            factors.append(RiskFactor(
                name="Prompt Injection",
                contribution=round(inj_contrib, 2),
                description=f"Category: {cat} (confidence: {conf:.2f})",
            ))

        # 2. PII Exposure (w_pii = 0.15 default)
        pii_raw = getattr(pii_result, "risk_contribution", 0.0)
        pii_contrib = pii_raw * self.settings.weight_pii
        if pii_contrib > 0:
            entities = getattr(pii_result, "entity_types", [])
            factors.append(RiskFactor(
                name="PII Exposure",
                contribution=round(pii_contrib, 2),
                description=f"Entities identified: {', '.join(entities)}",
            ))

        # 3. Secret Leakage (w_secrets = 0.20 default)
        sec_raw = getattr(secret_result, "risk_contribution", 0.0)
        sec_contrib = sec_raw * self.settings.weight_secrets
        if sec_contrib > 0:
            stypes = getattr(secret_result, "secret_types", [])
            canary = getattr(secret_result, "canary_detected", False)
            desc = f"Credentials: {', '.join(stypes)}"
            if canary:
                desc += " [CANARY HONEYTOKEN DETECTED]"
            factors.append(RiskFactor(
                name="Secret Leakage",
                contribution=round(sec_contrib, 2),
                description=desc,
            ))

        # 4. Toxicity & Harm (w_toxicity = 0.15 default)
        tox_raw = getattr(toxicity_result, "risk_contribution", 0.0)
        tox_contrib = tox_raw * self.settings.weight_toxicity
        if tox_contrib > 0:
            cats = getattr(toxicity_result, "categories", [])
            factors.append(RiskFactor(
                name="Toxicity & Harm",
                contribution=round(tox_contrib, 2),
                description=f"Categories: {', '.join(cats)}",
            ))

        # 5. Intent Risk (w_intent = 0.10 default)
        intent_raw = getattr(intent_result, "risk_contribution", 0.0)
        intent_contrib = intent_raw * self.settings.weight_intent
        if intent_contrib > 0:
            intent_name = getattr(intent_result, "primary_intent", "UNKNOWN")
            factors.append(RiskFactor(
                name="Hostile Intent",
                contribution=round(intent_contrib, 2),
                description=f"Operational intent: {intent_name}",
            ))

        # 6. Source Trust (Max 10 points)
        trust = _SOURCE_TRUST.get(source, 0.50)
        trust_risk = (1.0 - trust) * 10.0
        if trust_risk > 1.0:
            factors.append(RiskFactor(
                name="Source Trust",
                contribution=round(trust_risk, 2),
                description=f"Source '{source}' has trust baseline of {trust:.2f}",
            ))

        # 7. Session Risk (w_session = 0.10 default)
        session_risk_map = {
            "NORMAL": 0.0,
            "WATCH": 15.0,
            "HIGH_RISK": 40.0,
            "RESTRICTED": 70.0,
            "QUARANTINED": 100.0,
        }
        sess_base = session_risk_map.get(session_state, 0.0)
        sess_contrib = sess_base * self.settings.weight_session
        if sess_contrib > 0:
            factors.append(RiskFactor(
                name="Session Risk",
                contribution=round(sess_contrib, 2),
                description=f"Session risk level: {session_state}",
            ))

        total_score = min(100.0, sum(f.contribution for f in factors))
        level = self.settings.risk_level_for_score(total_score)

        return RiskResult(
            score=round(total_score, 2),
            level=level,
            contributing_factors=factors,
        )


_risk_engine = None


def get_risk_engine() -> RiskEngine:
    global _risk_engine
    if _risk_engine is None:
        _risk_engine = RiskEngine()
    return _risk_engine
