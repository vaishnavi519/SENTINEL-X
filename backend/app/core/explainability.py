"""
SENTINEL-X — Explainability Engine
====================================
Transforms opaque security decisions into human-auditable, defensible rationales.
Designed specifically for academic viva defense, regulatory compliance, and SOC analysts.

Features:
  - Natural language decision summary (no raw regex or internal jargon)
  - Relative risk factor influence ranking (% contribution to risk score)
  - Clear remediation guidance for end-users and developers
  - Safe representation: never regurgitates raw exploit payloads or leaked PII
"""

from dataclasses import dataclass, field
from typing import Any
from app.schemas.response import PolicyDecision, RiskResult


@dataclass
class ExplanationDetail:
    summary: str
    decision_rationale: str
    top_factors: list[dict[str, Any]]
    recommendations: list[str]


class ExplainabilityEngine:
    """Produces structured and narrative explanations of security actions."""

    def explain(
        self,
        decision: PolicyDecision,
        risk: RiskResult,
        threat_labels: list[str],
    ) -> ExplanationDetail:
        # 1. Decision Rationale
        if decision.action == "BLOCK":
            summary = (
                f"Request was BLOCKED because it violated active security policy "
                f"({', '.join(decision.triggered_policies) or 'Threat threshold'})."
            )
        elif decision.action == "QUARANTINE":
            summary = (
                f"Request was QUARANTINED for review due to elevated suspicion "
                f"({', '.join(decision.triggered_policies) or 'Risk score ' + str(risk.score)})."
            )
        elif decision.action == "SANITIZE":
            summary = (
                f"Request was SANITIZED. Sensitive identifiers (PII/secrets) were redacted "
                f"before forwarding to the LLM."
            )
        else:
            summary = "Request was evaluated as safe and ALLOWED to proceed."

        # 2. Factor Rankings
        total_contrib = sum(f.contribution for f in risk.contributing_factors) or 1.0
        top_factors = []
        for f in sorted(risk.contributing_factors, key=lambda x: x.contribution, reverse=True):
            pct = round((f.contribution / total_contrib) * 100, 1)
            top_factors.append({
                "factor": f.name,
                "contribution": f.contribution,
                "percentage_influence": pct,
                "detail": f.description,
            })

        # 3. Actionable Recommendations
        recommendations: list[str] = []
        for threat in threat_labels:
            t_upper = threat.upper()
            if "INJECTION" in t_upper or "JAILBREAK" in t_upper:
                recommendations.append(
                    "Ensure user inputs do not attempt to override system instructions or alter AI personas."
                )
            elif "PII" in t_upper:
                recommendations.append(
                    "Remove personal information (Aadhaar, PAN, emails, phones) from prompts before submission."
                )
            elif "SECRET" in t_upper:
                recommendations.append(
                    "Store API tokens and private keys in environment variables, never inside conversational prompts."
                )
            elif "TOXICITY" in t_upper:
                recommendations.append(
                    "Adhere to acceptable use policies by avoiding violent, abusive, or hateful language."
                )
            elif "INTENT" in t_upper:
                recommendations.append(
                    "Inquiries must be restricted to legitimate technical, educational, or creative tasks."
                )

        if not recommendations:
            recommendations.append("Prompt conforms to standard operational security baselines.")

        # Deduplicate recommendations
        recommendations = list(dict.fromkeys(recommendations))

        return ExplanationDetail(
            summary=summary,
            decision_rationale=decision.reason,
            top_factors=top_factors,
            recommendations=recommendations,
        )


_explainability_engine = None


def get_explainability_engine() -> ExplainabilityEngine:
    global _explainability_engine
    if _explainability_engine is None:
        _explainability_engine = ExplainabilityEngine()
    return _explainability_engine
