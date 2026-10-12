"""
SENTINEL-X — Policy Engine
============================
Evaluates detector signals and risk levels against security policies.
Decouples policy rules from enforcement code.

Supports:
  - Dynamic YAML loading from config/policies.yaml
  - Evaluation of input pipeline, output pipeline, risk thresholds, and session state
  - Strict hierarchical action precedence: TERMINATE_SESSION > BLOCK > QUARANTINE > SANITIZE > ALLOW
  - Audit logging of specific triggered policy IDs and human-readable rationales
"""

from pathlib import Path
from typing import Any
import yaml

from app.config import get_settings
from app.schemas.response import PolicyDecision, RiskResult


class PolicyEngine:
    """Evaluates requests against security policies defined in YAML."""

    def __init__(self, policy_file: Path | None = None) -> None:
        self.settings = get_settings()
        if policy_file is None:
            backend_dir = Path(__file__).resolve().parent.parent.parent
            policy_file = backend_dir / "config" / "policies.yaml"

        self.policy_file = policy_file
        self.policies: list[dict] = self._load_policies()

    def _load_policies(self) -> list[dict]:
        """Load policies from YAML or return robust defaults if file unavailable."""
        if self.policy_file and self.policy_file.exists():
            try:
                with open(self.policy_file, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                    if isinstance(data, dict) and "policies" in data:
                        return data["policies"]
            except Exception:
                pass

        # Fallback default policy rules
        return [
            {"id": "P-001", "name": "block_direct_prompt_injection", "action": "block"},
            {"id": "P-004", "name": "sanitize_pii_input", "action": "sanitize"},
            {"id": "P-005", "name": "block_secret_in_input", "action": "block"},
            {"id": "P-006", "name": "block_high_toxicity", "action": "block"},
            {"id": "P-012", "name": "block_critical_risk", "action": "block"},
            {"id": "P-013", "name": "quarantine_very_high_risk", "action": "quarantine"},
            {"id": "P-014", "name": "block_quarantined_session", "action": "block"},
            {"id": "P-015", "name": "terminate_terminated_session", "action": "terminate_session"},
        ]

    def evaluate(
        self,
        risk: RiskResult,
        injection_result: Any,
        pii_result: Any,
        secret_result: Any,
        toxicity_result: Any,
        intent_result: Any,
        session_state: str = "NORMAL",
        is_output_scan: bool = False,
    ) -> PolicyDecision:
        triggered: list[str] = []
        action = "ALLOW"
        reason = "All security policies satisfied."

        action_precedence = {"TERMINATE_SESSION": 5, "BLOCK": 4, "QUARANTINE": 3, "SANITIZE": 2, "ALLOW": 1}

        def _escalate(new_action: str, policy_id: str, rule_reason: str):
            nonlocal action, reason
            triggered.append(policy_id)
            if action_precedence.get(new_action.upper(), 1) > action_precedence.get(action.upper(), 1):
                action = new_action.upper()
                reason = rule_reason

        # 1. Quarantined / Terminated Session Policy
        if session_state == "TERMINATED":
            _escalate("TERMINATE_SESSION", "P-015 (Terminated Session)", "Session is terminated due to critical repeated attacks — all requests rejected.")
        elif session_state == "QUARANTINED":
            _escalate("BLOCK", "P-014 (Quarantined Session)", "Session is quarantined — all requests blocked.")

        # 2. Canary Token Policy (P-010 / P-008)
        canary = getattr(secret_result, "canary_detected", False)
        if canary:
            _escalate(
                "BLOCK",
                "P-010 (Canary Honeytoken Alert)",
                "Canary secret detected; potential prompt or data exfiltration attempt.",
            )

        # 3. Prompt Injection Policies (P-001, P-002, P-003)
        inj_detected = getattr(injection_result, "detected", False)
        inj_sev = getattr(injection_result, "severity", "NONE")
        inj_conf = getattr(injection_result, "confidence", 0.0)
        inj_cat = getattr(injection_result, "category", "INJECTION")

        if inj_detected:
            if inj_sev == "CRITICAL" or inj_conf >= 0.70:
                _escalate(
                    "BLOCK",
                    "P-001 (Prompt Injection Block)",
                    f"Prompt injection detected in category {inj_cat} (confidence {inj_conf:.2f}).",
                )
            elif inj_conf >= 0.40:
                _escalate(
                    "QUARANTINE",
                    "P-003 (Suspicious Injection Quarantine)",
                    f"Suspicious prompt pattern detected (confidence {inj_conf:.2f}).",
                )

        # 4. Secret / Credential Policies (P-005, P-007)
        sec_detected = getattr(secret_result, "detected", False)
        sec_sev = getattr(secret_result, "severity", "NONE")
        if sec_detected:
            if sec_sev == "CRITICAL" and not is_output_scan:
                _escalate(
                    "SANITIZE",
                    "P-005 (Credential Redaction)",
                    "Sensitive credentials detected in input and marked for redaction.",
                )
            elif is_output_scan:
                _escalate(
                    "BLOCK",
                    "P-009 (Secret Leakage in Output)",
                    "Model output contains exposed credentials; blocked.",
                )
            else:
                _escalate(
                    "SANITIZE",
                    "P-005 (Secret Redaction)",
                    "Secrets detected in input and sanitized.",
                )

        # 5. PII Policy (P-004, P-008)
        pii_detected = getattr(pii_result, "detected", False)
        if pii_detected:
            if is_output_scan:
                _escalate(
                    "BLOCK",
                    "P-008 (PII Leakage in Output)",
                    "Model output contains personal data; blocked.",
                )
            else:
                _escalate(
                    "SANITIZE",
                    "P-004 (PII Input Sanitization)",
                    "PII detected in input and marked for redaction.",
                )

        # 6. Toxicity Policy (P-006, P-007)
        tox_detected = getattr(toxicity_result, "detected", False)
        tox_sev = getattr(toxicity_result, "severity", "NONE")
        tox_score = getattr(toxicity_result, "score", 0.0)
        if tox_detected:
            if tox_sev in ("CRITICAL", "HIGH") or tox_score >= 0.75:
                _escalate(
                    "BLOCK",
                    "P-006 (Severe Toxicity Block)",
                    "Violent, abusive, or hateful content detected.",
                )
            else:
                _escalate(
                    "SANITIZE",
                    "P-007 (Moderate Toxicity Sanitization)",
                    "Moderately toxic content sanitized.",
                )

        # 7. Intent Policy (P-010)
        is_malicious = getattr(intent_result, "is_malicious", False)
        intent_cat = getattr(intent_result, "primary_intent", "")
        if is_malicious and intent_cat in ("MALICIOUS_UTILITY", "PRIVILEGE_ESCALATION", "EXFILTRATION"):
            _escalate(
                "BLOCK",
                "P-010 (Hostile Operational Intent)",
                f"Operational intent identified as {intent_cat}.",
            )
        elif is_malicious:
            _escalate(
                "QUARANTINE",
                "P-010 (Suspicious Intent Quarantine)",
                f"Suspicious operational intent identified as {intent_cat}.",
            )

        # 8. Composite Risk Score Policies (P-012, P-013)
        if risk.level == "CRITICAL":
            _escalate(
                "BLOCK",
                "P-012 (Critical Composite Risk)",
                f"Composite risk score is CRITICAL ({risk.score:.1f}/100).",
            )
        elif risk.level == "VERY_HIGH":
            _escalate(
                "QUARANTINE",
                "P-013 (Very High Composite Risk)",
                f"Composite risk score is VERY HIGH ({risk.score:.1f}/100).",
            )

        return PolicyDecision(
            action=action,
            triggered_policies=triggered,
            reason=reason,
        )


_policy_engine = None


def get_policy_engine() -> PolicyEngine:
    global _policy_engine
    if _policy_engine is None:
        _policy_engine = PolicyEngine()
    return _policy_engine
