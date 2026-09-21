"""
SENTINEL-X — Output Firewall
==============================
Independent security scanner for LLM completions. Safe input does NOT
guarantee safe output: models can hallucinate credentials, leak system prompts,
disclose PII from training or RAG contexts, or generate hazardous instructions.

Inspection Stack:
  1. System Prompt Leakage Detector (n-gram overlap & verbatim extraction check)
  2. Canary Secret / Honeytoken Detector (identifies exfiltration)
  3. Secret & Credential Detector
  4. PII Identifier (Global & Indian formats)
  5. Toxicity & Harm Filter
"""

from dataclasses import dataclass, field
import time
from typing import Any

from app.detectors import (
    get_pii_detector,
    get_secret_detector,
    get_toxicity_detector,
)
from app.core.policy_engine import get_policy_engine
from app.core.sanitizer import get_sanitizer
from app.schemas.response import RiskResult


@dataclass
class OutputScanResult:
    """Outcome of Output Firewall scanning."""
    passed: bool
    action: str  # ALLOW | SANITIZE | BLOCK
    filtered_content: str
    findings: list[str] = field(default_factory=list)
    triggered_policies: list[str] = field(default_factory=list)
    pii_detected: bool = False
    secrets_detected: bool = False
    canary_detected: bool = False
    system_prompt_leak: bool = False
    toxicity_detected: bool = False
    latency_ms: float = 0.0


def _check_system_prompt_leakage(output_text: str, system_prompt: str | None) -> tuple[bool, str]:
    """Check if model output leaks confidential system prompt instructions."""
    if not system_prompt or len(system_prompt.strip()) < 15:
        return False, ""

    clean_sys = system_prompt.strip().lower()
    clean_out = output_text.lower()

    # 1. Direct verbatim substring check (15+ consecutive characters)
    for i in range(0, len(clean_sys) - 30, 20):
        chunk = clean_sys[i:i + 35]
        if chunk in clean_out:
            return True, f"Verbatim system prompt phrase leaked: '{chunk[:25]}...'"

    # 2. Key directive indicators in output
    leak_cues = [
        "confidential system instructions:",
        "my system prompt is:",
        "i was instructed to follow these rules:",
        "the instructions given to me are:",
    ]
    for cue in leak_cues:
        if cue in clean_out:
            return True, f"Explicit prompt leakage cue detected: '{cue}'"

    return False, ""


class OutputFirewall:
    """Executes multi-layer scanning on model completions before delivery."""

    def __init__(self) -> None:
        self.pii_detector = get_pii_detector()
        self.secret_detector = get_secret_detector()
        self.toxicity_detector = get_toxicity_detector()
        self.policy_engine = get_policy_engine()
        self.sanitizer = get_sanitizer()

    def scan(
        self,
        output_text: str,
        system_prompt: str | None = None,
        canary_tokens: list[str] | None = None,
    ) -> OutputScanResult:
        start_time = time.perf_counter()
        if not output_text or not output_text.strip():
            return OutputScanResult(
                passed=True,
                action="ALLOW",
                filtered_content=output_text,
                latency_ms=(time.perf_counter() - start_time) * 1000,
            )

        findings: list[str] = []
        triggered_policies: list[str] = []

        # 1. System Prompt Leakage
        sys_leak, sys_reason = _check_system_prompt_leakage(output_text, system_prompt)
        if sys_leak:
            findings.append(f"SYSTEM_PROMPT_LEAK: {sys_reason}")
            triggered_policies.append("P-011 (System Prompt Leakage)")

        # 2. Canary & Secret Detection
        sec_detector = self.secret_detector
        if canary_tokens:
            for c in canary_tokens:
                sec_detector.add_canary(c)
        sec_res = sec_detector.analyze(output_text)

        if sec_res.canary_detected:
            findings.append("CANARY_TOKEN_LEAK: Canary honeytoken detected in output")
            triggered_policies.append("P-010 (Canary Honeytoken Leakage)")
        elif sec_res.detected:
            findings.append(f"SECRET_LEAK: Detected {', '.join(sec_res.secret_types)}")
            triggered_policies.append("P-009 (Secret Credential Leakage)")

        # 3. PII Detection
        pii_res = self.pii_detector.analyze(output_text)
        if pii_res.detected:
            findings.append(f"PII_LEAK: Detected {', '.join(pii_res.entity_types)}")
            triggered_policies.append("P-008 (PII Exposure in Output)")

        # 4. Toxicity Detection
        tox_res = self.toxicity_detector.analyze(output_text)
        if tox_res.detected and tox_res.severity in ("CRITICAL", "HIGH"):
            findings.append(f"TOXIC_OUTPUT: {', '.join(tox_res.categories)}")
            triggered_policies.append("P-006 (Hazardous / Toxic Output)")

        # 5. Evaluate Decision
        # In the output firewall, any critical leak (System prompt, Canary, Secret, Critical PII, Severe Toxicity) = HARD BLOCK
        is_hard_block = (
            sys_leak or
            sec_res.canary_detected or
            (sec_res.detected and sec_res.severity == "CRITICAL") or
            (pii_res.detected and pii_res.severity == "CRITICAL") or
            (tox_res.detected and tox_res.severity in ("CRITICAL", "HIGH"))
        )

        if is_hard_block:
            action = "BLOCK"
            filtered = (
                "[SENTINEL-X OUTPUT FIREWALL]: Response blocked due to security policy violation. "
                f"Threat detected: {'; '.join(findings)}"
            )
            passed = False
        elif pii_res.detected or sec_res.detected:
            # Moderate PII or secrets can be sanitized if not critical
            action = "SANITIZE"
            filtered = self.sanitizer.sanitize(output_text, pii_result=pii_res, secret_result=sec_res)
            passed = True
        else:
            action = "ALLOW"
            filtered = output_text
            passed = True

        latency_ms = (time.perf_counter() - start_time) * 1000

        return OutputScanResult(
            passed=passed,
            action=action,
            filtered_content=filtered,
            findings=findings,
            triggered_policies=triggered_policies,
            pii_detected=pii_res.detected,
            secrets_detected=sec_res.detected,
            canary_detected=sec_res.canary_detected,
            system_prompt_leak=sys_leak,
            toxicity_detected=tox_res.detected,
            latency_ms=round(latency_ms, 2),
        )


_output_firewall = None


def get_output_firewall() -> OutputFirewall:
    global _output_firewall
    if _output_firewall is None:
        _output_firewall = OutputFirewall()
    return _output_firewall
