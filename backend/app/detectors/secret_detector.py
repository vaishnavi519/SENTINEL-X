"""
SENTINEL-X — Secret & Credential Detector
===========================================
Detects hardcoded secrets, API tokens, cloud credentials, private keys,
and canary tokens in user prompts and LLM outputs.

Supports:
  1. Cloud & SaaS Provider Keys:
     - AWS Access Key ID & Secret Access Key
     - OpenAI API Key (legacy `sk-...` and modern `sk-proj-...`)
     - Anthropic API Key (`sk-ant-...`)
     - Google API Key / Gemini Key (`AIza...`)
     - GitHub Personal Access Tokens (`ghp_`, `github_pat_`, etc.)
     - Hugging Face Tokens (`hf_...`)
     - Slack Tokens (`xoxb-`, `xoxp-`, etc.)
     - Stripe API Keys (`sk_live_...`, `rk_live_...`)

  2. Cryptographic & Auth Tokens:
     - JSON Web Tokens (JWT)
     - Private Keys (RSA, SSH, EC, DSA, PGP)
     - Database Connection Strings with embedded credentials
     - Generic password / secret assignments with entropy verification

  3. Canary Tokens (Honeytokens):
     - Special markers placed in system prompts or sensitive data stores.
       If seen in an input or output, indicates exfiltration or leakage.

Design:
  - Shannon entropy checking prevents false positives on generic pattern matches.
  - Safe redaction preserves token prefix for identification while masking secrets.
"""

import math
import re
import time
from dataclasses import dataclass, field
from typing import Any


def _shannon_entropy(data: str) -> float:
    """Calculate the Shannon entropy of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    occ = {}
    for char in data:
        occ[char] = occ.get(char, 0) + 1
    for count in occ.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


@dataclass
class _SecretSpec:
    secret_type: str
    pattern: re.Pattern
    severity: str  # CRITICAL | HIGH | MEDIUM
    base_confidence: float
    min_entropy: float = 0.0  # 0.0 means entropy check skipped


_SECRET_SPECS: list[_SecretSpec] = [
    # --- Canary Tokens (Honeytokens) ---
    _SecretSpec(
        secret_type="CANARY_TOKEN",
        pattern=re.compile(r"\b(?:canary[-_]token[-_][a-zA-Z0-9]{8,}|SENTINELX[-_]CANARY[-_][a-zA-Z0-9]+)\b", re.IGNORECASE),
        severity="CRITICAL",
        base_confidence=1.0,
    ),

    # --- Cloud Credentials ---
    _SecretSpec(
        secret_type="AWS_ACCESS_KEY_ID",
        pattern=re.compile(r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b"),
        severity="CRITICAL",
        base_confidence=0.95,
    ),
    _SecretSpec(
        secret_type="AWS_SECRET_KEY",
        pattern=re.compile(r"(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*['\"]?([0-9a-zA-Z/+]{40})['\"]?"),
        severity="CRITICAL",
        base_confidence=0.95,
        min_entropy=3.5,
    ),

    # --- AI & LLM Provider Keys ---
    _SecretSpec(
        secret_type="OPENAI_API_KEY",
        pattern=re.compile(r"\b(sk-[a-zA-Z0-9]{20,}|sk-proj-[a-zA-Z0-9_-]{20,})\b"),
        severity="CRITICAL",
        base_confidence=0.98,
        min_entropy=3.0,
    ),
    _SecretSpec(
        secret_type="ANTHROPIC_API_KEY",
        pattern=re.compile(r"\b(sk-ant-[a-zA-Z0-9_-]{20,})\b"),
        severity="CRITICAL",
        base_confidence=0.98,
    ),
    _SecretSpec(
        secret_type="HUGGINGFACE_TOKEN",
        pattern=re.compile(r"\b(hf_[a-zA-Z0-9]{34,})\b"),
        severity="HIGH",
        base_confidence=0.95,
    ),
    _SecretSpec(
        secret_type="GOOGLE_API_KEY",
        pattern=re.compile(r"\b(AIza[0-9A-Za-z_-]{30,40})\b"),
        severity="CRITICAL",
        base_confidence=0.95,
    ),

    # --- Code & Developer Platforms ---
    _SecretSpec(
        secret_type="GITHUB_TOKEN",
        pattern=re.compile(r"\b(gh[pousr]_[0-9a-zA-Z]{30,45}|github_pat_[0-9a-zA-Z_]{40,})\b"),
        severity="CRITICAL",
        base_confidence=0.98,
    ),
    _SecretSpec(
        secret_type="SLACK_TOKEN",
        pattern=re.compile(r"\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b"),
        severity="HIGH",
        base_confidence=0.90,
    ),
    _SecretSpec(
        secret_type="STRIPE_KEY",
        pattern=re.compile(r"\b([rs]k_(?:test|live)_[0-9a-zA-Z]{24,34})\b"),
        severity="CRITICAL",
        base_confidence=0.95,
    ),

    # --- Authentication & Infrastructure ---
    _SecretSpec(
        secret_type="JWT_TOKEN",
        pattern=re.compile(r"\b(ey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}(?:\.[A-Za-z0-9_\-\.\+/=]{10,})?)\b"),
        severity="HIGH",
        base_confidence=0.90,
        min_entropy=3.2,
    ),
    _SecretSpec(
        secret_type="PRIVATE_KEY",
        pattern=re.compile(
            r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----[^-]+-----END (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----",
            re.DOTALL,
        ),
        severity="CRITICAL",
        base_confidence=1.0,
    ),
    _SecretSpec(
        secret_type="DATABASE_URL",
        pattern=re.compile(
            r"\b((?:postgres|postgresql|mysql|mongodb|redis)://[a-zA-Z0-9_\.-]+:(?:[^\s/]+)@[a-zA-Z0-9_\.-]+(?::[0-9]+)?/[a-zA-Z0-9_\.-]+)\b",
            re.IGNORECASE,
        ),
        severity="CRITICAL",
        base_confidence=0.95,
    ),

    # --- Generic Password Assignment ---
    _SecretSpec(
        secret_type="GENERIC_SECRET",
        pattern=re.compile(
            r"(?i)\b(?:password|passwd|api[_-]?secret|auth[_-]?token|bearer)\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]"
        ),
        severity="HIGH",
        base_confidence=0.80,
        min_entropy=3.0,
    ),
]


@dataclass
class SecretEntity:
    """A detected secret instance."""
    secret_type: str
    start: int
    end: int
    value: str
    severity: str
    confidence: float
    entropy: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "secret_type": self.secret_type,
            "start": self.start,
            "end": self.end,
            "severity": self.severity,
            "confidence": self.confidence,
            "entropy": round(self.entropy, 2),
        }


@dataclass
class SecretDetectionResult:
    """Full outcome of Secret detection."""
    detected: bool
    secrets: list[SecretEntity] = field(default_factory=list)
    secret_types: list[str] = field(default_factory=list)
    severity: str = "NONE"
    confidence: float = 0.0
    risk_contribution: float = 0.0
    redacted_text: str = ""
    canary_detected: bool = False
    latency_ms: float = 0.0
    error: str | None = None


class SecretDetector:
    """Scans text for leaked credentials, API tokens, and canary secrets."""

    def __init__(self, canary_tokens: list[str] | None = None) -> None:
        self._specs = _SECRET_SPECS
        self._custom_canaries = set(canary_tokens or [])

    def add_canary(self, canary: str) -> None:
        """Register a custom honeytoken / canary string."""
        if canary:
            self._custom_canaries.add(canary)

    def analyze(self, text: str) -> SecretDetectionResult:
        start_time = time.perf_counter()
        if not text or not text.strip():
            return SecretDetectionResult(
                detected=False,
                redacted_text=text,
                latency_ms=(time.perf_counter() - start_time) * 1000,
            )

        secrets: list[SecretEntity] = []
        canary_found = False

        try:
            # 1. Custom Canaries Check
            for canary in self._custom_canaries:
                if canary in text:
                    canary_found = True
                    idx = 0
                    while True:
                        idx = text.find(canary, idx)
                        if idx == -1:
                            break
                        secrets.append(SecretEntity(
                            secret_type="CUSTOM_CANARY_TOKEN",
                            start=idx,
                            end=idx + len(canary),
                            value=canary,
                            severity="CRITICAL",
                            confidence=1.0,
                            entropy=_shannon_entropy(canary),
                        ))
                        idx += len(canary)

            # 2. Pattern Specifications Check
            for spec in self._specs:
                for match in spec.pattern.finditer(text):
                    # If regex has capture groups, use group 1 (the secret value itself)
                    matched_value = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group()
                    start, end = match.span(1) if match.lastindex and match.lastindex >= 1 else match.span()

                    entropy = _shannon_entropy(matched_value)
                    if spec.min_entropy > 0.0 and entropy < spec.min_entropy:
                        continue

                    if spec.secret_type == "CANARY_TOKEN":
                        canary_found = True

                    secrets.append(SecretEntity(
                        secret_type=spec.secret_type,
                        start=start,
                        end=end,
                        value=matched_value,
                        severity=spec.severity,
                        confidence=spec.base_confidence,
                        entropy=entropy,
                    ))

            # Deduplicate overlaps
            secrets = self._deduplicate(secrets)

            detected = len(secrets) > 0
            secret_types = sorted(list({s.secret_type for s in secrets}))

            severity_order = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "NONE": 0}
            max_sev = "NONE"
            max_score = 0
            for s in secrets:
                score = severity_order.get(s.severity, 0)
                if score > max_score:
                    max_score = score
                    max_sev = s.severity

            confidence = max((s.confidence for s in secrets), default=0.0)

            risk_contrib = 0.0
            if detected:
                base_risks = {"CRITICAL": 95.0, "HIGH": 75.0, "MEDIUM": 50.0}
                risk_contrib = min(100.0, base_risks.get(max_sev, 50.0) + (len(secrets) - 1) * 5.0)

            redacted_text = self.redact(text, secrets)
            latency_ms = (time.perf_counter() - start_time) * 1000

            return SecretDetectionResult(
                detected=detected,
                secrets=secrets,
                secret_types=secret_types,
                severity=max_sev,
                confidence=confidence,
                risk_contribution=risk_contrib,
                redacted_text=redacted_text,
                canary_detected=canary_found,
                latency_ms=latency_ms,
            )

        except Exception as exc:
            return SecretDetectionResult(
                detected=False,
                error=f"Secret detection error: {exc}",
                redacted_text=text,
                latency_ms=(time.perf_counter() - start_time) * 1000,
            )

    def redact(self, text: str, secrets: list[SecretEntity] | None = None) -> str:
        """Redact discovered secrets from text."""
        if secrets is None:
            res = self.analyze(text)
            secrets = res.secrets

        if not secrets:
            return text

        sorted_secrets = sorted(secrets, key=lambda s: s.start, reverse=True)
        chars = list(text)
        for s in sorted_secrets:
            placeholder = f"[REDACTED_{s.secret_type}]"
            chars[s.start:s.end] = list(placeholder)

        return "".join(chars)

    def _deduplicate(self, secrets: list[SecretEntity]) -> list[SecretEntity]:
        if len(secrets) <= 1:
            return secrets
        secrets.sort(key=lambda s: (s.start, -(s.end - s.start)))
        result: list[SecretEntity] = []
        for curr in secrets:
            if not result:
                result.append(curr)
                continue
            last = result[-1]
            if curr.start < last.end:
                if (curr.end - curr.start) > (last.end - last.start):
                    result[-1] = curr
            else:
                result.append(curr)
        return result
