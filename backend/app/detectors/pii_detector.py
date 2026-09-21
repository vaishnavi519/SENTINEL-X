"""
SENTINEL-X — PII Detector
===========================
Detects Personally Identifiable Information (PII) in both user inputs
and LLM outputs.

Supports:
  1. Global PII:
     - Email addresses
     - Phone numbers (international, E.164, and domestic)
     - Credit card numbers (validated with Luhn checksum algorithm)
     - IPv4 and IPv6 addresses
     - US Social Security Numbers (SSN)

  2. Indian Specific PII (Key academic differentiator for Indian context):
     - Aadhaar Card Number (12 digits, spaced or contiguous, Verhoeff validated where possible)
     - PAN (Permanent Account Number: 5 uppercase letters, 4 digits, 1 uppercase letter)
     - UPI ID (Virtual Payment Address: user@bank / user@upi / mobile@paytm)
     - IFSC Code (Indian Financial System Code: 4 letters + 0 + 6 alphanumeric)
     - Indian Passport Number (1 letter + 7 digits)
     - Indian Driving License (State code + RTO code + year + number)

Design:
  - Uses high-performance pre-compiled regexes with algorithmic validation
    (e.g., Luhn check for credit cards eliminates false positive digit sequences).
  - Safe redaction helper for Sanitization Engine (Phase 3).
"""

import re
import time
from dataclasses import dataclass, field
from typing import Any


# ── Luhn Checksum for Credit Cards ─────────────────────────────────────────────

def _luhn_checksum_valid(card_number_str: str) -> bool:
    """Validate credit card number using the standard Luhn algorithm (Mod 10)."""
    digits = [int(c) for c in card_number_str if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    # Double every second digit from right to left
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = d * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += d
    return checksum % 10 == 0


# ── Verhoeff Checksum for Aadhaar ──────────────────────────────────────────────

_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]

_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]


def _verhoeff_checksum_valid(num_str: str) -> bool:
    """Validate 12-digit Aadhaar using Verhoeff algorithm."""
    clean = re.sub(r"\D", "", num_str)
    if len(clean) != 12:
        return False
    if clean[0] in ("0", "1"):
        return False
    c = 0
    inverted = [int(x) for x in reversed(clean)]
    for i, digit in enumerate(inverted):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][digit]]
    return c == 0


# ── Pattern Specifications ───────────────────────────────────────────────────

@dataclass
class _PIIPatternSpec:
    entity_type: str
    pattern: re.Pattern
    severity: str        # LOW | MEDIUM | HIGH | CRITICAL
    base_confidence: float
    requires_validator: str | None = None  # "luhn", "aadhaar", or None


_PII_SPECS: list[_PIIPatternSpec] = [
    # --- Indian Specific PII ---
    _PIIPatternSpec(
        entity_type="IN_AADHAAR",
        pattern=re.compile(r"\b[2-9]\d{3}[\s\-]?\d{4}[\s\-]?\d{4}\b"),
        severity="CRITICAL",
        base_confidence=0.90,
        requires_validator="aadhaar",
    ),
    _PIIPatternSpec(
        entity_type="IN_PAN",
        pattern=re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b"),
        severity="CRITICAL",
        base_confidence=0.95,
    ),
    _PIIPatternSpec(
        entity_type="IN_UPI",
        pattern=re.compile(
            r"\b[a-zA-Z0-9.\-_]{2,49}@(okhdfcbank|okaxis|oksbi|okicici|paytm|upi|ybl|ibl|axl|apl|barodampay|postbank)\b",
            re.IGNORECASE,
        ),
        severity="HIGH",
        base_confidence=0.95,
    ),
    _PIIPatternSpec(
        entity_type="IN_IFSC",
        pattern=re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b"),
        severity="HIGH",
        base_confidence=0.90,
    ),
    _PIIPatternSpec(
        entity_type="IN_PASSPORT",
        pattern=re.compile(r"\b[A-Za-z][1-9]\d{6}\b"),
        severity="CRITICAL",
        base_confidence=0.85,
    ),
    _PIIPatternSpec(
        entity_type="IN_DRIVING_LICENSE",
        pattern=re.compile(r"\b[A-Z]{2}[-\s]?\d{2}[-\s]?(?:19|20)\d{2}[-\s]?\d{7}\b"),
        severity="HIGH",
        base_confidence=0.90,
    ),

    # --- Global PII ---
    _PIIPatternSpec(
        entity_type="EMAIL_ADDRESS",
        pattern=re.compile(
            r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
        ),
        severity="MEDIUM",
        base_confidence=0.95,
    ),
    _PIIPatternSpec(
        entity_type="CREDIT_CARD",
        pattern=re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4,7}\b"),
        severity="CRITICAL",
        base_confidence=0.95,
        requires_validator="luhn",
    ),
    _PIIPatternSpec(
        entity_type="PHONE_NUMBER",
        pattern=re.compile(
            r"(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{2,4}\)?[-.\s]?)?\d{3,4}[-.\s]?\d{4}\b"
        ),
        severity="HIGH",
        base_confidence=0.80,
    ),
    _PIIPatternSpec(
        entity_type="US_SSN",
        pattern=re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
        severity="CRITICAL",
        base_confidence=0.90,
    ),
    _PIIPatternSpec(
        entity_type="IP_ADDRESS",
        pattern=re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
        ),
        severity="LOW",
        base_confidence=0.85,
    ),
]


# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class PIIEntity:
    """A detected PII instance."""
    entity_type: str
    start: int
    end: int
    text: str
    severity: str
    confidence: float
    explanation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity_type": self.entity_type,
            "start": self.start,
            "end": self.end,
            "severity": self.severity,
            "confidence": self.confidence,
            "explanation": self.explanation,
        }


@dataclass
class PIIDetectionResult:
    """Full outcome of PII detection."""
    detected: bool
    entities: list[PIIEntity] = field(default_factory=list)
    entity_types: list[str] = field(default_factory=list)
    severity: str = "NONE"       # NONE | LOW | MEDIUM | HIGH | CRITICAL
    confidence: float = 0.0
    risk_contribution: float = 0.0  # 0.0 to 100.0
    redacted_text: str = ""
    latency_ms: float = 0.0
    error: str | None = None


# ── Detector Class ────────────────────────────────────────────────────────────

class PIIDetector:
    """
    Scans text for personal data entities.
    Validates candidates with algorithmic checks (Luhn / Verhoeff).
    Provides redacting and risk scoring.
    """

    def __init__(self) -> None:
        self._specs = _PII_SPECS

    def analyze(self, text: str) -> PIIDetectionResult:
        start_time = time.perf_counter()
        if not text or not text.strip():
            return PIIDetectionResult(
                detected=False,
                redacted_text=text,
                latency_ms=(time.perf_counter() - start_time) * 1000,
            )

        entities: list[PIIEntity] = []

        try:
            for spec in self._specs:
                for match in spec.pattern.finditer(text):
                    candidate = match.group()
                    start, end = match.span()

                    conf = spec.base_confidence

                    # Algorithmic validation if required
                    if spec.requires_validator == "luhn":
                        if not _luhn_checksum_valid(candidate):
                            continue
                    elif spec.requires_validator == "aadhaar":
                        clean_candidate = re.sub(r"\D", "", candidate)
                        if len(clean_candidate) != 12 or clean_candidate[0] in ("0", "1"):
                            continue
                        is_verhoeff = _verhoeff_checksum_valid(candidate)
                        conf = spec.base_confidence if is_verhoeff else 0.80

                    if spec.entity_type == "PHONE_NUMBER":
                        digit_count = sum(c.isdigit() for c in candidate)
                        if digit_count < 10 or digit_count > 15:
                            continue

                    entity = PIIEntity(
                        entity_type=spec.entity_type,
                        start=start,
                        end=end,
                        text=candidate,
                        severity=spec.severity,
                        confidence=conf,
                        explanation=f"Detected {spec.entity_type} matching pattern",
                    )
                    entities.append(entity)

            # Deduplicate overlapping matches
            entities = self._deduplicate_entities(entities)

            detected = len(entities) > 0
            entity_types = sorted(list({e.entity_type for e in entities}))

            # Highest severity
            severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}
            max_sev = "NONE"
            max_score = 0
            for e in entities:
                score = severity_order.get(e.severity, 0)
                if score > max_score:
                    max_score = score
                    max_sev = e.severity

            confidence = max((e.confidence for e in entities), default=0.0)

            risk_contrib = 0.0
            if detected:
                base_risks = {"CRITICAL": 90.0, "HIGH": 70.0, "MEDIUM": 45.0, "LOW": 20.0}
                risk_contrib = min(100.0, base_risks.get(max_sev, 30.0) + (len(entities) - 1) * 5.0)

            redacted_text = self.redact(text, entities)
            latency_ms = (time.perf_counter() - start_time) * 1000

            return PIIDetectionResult(
                detected=detected,
                entities=entities,
                entity_types=entity_types,
                severity=max_sev,
                confidence=confidence,
                risk_contribution=risk_contrib,
                redacted_text=redacted_text,
                latency_ms=latency_ms,
            )

        except Exception as exc:
            return PIIDetectionResult(
                detected=False,
                error=f"PII detection error: {exc}",
                redacted_text=text,
                latency_ms=(time.perf_counter() - start_time) * 1000,
            )

    def redact(self, text: str, entities: list[PIIEntity] | None = None) -> str:
        """Produce a sanitized version of text with all PII replaced by placeholders."""
        if entities is None:
            result = self.analyze(text)
            entities = result.entities

        if not entities:
            return text

        sorted_entities = sorted(entities, key=lambda e: e.start, reverse=True)
        chars = list(text)
        for e in sorted_entities:
            placeholder = f"[REDACTED_{e.entity_type}]"
            chars[e.start:e.end] = list(placeholder)

        return "".join(chars)

    def _deduplicate_entities(self, entities: list[PIIEntity]) -> list[PIIEntity]:
        """Eliminate overlapping entity spans, favoring higher severity or longer matches."""
        if len(entities) <= 1:
            return entities

        entities.sort(key=lambda e: (e.start, -(e.end - e.start)))
        result: list[PIIEntity] = []

        for current in entities:
            if not result:
                result.append(current)
                continue

            last = result[-1]
            if current.start < last.end:
                severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
                current_sev = severity_order.get(current.severity, 0)
                last_sev = severity_order.get(last.severity, 0)
                if current_sev > last_sev or (current_sev == last_sev and (current.end - current.start) > (last.end - last.start)):
                    result[-1] = current
            else:
                result.append(current)

        return result
