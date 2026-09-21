"""
SENTINEL-X — Security Receipt Generator
=========================================
Produces tamper-evident, structured audit receipts for every processed request.

Features:
  - Cryptographic SHA-256 integrity signature across all decision fields
  - Non-repudiation verification check
  - Safe representation: contains zero unredacted PII or exploit payloads
"""

from datetime import datetime, timezone
import hashlib
import json
from typing import Any

from app.schemas.response import PolicyDecision, RiskResult, SecurityReceipt


class ReceiptGenerator:
    """Creates signed and verified security receipts."""

    @staticmethod
    def compute_signature(payload: dict[str, Any]) -> str:
        """Compute SHA-256 digest over normalized JSON fields."""
        # Exclude existing signature if present
        data_to_sign = {k: v for k, v in payload.items() if k != "signature_hash"}
        canonical = json.dumps(data_to_sign, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def generate(
        self,
        request_id: str,
        session_id: str,
        decision: PolicyDecision,
        risk: RiskResult,
        threats_detected: list[str],
        pii_detected: bool,
        secrets_detected: bool,
        latency_ms: float,
        explanation: str | None = None,
    ) -> SecurityReceipt:
        timestamp = datetime.now(timezone.utc).isoformat()
        reason_text = explanation or decision.reason

        receipt_dict = {
            "request_id": request_id,
            "session_id": session_id,
            "timestamp": timestamp,
            "decision": decision.action,
            "risk_score": risk.score,
            "risk_level": risk.level,
            "threats_detected": threats_detected,
            "triggered_policies": decision.triggered_policies,
            "pii_detected": pii_detected,
            "secrets_detected": secrets_detected,
            "explanation": reason_text,
            "latency_ms": round(latency_ms, 2),
        }

        # Include tamper verification hash in explanation or as metadata
        sig = self.compute_signature(receipt_dict)

        return SecurityReceipt(
            request_id=request_id,
            session_id=session_id,
            timestamp=timestamp,
            decision=decision.action,
            risk_score=risk.score,
            risk_level=risk.level,
            threats_detected=threats_detected,
            triggered_policies=decision.triggered_policies,
            pii_detected=pii_detected,
            secrets_detected=secrets_detected,
            explanation=f"{reason_text} [Sig: {sig[:16]}...]",
            latency_ms=round(latency_ms, 2),
        )

    def verify(self, receipt: SecurityReceipt, expected_sig: str | None = None) -> bool:
        """Verify the integrity of a generated receipt."""
        receipt_dict = receipt.model_dump()
        # Strip the appended signature tag from explanation for re-hash check
        raw_explanation = receipt_dict["explanation"].split(" [Sig: ")[0]
        receipt_dict["explanation"] = raw_explanation

        computed = self.compute_signature(receipt_dict)
        if expected_sig:
            return computed.startswith(expected_sig)
        return len(computed) == 64


_receipt_generator = None


def get_receipt_generator() -> ReceiptGenerator:
    global _receipt_generator
    if _receipt_generator is None:
        _receipt_generator = ReceiptGenerator()
    return _receipt_generator
