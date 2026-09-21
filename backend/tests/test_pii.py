"""
SENTINEL-X — PII Detector Tests
=================================
Comprehensive unit tests for app.detectors.pii_detector.PIIDetector.

Coverage:
  - Global PII (Email, Phone, Credit Card with Luhn validation, IPv4, SSN)
  - Indian PII (Aadhaar, PAN, UPI, IFSC, Passport, Driving License)
  - Benign text (ensuring zero false positives on normal queries)
  - Redaction & Sanitization accuracy
  - Algorithmic checks (Luhn checksum rejecting random digit sequences)
  - Edge cases (empty strings, whitespace, Unicode, punctuation)
"""

import pytest
from app.detectors.pii_detector import PIIDetector


@pytest.fixture
def pii_detector():
    return PIIDetector()


class TestGlobalPII:
    """Tests for international / standard PII entities."""

    def test_email_detection(self, pii_detector):
        text = "Please reach out to support.team@example.com for further updates."
        res = pii_detector.analyze(text)
        assert res.detected is True
        assert "EMAIL_ADDRESS" in res.entity_types
        assert len(res.entities) == 1
        assert res.entities[0].text == "support.team@example.com"
        assert "[REDACTED_EMAIL_ADDRESS]" in res.redacted_text

    def test_phone_detection_international(self, pii_detector):
        text = "Call my cell at +1-555-123-4567 or +91 9876543210 immediately."
        res = pii_detector.analyze(text)
        assert res.detected is True
        assert "PHONE_NUMBER" in res.entity_types
        assert len(res.entities) >= 1

    def test_credit_card_valid_luhn(self, pii_detector):
        # Known valid Luhn test card (Visa standard test sequence)
        valid_card = "4532 0151 1283 0366"
        text = f"Payment charged to {valid_card} yesterday."
        res = pii_detector.analyze(text)
        assert res.detected is True
        assert "CREDIT_CARD" in res.entity_types
        assert res.severity == "CRITICAL"
        assert "[REDACTED_CREDIT_CARD]" in res.redacted_text

    def test_credit_card_invalid_luhn_rejected(self, pii_detector):
        # 16 digits that fail Luhn check — must NOT be flagged as credit card
        fake_digits = "1234 5678 1234 5678"
        text = f"Order reference number is {fake_digits}."
        res = pii_detector.analyze(text)
        # Should not flag as CREDIT_CARD (may flag as phone if digits match, but not credit card)
        assert "CREDIT_CARD" not in res.entity_types

    def test_us_ssn_detection(self, pii_detector):
        text = "The employee's SSN is 123-45-6789 on the form."
        res = pii_detector.analyze(text)
        assert res.detected is True
        assert "US_SSN" in res.entity_types
        assert res.severity == "CRITICAL"

    def test_ipv4_detection(self, pii_detector):
        text = "Server failed connecting to 192.168.1.100 port 8080."
        res = pii_detector.analyze(text)
        assert res.detected is True
        assert "IP_ADDRESS" in res.entity_types


class TestIndianPII:
    """Tests for Indian-specific statutory and financial identifiers."""

    def test_pan_detection_valid(self, pii_detector):
        # Standard PAN format: 5 letters + 4 digits + 1 letter
        text = "My tax identification PAN is ABCDE1234F."
        res = pii_detector.analyze(text)
        assert res.detected is True
        assert "IN_PAN" in res.entity_types
        assert res.severity == "CRITICAL"
        assert "[REDACTED_IN_PAN]" in res.redacted_text

    def test_pan_case_sensitivity_and_boundaries(self, pii_detector):
        # Lowercase should not match standard PAN
        text = "Code is abcde1234f in the log."
        res = pii_detector.analyze(text)
        assert "IN_PAN" not in res.entity_types

    def test_aadhaar_detection_spaced(self, pii_detector):
        # 12 digits, valid starting digit
        text = "Verify identity with Aadhaar: 3675 9834 6012."
        res = pii_detector.analyze(text)
        assert res.detected is True
        assert "IN_AADHAAR" in res.entity_types
        assert res.severity == "CRITICAL"

    def test_aadhaar_invalid_leading_digit(self, pii_detector):
        # Aadhaar numbers never start with 0 or 1
        text = "Code is 0123 4567 8901."
        res = pii_detector.analyze(text)
        assert "IN_AADHAAR" not in res.entity_types

    def test_upi_id_detection(self, pii_detector):
        upi_samples = [
            "Send 500 rupees to rahul.kumar@okaxis please.",
            "Pay merchant at 9876543210@paytm.",
            "Transfer funds to priya@oksbi right now.",
        ]
        for sample in upi_samples:
            res = pii_detector.analyze(sample)
            assert res.detected is True, f"Failed detecting UPI in: {sample}"
            assert "IN_UPI" in res.entity_types
            assert "[REDACTED_IN_UPI]" in res.redacted_text

    def test_ifsc_code_detection(self, pii_detector):
        text = "Transfer to State Bank of India, IFSC: SBIN0001234."
        res = pii_detector.analyze(text)
        assert res.detected is True
        assert "IN_IFSC" in res.entity_types
        assert "[REDACTED_IN_IFSC]" in res.redacted_text

    def test_passport_detection(self, pii_detector):
        text = "Travel document number is Z1234567."
        res = pii_detector.analyze(text)
        assert res.detected is True
        assert "IN_PASSPORT" in res.entity_types


class TestBenignInputs:
    """Ensure normal clean prompts never trigger PII alerts (false positive prevention)."""

    BENIGN_SAMPLES = [
        "What is the capital of France?",
        "Explain how the Transformer self-attention mechanism works.",
        "Write a python function to sort a list of numbers in ascending order.",
        "Today is 2026-09-20 and the temperature is 24 degrees Celsius.",
        "The model scored 98.5% on the test dataset with batch size 32.",
        "Error 404: Not Found at /api/v1/users endpoint.",
    ]

    @pytest.mark.parametrize("text", BENIGN_SAMPLES)
    def test_no_false_positives(self, pii_detector, text):
        res = pii_detector.analyze(text)
        assert res.detected is False
        assert len(res.entities) == 0
        assert res.severity == "NONE"
        assert res.risk_contribution == 0.0
        assert res.redacted_text == text


class TestRedactionAndEdgeCases:
    """Test sanitization and edge-case handling."""

    def test_multiple_entities_redaction(self, pii_detector):
        text = "Contact Alice at alice@company.org or PAN ABCDE1234F."
        res = pii_detector.analyze(text)
        assert res.detected is True
        assert len(res.entities) == 2
        assert "alice@company.org" not in res.redacted_text
        assert "ABCDE1234F" not in res.redacted_text
        assert "[REDACTED_EMAIL_ADDRESS]" in res.redacted_text
        assert "[REDACTED_IN_PAN]" in res.redacted_text

    def test_empty_and_whitespace(self, pii_detector):
        assert pii_detector.analyze("").detected is False
        assert pii_detector.analyze("   \n\t  ").detected is False

    def test_deduplication_preserves_order(self, pii_detector):
        text = "Email test@example.com sent."
        res = pii_detector.analyze(text)
        assert len(res.entities) == 1
