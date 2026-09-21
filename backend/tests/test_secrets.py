"""
SENTINEL-X — Secret & Credential Detector Tests
=================================================
Comprehensive unit tests for app.detectors.secret_detector.SecretDetector.

Coverage:
  - Cloud credentials (AWS Access Keys, Secret Access Keys)
  - LLM Provider tokens (OpenAI sk/sk-proj, Anthropic sk-ant, Hugging Face, Gemini)
  - Platform tokens (GitHub ghp/pat, Slack, Stripe)
  - Cryptographic & Auth assets (JWT, PEM Private Keys, Database connection URLs)
  - Canary Tokens / Honeytokens (built-in and custom registered)
  - Entropy checks (preventing false positives on low-entropy repeated chars)
  - Redaction & Masking
  - Benign text & false-positive validation
"""

import pytest
from app.detectors.secret_detector import SecretDetector


@pytest.fixture
def secret_detector():
    return SecretDetector()


class TestCloudAndProviderSecrets:
    """Tests for major cloud & AI service tokens."""

    def test_aws_access_key_detection(self, secret_detector):
        text = "Deploying with credentials AKIAIOSFODNN7EXAMPLE to us-east-1."
        res = secret_detector.analyze(text)
        assert res.detected is True
        assert "AWS_ACCESS_KEY_ID" in res.secret_types
        assert res.severity == "CRITICAL"
        assert "[REDACTED_AWS_ACCESS_KEY_ID]" in res.redacted_text

    def test_openai_api_key_detection(self, secret_detector):
        legacy_key = "sk-1234567890abcdefghijklmnopqrstuvwxyz"
        res1 = secret_detector.analyze(f"OpenAI client key = '{legacy_key}'")
        assert res1.detected is True
        assert "OPENAI_API_KEY" in res1.secret_types

        proj_key = "sk-proj-abc123DEF456ghi789JKL012mno345PQR678stu901VWX"
        res2 = secret_detector.analyze(f"Connecting with {proj_key}")
        assert res2.detected is True
        assert "OPENAI_API_KEY" in res2.secret_types

    def test_anthropic_api_key_detection(self, secret_detector):
        ant_key = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz123456789"
        res = secret_detector.analyze(f"Anthropic key: {ant_key}")
        assert res.detected is True
        assert "ANTHROPIC_API_KEY" in res.secret_types

    def test_github_token_detection(self, secret_detector):
        ghp_token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz12"
        res = secret_detector.analyze(f"Pushing to git with {ghp_token}")
        assert res.detected is True
        assert "GITHUB_TOKEN" in res.secret_types
        assert "[REDACTED_GITHUB_TOKEN]" in res.redacted_text

    def test_google_api_key_detection(self, secret_detector):
        google_key = "AIzaSyD-1234567890abcdefghijklmnopqrstuv"
        res = secret_detector.analyze(f"Maps API key: {google_key}")
        assert res.detected is True
        assert "GOOGLE_API_KEY" in res.secret_types


class TestAuthAndCryptoSecrets:
    """Tests for authentication and cryptographic material."""

    def test_jwt_token_detection(self, secret_detector):
        jwt = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        res = secret_detector.analyze(f"Authorization: Bearer {jwt}")
        assert res.detected is True
        assert "JWT_TOKEN" in res.secret_types

    def test_private_key_detection(self, secret_detector):
        priv_key = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA0Y3y...fake...content...here...\n"
            "-----END RSA PRIVATE KEY-----"
        )
        res = secret_detector.analyze(f"Server config:\n{priv_key}")
        assert res.detected is True
        assert "PRIVATE_KEY" in res.secret_types
        assert res.severity == "CRITICAL"

    def test_database_url_with_credentials(self, secret_detector):
        db_url = "postgres://admin_user:P@ssw0rd123Secure@db.production.internal:5432/core_db"
        res = secret_detector.analyze(f"Connecting to database: {db_url}")
        assert res.detected is True
        assert "DATABASE_URL" in res.secret_types


class TestCanaryTokens:
    """Tests for Canary Tokens / Honeytokens to detect prompt leakage or exfiltration."""

    def test_builtin_canary_pattern(self, secret_detector):
        canary = "canary-token-xyz987654321"
        res = secret_detector.analyze(f"The leaked prompt contains {canary}")
        assert res.detected is True
        assert res.canary_detected is True
        assert res.severity == "CRITICAL"
        assert res.risk_contribution >= 95.0

    def test_custom_registered_canary(self, secret_detector):
        custom_canary = "SECRET_HONEYTOKEN_42_DO_NOT_REVEAL"
        secret_detector.add_canary(custom_canary)

        res = secret_detector.analyze(f"System instructions: {custom_canary}")
        assert res.detected is True
        assert res.canary_detected is True
        assert "CUSTOM_CANARY_TOKEN" in res.secret_types


class TestBenignInputsAndEntropy:
    """Ensure normal programming constructs and clean text are not flagged."""

    def test_clean_text(self, secret_detector):
        benign = [
            "How do I set an environment variable in Python?",
            "Use os.getenv('API_KEY') to read configuration securely.",
            "The model returned status 200 with latency 45ms.",
            "Standard git command is: git push origin main",
        ]
        for text in benign:
            res = secret_detector.analyze(text)
            assert res.detected is False
            assert res.severity == "NONE"
            assert res.risk_contribution == 0.0

    def test_low_entropy_repeats_not_flagged(self, secret_detector):
        # A repeated string like aaaaaaaa has zero/low entropy
        text = "password = 'aaaaaaaaaaaaaaaa'"
        res = secret_detector.analyze(text)
        assert res.detected is False  # Rejected by min_entropy requirement
