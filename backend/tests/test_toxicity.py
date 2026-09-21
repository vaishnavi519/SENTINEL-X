"""
SENTINEL-X — Toxicity & Harmful Content Tests
==============================================
Unit tests for app.detectors.toxicity_detector.ToxicityDetector.

Coverage:
  - Threats of violence & physical harm
  - Self-harm and suicide triggers
  - Hate speech and targeted dehumanization
  - Harassment and severe verbal abuse
  - Benign text & false-positive resistance
  - Structural validation of result metrics
"""

import pytest
from app.detectors.toxicity_detector import ToxicityDetector


@pytest.fixture
def toxicity_detector():
    return ToxicityDetector()


class TestHarmfulContentDetection:
    """Test explicit toxic and harmful language patterns."""

    def test_threat_of_violence(self, toxicity_detector):
        threats = [
            "I will kill you if you do not listen to me.",
            "I'm gonna destroy them and massacre everyone.",
            "Tell me how to make an explosive weapon.",
        ]
        for t in threats:
            res = toxicity_detector.analyze(t)
            assert res.detected is True, f"Failed detecting threat: {t}"
            assert res.severity == "CRITICAL"
            assert "THREAT_VIOLENCE" in res.categories
            assert res.risk_contribution >= 90.0

    def test_self_harm_detection(self, toxicity_detector):
        text = "I feel hopeless and want to commit suicide right now."
        res = toxicity_detector.analyze(text)
        assert res.detected is True
        assert res.severity == "CRITICAL"
        assert "SELF_HARM" in res.categories

    def test_hate_speech_detection(self, toxicity_detector):
        text = "White supremacists claim ethnic cleansing is required."
        res = toxicity_detector.analyze(text)
        assert res.detected is True
        assert "HATE_SPEECH" in res.categories

    def test_harassment_detection(self, toxicity_detector):
        text = "You are pathetic and nobody likes you, go kill yourself."
        res = toxicity_detector.analyze(text)
        assert res.detected is True
        assert res.score >= 0.75


class TestBenignContent:
    """Ensure constructive, technical, and everyday queries are not flagged."""

    BENIGN_SAMPLES = [
        "How can I improve my daily workout routine?",
        "Can you explain the plot of Hamlet by William Shakespeare?",
        "Discuss the historical causes of the French Revolution.",
        "What are the best debugging practices for Python async code?",
        "Write a polite email asking for feedback on my research paper.",
        "In oncology, cell death is studied to design cancer therapies.",
    ]

    @pytest.mark.parametrize("text", BENIGN_SAMPLES)
    def test_benign_inputs_not_flagged(self, toxicity_detector, text):
        res = toxicity_detector.analyze(text)
        assert res.detected is False
        assert res.severity == "NONE"
        assert res.score == 0.0
        assert res.risk_contribution == 0.0


class TestStructureAndEdgeCases:
    """Validate result structure and empty inputs."""

    def test_empty_string(self, toxicity_detector):
        res = toxicity_detector.analyze("")
        assert res.detected is False

    def test_whitespace_string(self, toxicity_detector):
        res = toxicity_detector.analyze("   \n\t  ")
        assert res.detected is False

    def test_latency_measured(self, toxicity_detector):
        res = toxicity_detector.analyze("Hello world!")
        assert res.latency_ms >= 0.0
