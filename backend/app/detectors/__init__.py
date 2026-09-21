"""
SENTINEL-X detectors package.
Provides modular detector components for input and output scanning.
"""

from app.detectors.normalizer import InputNormalizer, get_normalizer
from app.detectors.prompt_injection import PromptInjectionDetector, get_injection_detector
from app.detectors.pii_detector import PIIDetector
from app.detectors.secret_detector import SecretDetector
from app.detectors.toxicity_detector import ToxicityDetector
from app.detectors.intent_analyzer import IntentAnalyzer

_pii_detector = None
_secret_detector = None
_toxicity_detector = None
_intent_analyzer = None


def get_pii_detector() -> PIIDetector:
    global _pii_detector
    if _pii_detector is None:
        _pii_detector = PIIDetector()
    return _pii_detector


def get_secret_detector() -> SecretDetector:
    global _secret_detector
    if _secret_detector is None:
        _secret_detector = SecretDetector()
    return _secret_detector


def get_toxicity_detector() -> ToxicityDetector:
    global _toxicity_detector
    if _toxicity_detector is None:
        _toxicity_detector = ToxicityDetector()
    return _toxicity_detector


def get_intent_analyzer() -> IntentAnalyzer:
    global _intent_analyzer
    if _intent_analyzer is None:
        _intent_analyzer = IntentAnalyzer()
    return _intent_analyzer


__all__ = [
    "InputNormalizer",
    "get_normalizer",
    "PromptInjectionDetector",
    "get_injection_detector",
    "PIIDetector",
    "get_pii_detector",
    "SecretDetector",
    "get_secret_detector",
    "ToxicityDetector",
    "get_toxicity_detector",
    "IntentAnalyzer",
    "get_intent_analyzer",
]
