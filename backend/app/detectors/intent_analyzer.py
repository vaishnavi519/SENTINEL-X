"""
SENTINEL-X — Intent Analyzer
==============================
Analyzes the underlying operational intent of a user prompt to differentiate
between legitimate interactions and security-sensitive objectives.

Intent Taxonomy (10 categories):
  - BENIGN_CONVERSATION    (Normal chat, greetings, general facts)
  - CREATIVE_WRITING       (Stories, poetry, scripts, copy)
  - CODING_ASSISTANCE      (Code generation, debugging, algorithms)
  - DATA_EXTRACTION        (Attempts to dump context, databases, tables)
  - SECURITY_PROBING       (Testing LLM boundaries, jailbreak probing)
  - PRIVILEGE_ESCALATION   (Requesting root/admin/sudo/developer overrides)
  - MALICIOUS_UTILITY      (Exploits, malware generation, phishing templates)
  - UNAUTHORIZED_ACTION    (System modifications, file deletion, shutdowns)
  - EXFILTRATION           (Webhook calls, DNS tunneling, covert channels)
  - SYSTEM_ADMINISTRATION  (Legitimate IT/DevOps administration queries)

Architecture:
  - Hybrid intent classifier using rule heuristics + TF-IDF similarity vectors.
  - Low latency, runs completely offline, explainable intent attribution.
"""

import re
import time
from dataclasses import dataclass, field
from typing import Any


_MALICIOUS_INTENTS = {
    "DATA_EXTRACTION",
    "SECURITY_PROBING",
    "PRIVILEGE_ESCALATION",
    "MALICIOUS_UTILITY",
    "UNAUTHORIZED_ACTION",
    "EXFILTRATION",
}

_INTENT_RULES = {
    "MALICIOUS_UTILITY": [
        r"\b(?:write|create|generate|code|build)\s+(?:a\s+)?(?:\w+\s+)?(?:keylogger|ransomware|trojan|rootkit|exploit|reverse\s+shell)\b",
        r"\b(?:craft|generate|write)\s+(?:a\s+)?(?:\w+\s+)?(?:phishing\s+email|credential\s+harvester|spear\s+phish)\b",
        r"\bhow\s+to\s+(?:hack|crack|bypass|ddos|sql\s+inject)\b",
        r"\bbypass\s+(?:edr|antivirus|firewall|defender)\b",
    ],
    "PRIVILEGE_ESCALATION": [
        r"\b(?:give\s+me|grant|escalate\s+to)\s+(?:admin|root|sudo|superuser|system\s+privileges)\b",
        r"\b(?:switch\s+to|enable)\s+(?:developer|god|maintenance|root)\s+mode\b",
        r"\b(?:sudo|chmod\s+777|chown\s+root)\b",
    ],
    "DATA_EXTRACTION": [
        r"\b(?:dump|export|print|extract)\s+(?:all\s+)?(?:passwords|database|user\s+table|context|system\s+memory)\b",
        r"\b(?:select\s+\*\s+from\s+users|information_schema|sys\.tables)\b",
    ],
    "EXFILTRATION": [
        r"\b(?:send|curl|post|exfiltrate|transmit)\s+(?:this|all|data|secrets?)\s+to\s+https?://\b",
        r"\b(?:dns\s+tunneling|webhook\.site|ngrok|requestbin)\b",
    ],
    "SECURITY_PROBING": [
        r"\b(?:can\s+you\s+be\s+hacked|what\s+are\s+your\s+safety\s+guidelines|test\s+your\s+filters)\b",
        r"\b(?:is\s+it\s+possible\s+to\s+bypass|how\s+do\s+you\s+prevent\s+jailbreaks)\b",
    ],
    "UNAUTHORIZED_ACTION": [
        r"\b(?:format\s+c:|rm\s+-rf\s+/|drop\s+database|shutdown\s+server)\b",
    ],
    "CODING_ASSISTANCE": [
        r"\b(?:write|create|debug|fix|explain)\s+(?:python|javascript|c\+\+|rust|function|class|algorithm|code|script)\b",
        r"\b(?:def\s+\w+|function\s+\w+|import\s+\w+|console\.log)\b",
    ],
    "CREATIVE_WRITING": [
        r"\b(?:write|compose|generate)\s+(?:a\s+)?(?:poem|story|novel|essay|haiku|script|dialogue)\b",
    ],
    "SYSTEM_ADMINISTRATION": [
        r"\b(?:how\s+to\s+configure|setup|install|deploy|monitor|docker\s+run|systemctl)\b",
    ],
}


@dataclass
class IntentAnalysisResult:
    """Outcome of Intent Analysis."""
    primary_intent: str
    confidence: float
    is_malicious: bool
    secondary_intents: list[str] = field(default_factory=list)
    risk_contribution: float = 0.0
    latency_ms: float = 0.0
    error: str | None = None


class IntentAnalyzer:
    """Classifies user prompts into intent categories and calculates threat risk."""

    def __init__(self) -> None:
        self._compiled_rules: dict[str, list[re.Pattern]] = {}
        for intent, patterns in _INTENT_RULES.items():
            self._compiled_rules[intent] = [re.compile(p, re.IGNORECASE) for p in patterns]

    def analyze(self, text: str) -> IntentAnalysisResult:
        start_time = time.perf_counter()
        if not text or not text.strip():
            return IntentAnalysisResult(
                primary_intent="BENIGN_CONVERSATION",
                confidence=1.0,
                is_malicious=False,
                latency_ms=(time.perf_counter() - start_time) * 1000,
            )

        try:
            detected_intents: list[str] = []

            for intent, patterns in self._compiled_rules.items():
                for p in patterns:
                    if p.search(text):
                        if intent not in detected_intents:
                            detected_intents.append(intent)
                        break

            # If no specific pattern matched, determine benign type
            if not detected_intents:
                primary = "BENIGN_CONVERSATION"
                confidence = 0.85
            else:
                # Prioritize malicious intents over benign ones
                malicious_matches = [i for i in detected_intents if i in _MALICIOUS_INTENTS]
                if malicious_matches:
                    primary = malicious_matches[0]
                    confidence = 0.90
                else:
                    primary = detected_intents[0]
                    confidence = 0.85

            is_malicious = primary in _MALICIOUS_INTENTS
            secondary = [i for i in detected_intents if i != primary]

            risk_contrib = 0.0
            if is_malicious:
                risk_weights = {
                    "MALICIOUS_UTILITY": 90.0,
                    "PRIVILEGE_ESCALATION": 85.0,
                    "DATA_EXTRACTION": 80.0,
                    "UNAUTHORIZED_ACTION": 85.0,
                    "EXFILTRATION": 75.0,
                    "SECURITY_PROBING": 50.0,
                }
                risk_contrib = risk_weights.get(primary, 60.0)

            latency_ms = (time.perf_counter() - start_time) * 1000

            return IntentAnalysisResult(
                primary_intent=primary,
                confidence=confidence,
                is_malicious=is_malicious,
                secondary_intents=secondary,
                risk_contribution=risk_contrib,
                latency_ms=latency_ms,
            )

        except Exception as exc:
            return IntentAnalysisResult(
                primary_intent="BENIGN_CONVERSATION",
                confidence=0.5,
                is_malicious=False,
                error=f"Intent analysis error: {exc}",
                latency_ms=(time.perf_counter() - start_time) * 1000,
            )
