"""
SENTINEL-X — Input Normalizer
================================
The first stage of the security pipeline. Cleans and analyzes raw input
BEFORE any security detector runs.

Why this matters:
  Many prompt injection attacks rely on encoding tricks to bypass
  keyword-based detectors. An attacker might encode "ignore previous
  instructions" as Base64 or ROT13, insert zero-width characters between
  letters, or substitute lookalike Unicode characters.

  By normalizing first and flagging suspicious encodings, we:
    1. Give all downstream detectors a consistent, clean input.
    2. Generate decoded *variants* that are also checked for attacks.
    3. Surface the encoding technique itself as a security signal.

Security notes:
  - We do NOT blindly decode ALL content. Arbitrary decoding can be
    exploited (e.g., decoding base64 that happens to look like an image).
  - Decoded content is returned as separate *variants* for analysis,
    never as a replacement for the sanitized text.
  - Maximum input size is enforced BEFORE normalization to prevent
    ReDoS attacks on regex patterns.
  - All regex patterns are compiled at module load time (not per-call)
    for performance and to fail fast on bad patterns.

Usage:
    normalizer = InputNormalizer()
    result = normalizer.normalize(raw_text)
    print(result.normalized)         # cleaned text
    print(result.flags)              # ["BASE64_ENCODED", "ZERO_WIDTH_CHARS"]
    print(result.decoded_variants)   # ["decoded version 1", ...]
"""

import base64
import re
import time
import unicodedata
from dataclasses import dataclass, field

from app.config import get_settings


# ── Constants ──────────────────────────────────────────────────────────────────

# Unicode zero-width and invisible characters commonly used to hide text
_ZERO_WIDTH_CHARS = frozenset({
    "\u200b",  # ZERO WIDTH SPACE
    "\u200c",  # ZERO WIDTH NON-JOINER
    "\u200d",  # ZERO WIDTH JOINER
    "\u200e",  # LEFT-TO-RIGHT MARK
    "\u200f",  # RIGHT-TO-LEFT MARK
    "\u00ad",  # SOFT HYPHEN
    "\ufeff",  # ZERO WIDTH NO-BREAK SPACE (BOM)
    "\u2060",  # WORD JOINER
    "\u2061",  # FUNCTION APPLICATION
    "\u2062",  # INVISIBLE TIMES
    "\u2063",  # INVISIBLE SEPARATOR
    "\u2064",  # INVISIBLE PLUS
})

# Common homoglyphs: Unicode lookalikes mapped to their ASCII equivalent
# This covers the most common substitution attacks. NOT exhaustive.
_HOMOGLYPH_MAP: dict[str, str] = {
    # Cyrillic lookalikes
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "у": "y", "х": "x", "ё": "e", "і": "i",
    # Greek lookalikes
    "α": "a", "β": "b", "ε": "e", "ι": "i", "ο": "o",
    "ρ": "p", "τ": "t", "υ": "u", "χ": "x",
    # Common full-width characters (used in East Asian text attacks)
    "ａ": "a", "ｂ": "b", "ｃ": "c", "ｄ": "d", "ｅ": "e",
    "ｆ": "f", "ｇ": "g", "ｈ": "h", "ｉ": "i", "ｊ": "j",
    "ｋ": "k", "ｌ": "l", "ｍ": "m", "ｎ": "n", "ｏ": "o",
    "ｐ": "p", "ｑ": "q", "ｒ": "r", "ｓ": "s", "ｔ": "t",
    "ｕ": "u", "ｖ": "v", "ｗ": "w", "ｘ": "x", "ｙ": "y",
    "ｚ": "z",
}

# Regex: detect a base64-ish segment (must be padded and at least 20 chars)
# We require padding (=) to reduce false positives on normal text.
# Compiled at module load — never inside the hot path.
_BASE64_PATTERN = re.compile(
    r"(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?",
    re.ASCII,
)

# Regex: detect hex-encoded strings (0x... or long hex runs)
_HEX_PATTERN = re.compile(
    r"(?:0x)?(?:[0-9a-fA-F]{2}){8,}",
    re.ASCII,
)

# ROT13 test: after decoding, the result should look like English
# (simple check: ratio of common English words)
_COMMON_ENGLISH_WORDS = frozenset({
    "the", "be", "to", "of", "and", "a", "in", "that", "have",
    "it", "for", "not", "on", "with", "he", "as", "you", "do",
    "at", "this", "but", "his", "by", "from", "they", "we",
    "say", "her", "she", "or", "an", "will", "my", "one", "all",
    "would", "there", "their", "what", "so", "up", "out", "if",
    "about", "who", "get", "which", "go", "me", "ignore", "previous",
    "instructions", "system", "prompt", "reveal", "bypass", "forget",
    "disable", "override", "pretend", "act", "as", "jailbreak", "dan",
})

# Maximum base64 segment length to decode (prevents memory exhaustion)
_MAX_BASE64_DECODE_LEN = 2000


# ── Result Dataclass ───────────────────────────────────────────────────────────

@dataclass
class NormalizationResult:
    """
    Output of the Input Normalizer.

    Attributes:
        original:          The unmodified input string.
        normalized:        The cleaned text after Unicode/whitespace normalization.
        homoglyph_normalized: Normalized text with homoglyphs replaced (for detectors).
        leet_normalized:   Text with leetspeak substitutions applied (for detectors).
        flags:             List of security flags raised (e.g., BASE64_ENCODED).
        suspicious:        True if any suspicious encoding was detected.
        decoded_variants:  Decoded versions of the text (Base64, ROT13, etc.)
                           that should ALSO be checked by detectors.
        char_count:        Original character count.
        latency_ms:        Time taken by the normalizer in milliseconds.
    """
    original: str = ""
    normalized: str = ""
    homoglyph_normalized: str = ""
    leet_normalized: str = ""
    flags: list[str] = field(default_factory=list)
    suspicious: bool = False
    decoded_variants: list[str] = field(default_factory=list)
    char_count: int = 0
    latency_ms: float = 0.0


# ── Normalizer ────────────────────────────────────────────────────────────────

class InputNormalizer:
    """
    Multi-stage input normalizer for SENTINEL-X.

    This class is designed to be instantiated once and reused
    (stateless — safe to use from multiple async contexts).

    Stages (applied in order):
        1. Size validation
        2. Unicode normalization (NFKC)
        3. Zero-width character detection and removal
        4. Whitespace normalization
        5. Homoglyph detection and normalization
        6. Leetspeak detection and normalization
        7. Base64 segment detection and safe decoding
        8. ROT13 detection
        9. Hex encoding detection
    """

    def __init__(self) -> None:
        self._settings = get_settings()

    def normalize(self, raw_text: str) -> NormalizationResult:
        """
        Run all normalization stages on raw_text.

        Args:
            raw_text: The raw user input string.

        Returns:
            NormalizationResult with normalized text, flags, and decoded variants.

        Raises:
            ValueError: If input exceeds the configured maximum size.
        """
        start = time.perf_counter()

        # Stage 0: Size guard (also enforced by Pydantic schema, belt-and-suspenders)
        if len(raw_text) > self._settings.max_input_chars:
            raise ValueError(
                f"Input too large: {len(raw_text)} chars "
                f"(max {self._settings.max_input_chars})"
            )

        result = NormalizationResult(
            original=raw_text,
            char_count=len(raw_text),
        )

        text = raw_text

        # Stage 1: Unicode normalization (NFKC)
        # NFKC decomposes compatibility characters and recomposes canonical ones.
        # e.g., "ﬁ" (ligature) → "fi", "²" → "2"
        text = unicodedata.normalize("NFKC", text)

        # Stage 2: Zero-width character detection and removal
        zero_width_found = [c for c in text if c in _ZERO_WIDTH_CHARS]
        if zero_width_found:
            result.flags.append("ZERO_WIDTH_CHARS")
            text = "".join(c for c in text if c not in _ZERO_WIDTH_CHARS)

        # Stage 3: Whitespace normalization
        # Collapse runs of whitespace to single space, strip edges
        text = re.sub(r"[ \t]+", " ", text)     # Horizontal whitespace
        text = re.sub(r"\n{3,}", "\n\n", text)  # Max 2 consecutive newlines
        text = text.strip()

        result.normalized = text

        # Stage 4: Homoglyph normalization
        homoglyph_text = self._apply_homoglyphs(text)
        if homoglyph_text != text:
            result.flags.append("HOMOGLYPHS_DETECTED")
        result.homoglyph_normalized = homoglyph_text

        # Stage 5: Leetspeak normalization (applied to homoglyph-normalized text)
        leet_text = self._apply_leet(homoglyph_text)
        if leet_text != homoglyph_text:
            result.flags.append("LEETSPEAK_DETECTED")
        result.leet_normalized = leet_text

        # Stage 6: Base64 detection and safe decoding
        self._check_base64(text, result)

        # Stage 7: ROT13 detection
        self._check_rot13(text, result)

        # Stage 8: Hex encoding detection
        self._check_hex(text, result)

        # Summarize suspicious status
        result.suspicious = len(result.flags) > 0

        result.latency_ms = (time.perf_counter() - start) * 1000
        return result

    # ── Private helpers ───────────────────────────────────────────────────────

    def _apply_homoglyphs(self, text: str) -> str:
        """Replace known Unicode homoglyphs with their ASCII equivalents."""
        return "".join(_HOMOGLYPH_MAP.get(c, c) for c in text)

    def _apply_leet(self, text: str) -> str:
        """
        Apply conservative leetspeak substitution.

        Only applies when the surrounding characters suggest leetspeak intent
        (mixed alphanumeric with digits in word positions).
        We use a simple heuristic: replace digit substitutions only when they
        appear surrounded by letters (word-interior position).
        """
        leet_subs = {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t"}
        result = []
        chars = list(text)
        for i, ch in enumerate(chars):
            if ch in leet_subs:
                prev_alpha = i > 0 and chars[i - 1].isalpha()
                next_alpha = i < len(chars) - 1 and chars[i + 1].isalpha()
                if prev_alpha or next_alpha:
                    result.append(leet_subs[ch])
                    continue
            result.append(ch)
        return "".join(result)

    def _check_base64(self, text: str, result: NormalizationResult) -> None:
        """
        Find base64-like segments and attempt safe decoding.

        Only decodes segments that:
        - Match the base64 character set with padding
        - Are at least 20 characters long (reduces false positives)
        - Are not longer than _MAX_BASE64_DECODE_LEN (prevents memory abuse)
        - Decode to valid UTF-8 text (not binary data)
        """
        for match in _BASE64_PATTERN.finditer(text):
            segment = match.group()
            if len(segment) < 20 or len(segment) > _MAX_BASE64_DECODE_LEN:
                continue
            # Pad if needed
            padded = segment + "=" * ((-len(segment)) % 4)
            try:
                decoded_bytes = base64.b64decode(padded, validate=True)
                decoded_str = decoded_bytes.decode("utf-8", errors="strict")
                # Only accept printable-ish text (not binary)
                if decoded_str.isprintable() or "\n" in decoded_str:
                    result.flags.append("BASE64_ENCODED")
                    result.decoded_variants.append(decoded_str.strip())
            except Exception:
                # Not valid base64 or not UTF-8 — ignore
                pass

    def _check_rot13(self, text: str, result: NormalizationResult) -> None:
        """
        Check if the input might be ROT13 encoded.

        Heuristic: If ROT13-decoding the text yields a result containing
        more common English words than the original, it is likely ROT13.
        This is intentionally conservative — we require a clear signal.
        """
        import codecs
        decoded = codecs.decode(text, "rot_13")
        original_score = self._english_word_score(text)
        decoded_score = self._english_word_score(decoded)

        # If decoding yields significantly more common words, flag it
        if decoded_score > original_score + 3 and decoded_score >= 3:
            result.flags.append("ROT13_ENCODED")
            result.decoded_variants.append(decoded)

    def _check_hex(self, text: str, result: NormalizationResult) -> None:
        """Detect long hex-encoded strings that might encode attack payloads."""
        for match in _HEX_PATTERN.finditer(text):
            segment = match.group().replace("0x", "")
            if len(segment) >= 16:  # at least 8 bytes
                try:
                    decoded_bytes = bytes.fromhex(segment)
                    decoded_str = decoded_bytes.decode("utf-8", errors="strict")
                    if decoded_str.isprintable():
                        result.flags.append("HEX_ENCODED")
                        result.decoded_variants.append(decoded_str.strip())
                        break  # One flag is enough
                except Exception:
                    pass

    @staticmethod
    def _english_word_score(text: str) -> int:
        """Count how many common English words appear in the text (case-insensitive)."""
        words = re.findall(r"\b[a-zA-Z]{2,}\b", text.lower())
        return sum(1 for w in words if w in _COMMON_ENGLISH_WORDS)


# ── Module-level singleton ────────────────────────────────────────────────────

_normalizer_instance: InputNormalizer | None = None


def get_normalizer() -> InputNormalizer:
    """Return the shared InputNormalizer singleton."""
    global _normalizer_instance
    if _normalizer_instance is None:
        _normalizer_instance = InputNormalizer()
    return _normalizer_instance
