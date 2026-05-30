"""Homoglyph analyzer — detects Unicode confusable characters in domains.

Two checks:
- Per-character confusables: a Unicode character that mimics an ASCII letter
  (e.g. Cyrillic 'а' U+0430 vs Latin 'a'), via the bundled homoglyphs map.
- Mixed-script labels: a single domain label that mixes alphabets (e.g. Latin +
  Cyrillic in "аpple"). Legitimate IDNs stay within one script per label, so a
  mix is a strong spoofing signal even when no individual character is in the map.
"""

from __future__ import annotations

import unicodedata

from barb.analyzers.base import load_data
from barb.models import ParsedURL, Signal, SignalSeverity

_homoglyphs: dict[str, str] | None = None


def _get_homoglyphs() -> dict[str, str]:
    global _homoglyphs
    if _homoglyphs is None:
        _homoglyphs = load_data("homoglyphs.json")
    return _homoglyphs


def _script_of(char: str) -> str | None:
    """Return the Unicode script family of an alphabetic character (e.g. LATIN,
    CYRILLIC, GREEK), or None for non-alphabetic characters / unnamed code points."""
    if not char.isalpha():
        return None
    try:
        return unicodedata.name(char).split()[0]
    except ValueError:
        return None


class HomoglyphAnalyzer:
    """Detect Unicode confusable characters and mixed-script labels."""

    @property
    def name(self) -> str:
        return "homoglyph"

    def analyze(self, parsed_url: ParsedURL) -> list[Signal]:
        signals: list[Signal] = []
        homoglyphs = _get_homoglyphs()

        for char in parsed_url.host:
            if char in homoglyphs:
                signals.append(Signal(
                    analyzer=self.name,
                    severity=SignalSeverity.CRITICAL,
                    label="Homoglyph character detected",
                    detail=f"Character '{char}' (U+{ord(char):04X}) resembles '{homoglyphs[char]}'",
                ))

        # Mixed-script labels: more than one alphabet inside a single label.
        for label in parsed_url.host.split("."):
            scripts = {s for s in (_script_of(c) for c in label) if s is not None}
            if len(scripts) > 1:
                signals.append(Signal(
                    analyzer=self.name,
                    severity=SignalSeverity.HIGH,
                    label="Mixed-script domain label",
                    detail=f"Label '{label}' mixes scripts: {', '.join(sorted(scripts))}",
                ))

        return signals
