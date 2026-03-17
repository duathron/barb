"""Homoglyph analyzer — detects Unicode confusable characters in domains."""

from __future__ import annotations

from phishing_analyzer.analyzers.base import load_data
from phishing_analyzer.models import ParsedURL, Signal, SignalSeverity

_homoglyphs: dict[str, str] | None = None


def _get_homoglyphs() -> dict[str, str]:
    global _homoglyphs
    if _homoglyphs is None:
        _homoglyphs = load_data("homoglyphs.json")
    return _homoglyphs


class HomoglyphAnalyzer:
    """Detect Unicode confusable characters that mimic ASCII letters."""

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

        return signals
