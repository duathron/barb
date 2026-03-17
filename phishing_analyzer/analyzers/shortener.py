"""URL shortener analyzer — flags known URL shortener services."""

from __future__ import annotations

from phishing_analyzer.analyzers.base import load_data
from phishing_analyzer.models import ParsedURL, Signal, SignalSeverity

_shorteners: list[str] | None = None


def _get_shorteners() -> list[str]:
    global _shorteners
    if _shorteners is None:
        _shorteners = load_data("shorteners.json")
    return _shorteners


class ShortenerAnalyzer:
    """Detect URLs using known URL shortening services."""

    @property
    def name(self) -> str:
        return "shortener"

    def analyze(self, parsed_url: ParsedURL) -> list[Signal]:
        signals: list[Signal] = []
        shorteners = _get_shorteners()

        host_lower = parsed_url.host.lower()
        if host_lower in shorteners:
            signals.append(Signal(
                analyzer=self.name,
                severity=SignalSeverity.MEDIUM,
                label="URL shortener detected",
                detail=f"Domain '{parsed_url.host}' is a known URL shortener",
            ))

        return signals
