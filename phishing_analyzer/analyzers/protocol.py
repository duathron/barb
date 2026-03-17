"""Analyzer protocol — structural typing interface for all analyzers."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from phishing_analyzer.models import ParsedURL, Signal


@runtime_checkable
class AnalyzerProtocol(Protocol):
    """Interface that all URL analyzers must implement."""

    @property
    def name(self) -> str:
        """Unique analyzer identifier (e.g., 'entropy', 'homoglyph')."""
        ...

    def analyze(self, parsed_url: ParsedURL) -> list[Signal]:
        """Analyze a parsed URL and return detected signals."""
        ...
