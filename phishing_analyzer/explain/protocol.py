"""Explainer protocol — structural typing interface for explanation providers."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from phishing_analyzer.models import AnalysisResult


@runtime_checkable
class ExplainerProtocol(Protocol):
    """Interface that all explanation providers must implement."""

    def explain(self, result: AnalysisResult) -> str:
        """Generate a human-readable explanation of the analysis result."""
        ...
