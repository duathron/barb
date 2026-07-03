"""Pydantic v2 data models for barb."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel


class SignalSeverity(str, Enum):
    """Severity level for an individual analysis signal."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def points(self) -> int:
        return {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 5}[self.value]


class RiskVerdict(str, Enum):
    """Overall risk verdict for a URL."""

    SAFE = "SAFE"
    LOW_RISK = "LOW_RISK"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH_RISK = "HIGH_RISK"
    PHISHING = "PHISHING"

    @property
    def exit_code(self) -> int:
        if self in (RiskVerdict.SAFE, RiskVerdict.LOW_RISK):
            return 0
        if self in (RiskVerdict.SUSPICIOUS, RiskVerdict.HIGH_RISK):
            return 1
        return 2  # PHISHING


class Signal(BaseModel):
    """A single analysis signal from an analyzer."""

    analyzer: str
    severity: SignalSeverity
    label: str
    detail: str
    weight: float = 1.0


class ParsedURL(BaseModel):
    """Decomposed URL components."""

    original: str
    scheme: str
    userinfo: Optional[str] = None
    host: str
    port: Optional[int] = None
    path: str
    query: Optional[str] = None
    fragment: Optional[str] = None
    is_ip: bool = False
    is_punycode: bool = False


class AnalysisResult(BaseModel):
    """Complete analysis result for a single URL."""

    url: str
    defanged_url: str
    parsed_url: ParsedURL
    signals: list[Signal]
    risk_score: float
    verdict: RiskVerdict
    explanation: Optional[str] = None
    # F2 cut-1 (2026-07-03 MeetUp — 2026-07-03-f2-llm-failure-posture.md):
    # machine-legible degraded marker for a REQUESTED LLM explanation that
    # failed. When an LLM provider (anthropic/openai/ollama) errors, the URL
    # VERDICT above still completes normally (it is barb's primary output),
    # but `explanation` stays None and these two additive siblings are set
    # instead — never a silent TemplateExplainer substitution. Additive fields
    # (no extra="forbid"), so existing JSON consumers are unaffected. A
    # deliberately-chosen `template` provider (no LLM requested) never sets
    # these, even though it produces an explanation.
    explanation_degraded: bool = False
    explanation_provider: Optional[str] = None
    analyzed_at: datetime
