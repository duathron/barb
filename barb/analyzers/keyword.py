"""Keyword analyzer — detects phishing keywords in URL path and query."""

from __future__ import annotations

from barb.models import ParsedURL, Signal, SignalSeverity

_KEYWORDS = [
    "login",
    "signin",
    "verify",
    "secure",
    "account",
    "update",
    "confirm",
    "webscr",
    "bank",
    "password",
    "credential",
    "suspend",
    "unlock",
    "billing",
]


class KeywordAnalyzer:
    """Detect phishing-related keywords in URL path and query string."""

    @property
    def name(self) -> str:
        return "keyword"

    def analyze(self, parsed_url: ParsedURL) -> list[Signal]:
        text = ((parsed_url.path or "") + " " + (parsed_url.query or "")).lower()
        matched = [kw for kw in _KEYWORDS if kw in text]
        if not matched:
            return []
        return [
            Signal(
                analyzer=self.name,
                severity=SignalSeverity.LOW,
                label="Phishing keywords in URL path",
                detail=f"Matched keywords: {', '.join(matched)}",
            )
        ]
