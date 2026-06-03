"""Lexical analyzer — URL structure heuristics (length, hyphens, digit ratio)."""

from __future__ import annotations

from barb.models import ParsedURL, Signal, SignalSeverity

_URL_LENGTH_THRESHOLD = 100
_HYPHEN_THRESHOLD = 3
_DIGIT_RATIO_THRESHOLD = 0.3


class LexicalAnalyzer:
    """Detect suspicious lexical patterns in the URL structure."""

    @property
    def name(self) -> str:
        return "lexical"

    def analyze(self, parsed_url: ParsedURL) -> list[Signal]:
        signals: list[Signal] = []

        # 1. Long URL
        if len(parsed_url.original) > _URL_LENGTH_THRESHOLD:
            signals.append(
                Signal(
                    analyzer=self.name,
                    severity=SignalSeverity.LOW,
                    label="Long URL",
                    detail=f"URL length is {len(parsed_url.original)} characters (threshold: {_URL_LENGTH_THRESHOLD})",
                )
            )

        host = parsed_url.host

        # 2. Many hyphens in domain
        hyphen_count = host.count("-")
        if hyphen_count > _HYPHEN_THRESHOLD:
            signals.append(
                Signal(
                    analyzer=self.name,
                    severity=SignalSeverity.LOW,
                    label="Many hyphens in domain",
                    detail=f"Domain contains {hyphen_count} hyphens (threshold: >{_HYPHEN_THRESHOLD})",
                )
            )

        # 3. High digit ratio in host
        if host:
            digit_count = sum(1 for ch in host if ch.isdigit())
            digit_ratio = digit_count / len(host)
            if digit_ratio > _DIGIT_RATIO_THRESHOLD:
                signals.append(
                    Signal(
                        analyzer=self.name,
                        severity=SignalSeverity.LOW,
                        label="High digit ratio in domain",
                        detail=f"Digit ratio in host is {digit_ratio:.2f} (threshold: >{_DIGIT_RATIO_THRESHOLD})",
                    )
                )

        return signals
