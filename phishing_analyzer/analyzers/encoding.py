"""Encoding analyzer — detects percent-encoding abuse and punycode in URLs."""

from __future__ import annotations

import re

from phishing_analyzer.models import ParsedURL, Signal, SignalSeverity

_PERCENT_PATTERN = re.compile(r"%[0-9A-Fa-f]{2}")


class EncodingAnalyzer:
    """Detect suspicious percent-encoding and punycode usage."""

    @property
    def name(self) -> str:
        return "encoding"

    def analyze(self, parsed_url: ParsedURL) -> list[Signal]:
        signals: list[Signal] = []

        # Punycode detection
        if parsed_url.is_punycode:
            signals.append(Signal(
                analyzer=self.name,
                severity=SignalSeverity.HIGH,
                label="Punycode domain (IDN)",
                detail=f"Domain uses punycode encoding: {parsed_url.host}",
            ))

        # Excessive percent-encoding in URL
        encoded_chars = _PERCENT_PATTERN.findall(parsed_url.original)
        if len(encoded_chars) > 5:
            signals.append(Signal(
                analyzer=self.name,
                severity=SignalSeverity.MEDIUM,
                label="Excessive percent-encoding",
                detail=f"URL contains {len(encoded_chars)} percent-encoded characters",
            ))
        elif len(encoded_chars) > 2:
            # Check if encoding hides recognizable ASCII characters
            ascii_encoded = [c for c in encoded_chars if 0x20 <= int(c[1:], 16) <= 0x7E]
            if ascii_encoded:
                signals.append(Signal(
                    analyzer=self.name,
                    severity=SignalSeverity.MEDIUM,
                    label="Encoded ASCII characters",
                    detail=f"URL percent-encodes {len(ascii_encoded)} printable ASCII characters",
                ))

        return signals
