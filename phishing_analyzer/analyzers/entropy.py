"""Shannon entropy analyzer — detects randomized domains and paths."""

from __future__ import annotations

import math
from collections import Counter

from phishing_analyzer.models import ParsedURL, Signal, SignalSeverity


class EntropyAnalyzer:
    """Detect high-entropy (randomized) domain names and URL paths."""

    @property
    def name(self) -> str:
        return "entropy"

    def analyze(self, parsed_url: ParsedURL) -> list[Signal]:
        signals: list[Signal] = []

        host_entropy = self._shannon_entropy(parsed_url.host)
        if host_entropy > 4.0:
            severity = SignalSeverity.HIGH if host_entropy > 4.5 else SignalSeverity.MEDIUM
            signals.append(Signal(
                analyzer=self.name,
                severity=severity,
                label="High entropy domain",
                detail=f"Domain '{parsed_url.host}' has Shannon entropy {host_entropy:.2f}",
            ))

        path = parsed_url.path.strip("/")
        if path and len(path) > 10:
            path_entropy = self._shannon_entropy(path)
            if path_entropy > 4.5:
                signals.append(Signal(
                    analyzer=self.name,
                    severity=SignalSeverity.LOW,
                    label="High entropy path",
                    detail=f"Path has Shannon entropy {path_entropy:.2f}",
                ))

        return signals

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        if not s:
            return 0.0
        counts = Counter(s)
        length = len(s)
        return -sum((c / length) * math.log2(c / length) for c in counts.values())
