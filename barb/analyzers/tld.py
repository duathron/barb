"""TLD analyzer — flags URLs using suspicious top-level domains."""

from __future__ import annotations

from barb.analyzers.base import load_data
from barb.models import ParsedURL, Signal, SignalSeverity

_suspicious_tlds: list[str] | None = None


def _get_suspicious_tlds() -> list[str]:
    global _suspicious_tlds
    if _suspicious_tlds is None:
        _suspicious_tlds = load_data("suspicious_tlds.json")
    return _suspicious_tlds


class TLDAnalyzer:
    """Detect URLs using known-suspicious top-level domains."""

    @property
    def name(self) -> str:
        return "tld"

    def analyze(self, parsed_url: ParsedURL) -> list[Signal]:
        signals: list[Signal] = []
        suspicious_tlds = _get_suspicious_tlds()

        host_parts = parsed_url.host.rsplit(".", 1)
        if len(host_parts) == 2:
            tld = host_parts[1].lower()
            if tld in suspicious_tlds:
                signals.append(Signal(
                    analyzer=self.name,
                    severity=SignalSeverity.MEDIUM,
                    label="Suspicious TLD",
                    detail=f"TLD '.{tld}' is commonly associated with phishing",
                ))

        return signals
