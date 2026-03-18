"""Brand impersonation analyzer — detects brand names in non-brand domains."""

from __future__ import annotations

from barb.analyzers.base import load_data
from barb.models import ParsedURL, Signal, SignalSeverity

_brands: dict[str, list[str]] | None = None


def _get_brands() -> dict[str, list[str]]:
    global _brands
    if _brands is None:
        _brands = load_data("brands.json")
    return _brands


class BrandAnalyzer:
    """Detect brand name usage in non-official domains."""

    @property
    def name(self) -> str:
        return "brand"

    def analyze(self, parsed_url: ParsedURL) -> list[Signal]:
        signals: list[Signal] = []
        brands = _get_brands()

        host_lower = parsed_url.host.lower()

        for brand_name, official_domains in brands.items():
            if brand_name in host_lower:
                # Check if this is actually an official domain
                if not any(host_lower == d or host_lower.endswith(f".{d}") for d in official_domains):
                    signals.append(Signal(
                        analyzer=self.name,
                        severity=SignalSeverity.HIGH,
                        label="Brand impersonation",
                        detail=(
                            f"Domain contains '{brand_name}' but is not an official domain"
                            f" ({', '.join(official_domains)})"
                        ),
                    ))

        return signals
