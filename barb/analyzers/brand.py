"""Brand impersonation analyzer — detects brand names in non-brand domains."""

from __future__ import annotations

import re

from barb.analyzers.base import load_data
from barb.models import ParsedURL, Signal, SignalSeverity

_brands: dict[str, list[str]] | None = None

# Threshold below which we require a whole-token match (split on "." and "-")
# rather than a mere substring match.  Short brand strings like "ing" (3 chars)
# appear as substrings in huge numbers of benign domain labels
# (bing, booking, springer, …) causing high FP rates.
_SHORT_BRAND_WHOLE_TOKEN_THRESHOLD = 5


def _get_brands() -> dict[str, list[str]]:
    global _brands
    if _brands is None:
        _brands = load_data("brands.json")
    return _brands


def _registrable_domain(host: str) -> str:
    """Return the registrable domain (last two labels) for a host."""
    parts = host.lower().split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host.lower()


def _brand_in_host(brand_name: str, host_lower: str) -> bool:
    """Return True if brand_name appears in host_lower.

    For short brands (< _SHORT_BRAND_WHOLE_TOKEN_THRESHOLD chars) we require a
    whole-token match (the brand must appear as an independent segment when the
    host is split on dots and hyphens).  This prevents 'ing' from matching
    'booking', 'springer', 'duolingo', etc.

    Longer brands use the original substring check.
    """
    if brand_name not in host_lower:
        return False
    if len(brand_name) >= _SHORT_BRAND_WHOLE_TOKEN_THRESHOLD:
        return True
    # Whole-token check: split on dots and hyphens and look for an exact token
    tokens = re.split(r"[.\-]", host_lower)
    return brand_name in tokens


class BrandAnalyzer:
    """Detect brand name usage in non-official domains."""

    @property
    def name(self) -> str:
        return "brand"

    def analyze(self, parsed_url: ParsedURL) -> list[Signal]:
        signals: list[Signal] = []
        brands = _get_brands()

        host_lower = parsed_url.host.lower()
        registrable = _registrable_domain(host_lower)

        for brand_name, official_domains in brands.items():
            if not _brand_in_host(brand_name, host_lower):
                continue
            # Skip if this is already an official domain (exact or subdomain match)
            if any(host_lower == d or host_lower.endswith(f".{d}") for d in official_domains):
                continue
            # Skip if the host's own registrable domain matches an official domain
            # for this brand — e.g. dns.google → registrable=google.com matches
            # google's official domain list, so it IS Google's own infrastructure.
            if any(registrable == d or registrable.endswith(f".{d}") for d in official_domains):
                continue
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
