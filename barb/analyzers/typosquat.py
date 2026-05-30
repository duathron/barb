"""Typosquat analyzer — detects domains that visually resemble known brand names."""

from __future__ import annotations

from barb.analyzers.base import load_data
from barb.models import ParsedURL, Signal, SignalSeverity

_brands: dict[str, list[str]] | None = None

# Digit-to-letter substitution map for normalization
_DIGIT_MAP: dict[str, str] = {
    "0": "o",
    "1": "l",
    "3": "e",
    "5": "s",
    "4": "a",
}

# Multi-char substitution (applied before digit map)
_MULTI_MAP: list[tuple[str, str]] = [
    ("rn", "m"),
]


def _get_brands() -> dict[str, list[str]]:
    global _brands
    if _brands is None:
        _brands = load_data("brands.json")
    return _brands


def _levenshtein(a: str, b: str) -> int:
    """Compute Levenshtein distance between two strings."""
    if a == b:
        return 0
    la, lb = len(a), len(b)
    if la == 0:
        return lb
    if lb == 0:
        return la
    # Single-row DP
    prev = list(range(lb + 1))
    for i, ca in enumerate(a):
        curr = [i + 1] + [0] * lb
        for j, cb in enumerate(b):
            ins = curr[j] + 1
            de = prev[j + 1] + 1
            sub = prev[j] + (0 if ca == cb else 1)
            curr[j + 1] = min(ins, de, sub)
        prev = curr
    return prev[lb]


def _normalize(label: str) -> str:
    """Apply digit-to-letter and multi-char substitutions."""
    result = label
    for src, dst in _MULTI_MAP:
        result = result.replace(src, dst)
    result = "".join(_DIGIT_MAP.get(ch, ch) for ch in result)
    return result


def _registrable_label(host: str) -> str:
    """Return the main label of the registrable domain (second-to-last part)."""
    parts = host.lower().split(".")
    # Need at least <label>.<tld>
    if len(parts) < 2:
        return host.lower()
    return parts[-2]


class TyposquatAnalyzer:
    """Detect typosquatted domains that resemble known brands."""

    @property
    def name(self) -> str:
        return "typosquat"

    def analyze(self, parsed_url: ParsedURL) -> list[Signal]:
        if parsed_url.is_ip:
            return []

        host_lower = parsed_url.host.lower()
        label = _registrable_label(host_lower)
        brands = _get_brands()
        signals: list[Signal] = []

        for brand_name, official_domains in brands.items():
            # Skip if host is already an official domain for this brand
            if any(host_lower == d or host_lower.endswith(f".{d}") for d in official_domains):
                continue

            # Length pre-filter: only compare if label length within +-2 of brand name
            if abs(len(label) - len(brand_name)) > 2:
                continue

            # (a) Levenshtein distance 1..2
            dist = _levenshtein(label, brand_name)
            if 1 <= dist <= 2:
                signals.append(Signal(
                    analyzer=self.name,
                    severity=SignalSeverity.HIGH,
                    label="Possible typosquatting",
                    detail=f"'{label}' resembles brand '{brand_name}' (distance {dist})",
                ))
                continue

            # (b) Equal after digit<->letter normalization AND not identical to the brand
            normalized = _normalize(label)
            if normalized == brand_name and label != brand_name:
                signals.append(Signal(
                    analyzer=self.name,
                    severity=SignalSeverity.HIGH,
                    label="Possible typosquatting",
                    detail=f"'{label}' resembles brand '{brand_name}' (distance 1)",
                ))

        return signals
