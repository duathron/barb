"""Weighted signal aggregation and verdict determination."""

from __future__ import annotations

from barb.config import AppConfig
from barb.models import RiskVerdict, Signal, SignalSeverity

# Ordered verdict list for floor comparisons (lowest → highest).
_VERDICT_ORDER = [
    RiskVerdict.SAFE,
    RiskVerdict.LOW_RISK,
    RiskVerdict.SUSPICIOUS,
    RiskVerdict.HIGH_RISK,
    RiskVerdict.PHISHING,
]


def _max_verdict(a: RiskVerdict, b: RiskVerdict) -> RiskVerdict:
    """Return the higher of two verdicts."""
    return a if _VERDICT_ORDER.index(a) >= _VERDICT_ORDER.index(b) else b


def compute_risk_score(signals: list[Signal], config: AppConfig) -> float:
    """Compute the weighted risk score from a list of signals."""
    weights = config.scoring.weights
    weight_map = {
        "entropy": weights.entropy,
        "homoglyph": weights.homoglyph,
        "tld": weights.tld,
        "subdomain": weights.subdomain,
        "brand": weights.brand,
        "shortener": weights.shortener,
        "encoding": weights.encoding,
        "ip_url": weights.ip_url,
        "typosquat": weights.typosquat,
        "keyword": weights.keyword,
        "lexical": weights.lexical,
        "file_ext": weights.file_ext,
        # OSINT enrichers — low weight; severity carries the signal
        "osint:dns": 1.0,
        "osint:rdap": 1.0,
        "osint:crtsh": 1.0,
    }
    total = 0.0
    for signal in signals:
        analyzer_weight = weight_map.get(signal.analyzer, 1.0)
        total += signal.severity.points * signal.weight * analyzer_weight
    return round(total, 2)


def determine_verdict(score: float, signals: list[Signal], config: AppConfig) -> RiskVerdict:
    """Map a risk score to a verdict tier, with a severity-floor from signals.

    Floor rules (MeetUp 2026-05-30 D1):
    - Any CRITICAL signal  → verdict is at least HIGH_RISK
    - Any HIGH signal      → verdict is at least SUSPICIOUS
    - MEDIUM/LOW/INFO      → no floor applied
    The floor never lowers an already-higher score-based verdict.
    """
    t = config.scoring.thresholds
    if score >= t.phishing:
        score_verdict = RiskVerdict.PHISHING
    elif score >= t.high_risk:
        score_verdict = RiskVerdict.HIGH_RISK
    elif score >= t.suspicious:
        score_verdict = RiskVerdict.SUSPICIOUS
    elif score >= t.low_risk:
        score_verdict = RiskVerdict.LOW_RISK
    else:
        score_verdict = RiskVerdict.SAFE

    # Determine floor from signal severities
    severities = {s.severity for s in signals}
    if SignalSeverity.CRITICAL in severities:
        floor = RiskVerdict.HIGH_RISK
    elif SignalSeverity.HIGH in severities:
        floor = RiskVerdict.SUSPICIOUS
    else:
        floor = RiskVerdict.SAFE  # no effective floor

    return _max_verdict(score_verdict, floor)
