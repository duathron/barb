"""Weighted signal aggregation and verdict determination."""

from __future__ import annotations

from barb.config import AppConfig
from barb.models import AnalysisResult, RiskVerdict, Signal


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
    }
    total = 0.0
    for signal in signals:
        analyzer_weight = weight_map.get(signal.analyzer, 1.0)
        total += signal.severity.points * signal.weight * analyzer_weight
    return total


def determine_verdict(score: float, config: AppConfig) -> RiskVerdict:
    """Map a risk score to a verdict tier."""
    t = config.scoring.thresholds
    if score >= t.phishing:
        return RiskVerdict.PHISHING
    if score >= t.high_risk:
        return RiskVerdict.HIGH_RISK
    if score >= t.suspicious:
        return RiskVerdict.SUSPICIOUS
    if score >= t.low_risk:
        return RiskVerdict.LOW_RISK
    return RiskVerdict.SAFE
