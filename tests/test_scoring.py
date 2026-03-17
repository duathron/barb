"""Tests for scoring and verdict system."""

from __future__ import annotations

from barb.config import AppConfig
from barb.models import RiskVerdict, Signal, SignalSeverity
from barb.scoring import compute_risk_score, determine_verdict


def test_safe_verdict_no_signals():
    config = AppConfig()
    score = compute_risk_score([], config)
    assert score == 0.0
    assert determine_verdict(score, config) == RiskVerdict.SAFE


def test_phishing_verdict_critical_signals():
    config = AppConfig()
    signals = [
        Signal(analyzer="homoglyph", severity=SignalSeverity.CRITICAL, label="test", detail="test"),
        Signal(analyzer="brand", severity=SignalSeverity.HIGH, label="test", detail="test"),
        Signal(analyzer="tld", severity=SignalSeverity.MEDIUM, label="test", detail="test"),
    ]
    score = compute_risk_score(signals, config)
    assert score > 0
    verdict = determine_verdict(score, config)
    assert verdict in (RiskVerdict.HIGH_RISK, RiskVerdict.PHISHING)


def test_configurable_weights():
    config = AppConfig()
    config.scoring.weights.homoglyph = 3.0
    signals = [
        Signal(analyzer="homoglyph", severity=SignalSeverity.CRITICAL, label="test", detail="test"),
    ]
    score = compute_risk_score(signals, config)
    assert score == 5 * 3.0  # CRITICAL=5 * weight=3.0
