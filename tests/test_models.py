"""Tests for Pydantic models."""

from __future__ import annotations

from barb.models import RiskVerdict, SignalSeverity


def test_signal_severity_points():
    assert SignalSeverity.INFO.points == 0
    assert SignalSeverity.LOW.points == 1
    assert SignalSeverity.MEDIUM.points == 2
    assert SignalSeverity.HIGH.points == 3
    assert SignalSeverity.CRITICAL.points == 5


def test_verdict_exit_codes():
    assert RiskVerdict.SAFE.exit_code == 0
    assert RiskVerdict.LOW_RISK.exit_code == 0
    assert RiskVerdict.SUSPICIOUS.exit_code == 1
    assert RiskVerdict.HIGH_RISK.exit_code == 1
    assert RiskVerdict.PHISHING.exit_code == 2
