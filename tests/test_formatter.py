"""Tests for Rich and console output formatting."""

from __future__ import annotations

from datetime import datetime

from barb.models import (
    AnalysisResult,
    ParsedURL,
    RiskVerdict,
    Signal,
    SignalSeverity,
)
from barb.output.formatter import format_console


def _make_result(
    verdict: RiskVerdict = RiskVerdict.SAFE,
    score: float = 0.0,
    signals: list[Signal] | None = None,
) -> AnalysisResult:
    return AnalysisResult(
        url="https://example.com",
        defanged_url="hxxps[://]example[.]com",
        parsed_url=ParsedURL(original="https://example.com", scheme="https", host="example.com", path="/"),
        signals=signals or [],
        risk_score=score,
        verdict=verdict,
        analyzed_at=datetime.now(),
    )


def test_format_console_safe(capsys):
    result = _make_result()
    format_console(result, defang=True)
    captured = capsys.readouterr()
    assert "SAFE" in captured.out
    assert "hxxps" in captured.out


def test_format_console_with_signals(capsys):
    signals = [
        Signal(analyzer="ip_url", severity=SignalSeverity.HIGH, label="IP URL", detail="Uses IP address"),
        Signal(analyzer="tld", severity=SignalSeverity.MEDIUM, label="Suspicious TLD", detail=".tk domain"),
    ]
    result = _make_result(verdict=RiskVerdict.SUSPICIOUS, score=5.0, signals=signals)
    format_console(result, defang=True)
    captured = capsys.readouterr()
    assert "SUSPICIOUS" in captured.out
    assert "ip_url" in captured.out
    assert "tld" in captured.out
    assert "5.0" in captured.out


def test_format_console_no_defang(capsys):
    result = _make_result()
    format_console(result, defang=False)
    captured = capsys.readouterr()
    assert "https://example.com" in captured.out
    assert "hxxps" not in captured.out


def test_format_console_with_explanation(capsys):
    result = _make_result()
    result.explanation = "This URL appears safe."
    format_console(result, defang=True)
    captured = capsys.readouterr()
    assert "Explanation:" in captured.out
    assert "This URL appears safe." in captured.out
