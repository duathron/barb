"""Tests for Rich and console output formatting."""

from __future__ import annotations

from datetime import datetime
from io import StringIO

from rich.console import Console

from barb.models import (
    AnalysisResult,
    ParsedURL,
    RiskVerdict,
    Signal,
    SignalSeverity,
)
from barb.output.formatter import format_console, format_rich


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


# Fix 7: format_rich hides INFO signals for SAFE verdict


def _rich_output(result: AnalysisResult, defang: bool = True) -> str:
    """Capture format_rich output to a string (bypasses the module-level console)."""
    buf = StringIO()
    cap_console = Console(file=buf, highlight=False)
    import barb.output.formatter as _fmt
    orig = _fmt.console
    _fmt.console = cap_console
    try:
        format_rich(result, defang=defang)
    finally:
        _fmt.console = orig
    return buf.getvalue()


def test_format_rich_safe_hides_info_signals():
    """SAFE verdict: INFO signals must not appear in the rich table."""
    signals = [
        Signal(analyzer="file_ext", severity=SignalSeverity.INFO, label="File ext", detail=".gz extension"),
    ]
    result = _make_result(verdict=RiskVerdict.SAFE, score=0.0, signals=signals)
    out = _rich_output(result)
    assert "file_ext" not in out
    assert ".gz extension" not in out


def test_format_rich_safe_all_info_shows_placeholder():
    """SAFE verdict with only INFO signals → 'No significant signals' placeholder."""
    signals = [
        Signal(analyzer="file_ext", severity=SignalSeverity.INFO, label="File ext", detail=".gz extension"),
    ]
    result = _make_result(verdict=RiskVerdict.SAFE, score=0.0, signals=signals)
    out = _rich_output(result)
    assert "No significant signals" in out


def test_format_rich_safe_non_info_still_shown():
    """SAFE verdict: signals above INFO severity must still appear."""
    signals = [
        Signal(analyzer="tld", severity=SignalSeverity.LOW, label="Free TLD", detail="Free TLD used"),
        Signal(analyzer="file_ext", severity=SignalSeverity.INFO, label="File ext", detail=".gz extension"),
    ]
    result = _make_result(verdict=RiskVerdict.SAFE, score=1.0, signals=signals)
    out = _rich_output(result)
    assert "tld" in out
    assert ".gz extension" not in out


def test_format_rich_suspicious_shows_all_signals():
    """Non-SAFE verdict: all signals (including INFO) are shown."""
    signals = [
        Signal(analyzer="ip_url", severity=SignalSeverity.HIGH, label="IP URL", detail="Uses IP address"),
        Signal(analyzer="file_ext", severity=SignalSeverity.INFO, label="File ext", detail=".gz extension"),
    ]
    result = _make_result(verdict=RiskVerdict.SUSPICIOUS, score=6.0, signals=signals)
    out = _rich_output(result)
    assert "ip_url" in out
    assert ".gz extension" in out
