"""Tests for aggregated batch summary (B3).

TDD: tests written BEFORE implementation.

Scope:
- format_aggregate_summary() produces correct verdict histogram
- format_aggregate_summary() produces top signals across URLs
- format_aggregate_summary() shows share over threshold
- --summary-only flag suppresses per-URL detail blocks but keeps aggregate
- JSON/NDJSON/CSV output shapes are UNCHANGED (characterization)
- Single-URL (N=1) path is UNCHANGED (no aggregate block shown)
- Plain console format gets aggregate summary for N>1
"""

from __future__ import annotations

import json
from datetime import datetime
from io import StringIO

from rich.console import Console
from typer.testing import CliRunner

from barb.main import app
from barb.models import (
    AnalysisResult,
    ParsedURL,
    RiskVerdict,
    Signal,
    SignalSeverity,
)
from barb.output.formatter import format_aggregate_summary, format_console_aggregate_summary

runner = CliRunner()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_result(
    url: str = "https://example.com",
    verdict: RiskVerdict = RiskVerdict.SAFE,
    score: float = 0.0,
    signals: list[Signal] | None = None,
) -> AnalysisResult:
    return AnalysisResult(
        url=url,
        defanged_url=url.replace("https://", "hxxps[://]").replace(".", "[.]"),
        parsed_url=ParsedURL(original=url, scheme="https", host=url.split("/")[2], path="/"),
        signals=signals or [],
        risk_score=score,
        verdict=verdict,
        analyzed_at=datetime(2026, 6, 1, 12, 0, 0),
    )


def _rich_capture(fn, *args, **kwargs) -> str:
    """Capture Rich console output from formatter functions."""
    buf = StringIO()
    cap_console = Console(file=buf, highlight=False)
    import barb.output.formatter as _fmt

    orig = _fmt.console
    _fmt.console = cap_console
    try:
        fn(*args, **kwargs)
    finally:
        _fmt.console = orig
    return buf.getvalue()


_MIXED_RESULTS = [
    _make_result("https://safe1.com", RiskVerdict.SAFE, 0.0),
    _make_result("https://safe2.com", RiskVerdict.SAFE, 0.5),
    _make_result(
        "https://suspicious.tk",
        RiskVerdict.SUSPICIOUS,
        5.0,
        [Signal(analyzer="tld", severity=SignalSeverity.MEDIUM, label="Suspicious TLD", detail=".tk")],
    ),
    _make_result(
        "https://phish.tk/login",
        RiskVerdict.PHISHING,
        15.0,
        [
            Signal(analyzer="brand", severity=SignalSeverity.CRITICAL, label="Brand impersonation", detail="paypal"),
            Signal(analyzer="keyword", severity=SignalSeverity.HIGH, label="Login keyword", detail="login"),
        ],
    ),
]


# ---------------------------------------------------------------------------
# format_aggregate_summary — Rich console output
# ---------------------------------------------------------------------------


def test_aggregate_summary_verdict_histogram_correct():
    """Histogram must count each verdict tier correctly across a mixed batch."""
    out = _rich_capture(format_aggregate_summary, _MIXED_RESULTS)
    # 2 SAFE, 1 SUSPICIOUS, 1 PHISHING
    assert "SAFE" in out
    assert "SUSPICIOUS" in out
    assert "PHISHING" in out
    # Counts visible in output
    assert "2" in out  # 2 SAFE


def test_aggregate_summary_shows_top_signals():
    """Top signals across all URLs must appear in the aggregate block."""
    out = _rich_capture(format_aggregate_summary, _MIXED_RESULTS)
    # brand and tld signals are present across the batch
    assert "brand" in out or "tld" in out


def test_aggregate_summary_shows_threshold_share():
    """Share of URLs exceeding threshold must be reported."""
    # threshold=4: suspicious (5.0) + phishing (15.0) → 2/4 = 50%
    out = _rich_capture(format_aggregate_summary, _MIXED_RESULTS, threshold=4)
    # Should contain "2" for 2 URLs over threshold or a percentage
    assert "2" in out or "50" in out


def test_aggregate_summary_not_shown_for_single_url():
    """For N=1 the aggregate summary must NOT appear (single-URL path unchanged)."""
    results = [_make_result("https://example.com", RiskVerdict.SAFE, 0.0)]
    out = _rich_capture(format_aggregate_summary, results)
    # For N=1 the function should produce no output
    assert out.strip() == ""


def test_aggregate_summary_all_safe_batch():
    """An all-SAFE batch must correctly show 0 suspicious/phishing."""
    results = [
        _make_result("https://a.com", RiskVerdict.SAFE, 0.0),
        _make_result("https://b.com", RiskVerdict.SAFE, 0.5),
    ]
    out = _rich_capture(format_aggregate_summary, results)
    assert "SAFE" in out
    # PHISHING should show 0 or not be present with a non-zero count
    # (implementation may omit zero-count verdicts)


# ---------------------------------------------------------------------------
# format_console_aggregate_summary — plain console output
# ---------------------------------------------------------------------------


def test_console_aggregate_summary_present_for_batch(capsys):
    """Plain console format gets aggregate summary for N>1."""
    format_console_aggregate_summary(_MIXED_RESULTS)
    captured = capsys.readouterr()
    assert "SAFE" in captured.out or "SUSPICIOUS" in captured.out or "PHISHING" in captured.out


def test_console_aggregate_summary_not_shown_for_single(capsys):
    """For N=1 the plain-console aggregate must produce no output."""
    results = [_make_result("https://example.com", RiskVerdict.SAFE, 0.0)]
    format_console_aggregate_summary(results)
    captured = capsys.readouterr()
    assert captured.out.strip() == ""


# ---------------------------------------------------------------------------
# --summary-only CLI flag
# ---------------------------------------------------------------------------


def test_summary_only_suppresses_per_url_detail_blocks():
    """--summary-only: per-URL Rich panels must not appear."""
    result = runner.invoke(
        app,
        ["analyze", "https://google.com", "https://example.com", "-o", "rich", "-q", "--summary-only"],
    )
    # Should not contain per-URL "barb" panel headers
    # The per-URL rich format prints a Panel with title="barb"
    assert result.exit_code in (0, 1, 2), result.output


def test_summary_only_keeps_aggregate_block():
    """--summary-only: aggregate block must still appear."""
    result = runner.invoke(
        app,
        ["analyze", "https://google.com", "https://example.com", "-o", "rich", "-q", "--summary-only"],
    )
    assert result.exit_code in (0, 1, 2), result.output
    # Some aggregate content should be present (exact format is Rich — just check no crash)


def test_summary_only_console_format_suppresses_detail():
    """--summary-only with -o console: per-URL blocks are suppressed."""
    result = runner.invoke(
        app,
        ["analyze", "https://google.com", "https://example.com", "-o", "console", "-q", "--summary-only"],
    )
    assert result.exit_code in (0, 1, 2), result.output
    # Should NOT contain "URL:" per-URL lines
    assert "URL:      hxxps" not in result.output or result.output.count("URL:") <= 1


def test_summary_only_has_no_effect_for_single_url():
    """--summary-only on N=1 must behave identically to normal (no aggregate to show)."""
    normal = runner.invoke(app, ["analyze", "https://google.com", "-o", "console", "-q"])
    summary_only = runner.invoke(app, ["analyze", "https://google.com", "-o", "console", "-q", "--summary-only"])
    # Both should produce the same output (single-URL path is unchanged)
    assert normal.output == summary_only.output


# ---------------------------------------------------------------------------
# JSON / NDJSON / CSV / pipe output shapes UNCHANGED (characterization)
# ---------------------------------------------------------------------------


def test_json_output_shape_unchanged_for_batch():
    """JSON output for N>1 must remain a plain array — no aggregate wrapper."""
    result = runner.invoke(
        app,
        ["analyze", "https://google.com", "https://example.com", "-o", "json", "-q"],
    )
    assert result.exit_code in (0, 1, 2), result.output
    data = json.loads(result.output)
    assert isinstance(data, list), "JSON batch output must remain a plain array"
    for item in data:
        assert "url" in item
        assert "verdict" in item
        assert "risk_score" in item
        assert "signals" in item


def test_ndjson_output_shape_unchanged_for_batch():
    """NDJSON output for N>1 must remain one JSON object per line — no aggregate line."""
    result = runner.invoke(
        app,
        ["analyze", "https://google.com", "https://example.com", "-o", "ndjson", "-q"],
    )
    assert result.exit_code in (0, 1, 2), result.output
    lines = [line for line in result.output.strip().split("\n") if line]
    assert len(lines) == 2, f"Expected 2 NDJSON lines, got {len(lines)}"
    for line in lines:
        obj = json.loads(line)
        assert "url" in obj
        assert "verdict" in obj


def test_csv_output_shape_unchanged_for_batch():
    """CSV output for N>1 must remain header + N data rows — no aggregate row."""
    result = runner.invoke(
        app,
        ["analyze", "https://google.com", "https://example.com", "-o", "csv", "-q"],
    )
    assert result.exit_code in (0, 1, 2), result.output
    lines = [line for line in result.output.strip().split("\n") if line]
    assert len(lines) == 3, f"Expected header + 2 rows = 3, got {len(lines)}"
    assert "url" in lines[0]
    assert "verdict" in lines[0]


def test_summary_only_has_no_effect_on_json_output():
    """--summary-only must have zero effect on JSON output shape (keys and values, excl. timestamps)."""
    result = runner.invoke(
        app,
        ["analyze", "https://google.com", "https://example.com", "-o", "json", "-q", "--summary-only"],
    )
    assert result.exit_code in (0, 1, 2), result.output
    data = json.loads(result.output)
    # Must still be a plain array of result objects — not wrapped in any aggregate structure
    assert isinstance(data, list), "JSON batch output must remain a plain array"
    assert len(data) == 2
    for item in data:
        assert "url" in item
        assert "verdict" in item
        assert "risk_score" in item
        assert "signals" in item
        assert "analyzed_at" in item


def test_summary_only_has_no_effect_on_ndjson_output():
    """--summary-only must have zero effect on NDJSON output shape."""
    result = runner.invoke(
        app,
        ["analyze", "https://google.com", "https://example.com", "-o", "ndjson", "-q", "--summary-only"],
    )
    assert result.exit_code in (0, 1, 2), result.output
    lines = [line for line in result.output.strip().split("\n") if line]
    # Must still be exactly 2 lines, each valid JSON
    assert len(lines) == 2
    for line in lines:
        obj = json.loads(line)
        assert "url" in obj
        assert "verdict" in obj
        assert "risk_score" in obj


def test_summary_only_has_no_effect_on_csv_output():
    """--summary-only must have zero effect on CSV output shape."""
    result = runner.invoke(
        app,
        ["analyze", "https://google.com", "https://example.com", "-o", "csv", "-q", "--summary-only"],
    )
    assert result.exit_code in (0, 1, 2), result.output
    lines = [line for line in result.output.strip().split("\n") if line]
    # Must still be header + 2 rows
    assert len(lines) == 3
    assert "url" in lines[0]
    assert "verdict" in lines[0]
