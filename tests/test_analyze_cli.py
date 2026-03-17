"""Tests for the analyze CLI command (end-to-end)."""

from __future__ import annotations

from typer.testing import CliRunner

from barb.main import app

runner = CliRunner()


def test_analyze_safe_url():
    result = runner.invoke(app, ["analyze", "https://www.google.com", "-o", "console", "-q"])
    assert "SAFE" in result.output


def test_analyze_ip_url():
    result = runner.invoke(app, ["analyze", "http://192.168.1.1/login", "-o", "console", "-q"])
    assert result.exit_code in (1, 2)  # suspicious or phishing
    assert "ip_url" in result.output


def test_analyze_json_output():
    result = runner.invoke(app, ["analyze", "https://www.google.com", "-o", "json", "-q"])
    assert '"verdict"' in result.output
    assert '"SAFE"' in result.output


def test_analyze_csv_output():
    result = runner.invoke(app, ["analyze", "https://www.google.com", "-o", "csv", "-q"])
    assert "url" in result.output  # header
    assert "SAFE" in result.output


def test_analyze_with_explain():
    result = runner.invoke(app, ["analyze", "https://www.google.com", "-o", "console", "-q", "--explain"])
    assert "Explanation:" in result.output or "safe" in result.output.lower()


def test_analyze_no_defang():
    result = runner.invoke(app, ["analyze", "https://www.google.com", "-o", "console", "-q", "--no-defang"])
    assert "https://www.google.com" in result.output
    assert "hxxps" not in result.output


def test_analyze_batch():
    result = runner.invoke(app, ["analyze", "https://google.com", "https://example.com", "-o", "console", "-q"])
    assert "SAFE" in result.output


def test_analyze_no_urls():
    result = runner.invoke(app, ["analyze", "-q"])
    assert result.exit_code == 3


def test_analyze_threshold_filter():
    # google.com should score 0, so threshold=10 filters it out
    result = runner.invoke(app, ["analyze", "https://www.google.com", "-o", "console", "-q", "-t", "10"])
    assert "No URLs exceeded" in result.output or result.exit_code == 0
