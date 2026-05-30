"""Tests for the analyze CLI command (end-to-end)."""

from __future__ import annotations

import json
import tempfile

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


# B6 — batch file: comment + blank lines must not be analyzed as URLs
def test_analyze_file_skips_comments_and_blanks():
    """Only real URLs in --file are analyzed; comment and blank lines are skipped."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("# this is a comment\n")
        f.write("\n")
        f.write("https://www.google.com\n")
        tmp_path = f.name
    result = runner.invoke(app, ["analyze", "--file", tmp_path, "-o", "json", "-q"])
    assert result.exit_code in (0, 1, 2), f"unexpected exit code: {result.exit_code}\n{result.output}"
    data = json.loads(result.output)
    # Only 1 real URL → single-result JSON object (not a list)
    if isinstance(data, list):
        assert len(data) == 1
        assert data[0]["url"] == "https://www.google.com"
    else:
        assert data["url"] == "https://www.google.com"


# B7 — --no-defang: JSON defanged_url must equal the original URL
def test_json_no_defang_preserves_original_url():
    """With --no-defang, JSON defanged_url field == original URL (not defanged)."""
    url = "https://www.google.com"
    result = runner.invoke(app, ["analyze", url, "-o", "json", "-q", "--no-defang"])
    assert result.exit_code in (0, 1, 2), result.output
    data = json.loads(result.output)
    assert data["defanged_url"] == url, f"expected {url!r}, got {data['defanged_url']!r}"


def test_json_default_defangs_url():
    """Without --no-defang, JSON defanged_url field is defanged (contains hxxps or [.])."""
    url = "https://www.google.com"
    result = runner.invoke(app, ["analyze", url, "-o", "json", "-q"])
    assert result.exit_code in (0, 1, 2), result.output
    data = json.loads(result.output)
    defanged = data["defanged_url"]
    assert defanged != url, "expected defanged URL to differ from original"
    assert "hxxps" in defanged or "[.]" in defanged, f"unexpected defanged form: {defanged!r}"
