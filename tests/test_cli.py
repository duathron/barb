"""Tests for CLI interface."""

from __future__ import annotations

from typer.testing import CliRunner

from phishing_analyzer.main import app

runner = CliRunner()


def test_version_command():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "1.0.0" in result.output


def test_no_args_shows_help():
    result = runner.invoke(app, [])
    assert result.exit_code == 0
    assert "Usage" in result.output or "phishing-analyzer" in result.output
