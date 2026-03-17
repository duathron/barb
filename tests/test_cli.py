"""Tests for CLI interface."""

from __future__ import annotations

from typer.testing import CliRunner

from barb.main import app

runner = CliRunner()


def test_version_command():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "1.0.0" in result.output


def test_no_args_shows_help():
    result = runner.invoke(app, [])
    # Typer returns exit code 0 or 2 for no-args-is-help depending on version
    assert result.exit_code in (0, 2)
    assert "Usage" in result.output or "barb" in result.output
