"""Tests for CLI interface."""

from __future__ import annotations

import re

from typer.testing import CliRunner

from barb import __version__
from barb.main import app

runner = CliRunner()

_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(text: str) -> str:
    """Remove ANSI escape codes for assertion-safe substring checks."""
    return _ANSI_ESCAPE.sub("", text)


def test_version_command():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_no_args_shows_help():
    result = runner.invoke(app, [])
    # Typer returns exit code 0 or 2 for no-args-is-help depending on version
    assert result.exit_code in (0, 2)
    assert "Usage" in result.output or "barb" in result.output


# ---------------------------------------------------------------------------
# barb manual tests
# ---------------------------------------------------------------------------


def test_manual_overview_exit_code():
    """barb manual (no topic) exits 0."""
    result = runner.invoke(app, ["manual"])
    assert result.exit_code == 0


def test_manual_overview_contains_version():
    """Overview output contains the installed version string."""
    result = runner.invoke(app, ["manual"])
    clean = _strip_ansi(result.output)
    assert __version__ in clean


def test_manual_overview_contains_topics():
    """Overview output mentions available topics."""
    result = runner.invoke(app, ["manual"])
    clean = _strip_ansi(result.output)
    # Should list at least a handful of topics
    assert "analyzers" in clean
    assert "pipeline" in clean
    assert "osint" in clean


def test_manual_overview_contains_pipeline_hint():
    """Overview contains the pipeline hint line."""
    result = runner.invoke(app, ["manual"])
    clean = _strip_ansi(result.output)
    assert "vex triage" in clean or "vex" in clean


def test_manual_analyzers_topic():
    """barb manual analyzers exits 0 and contains analyzer-related content."""
    result = runner.invoke(app, ["manual", "analyzers"])
    assert result.exit_code == 0
    clean = _strip_ansi(result.output)
    assert "entropy" in clean
    assert "homoglyph" in clean
    assert "CRITICAL" in clean or "critical" in clean.lower()


def test_manual_osint_topic():
    """barb manual osint exits 0 and contains OSINT content."""
    result = runner.invoke(app, ["manual", "osint"])
    assert result.exit_code == 0
    clean = _strip_ansi(result.output)
    assert "rdap" in clean.lower()
    assert "dns" in clean.lower()


def test_manual_output_topic():
    """barb manual output exits 0 and mentions formats."""
    result = runner.invoke(app, ["manual", "output"])
    assert result.exit_code == 0
    clean = _strip_ansi(result.output)
    assert "json" in clean.lower()
    assert "stix" in clean.lower()


def test_manual_config_topic():
    """barb manual config exits 0 and mentions config file."""
    result = runner.invoke(app, ["manual", "config"])
    assert result.exit_code == 0
    clean = _strip_ansi(result.output)
    assert "config.yaml" in clean
    assert "BARB_LLM_KEY" in clean


def test_manual_pipeline_topic():
    """barb manual pipeline exits 0 and contains pipeline content."""
    result = runner.invoke(app, ["manual", "pipeline"])
    assert result.exit_code == 0
    clean = _strip_ansi(result.output)
    assert "vex" in clean.lower()
    assert "json" in clean.lower()


def test_manual_examples_topic():
    """barb manual examples exits 0 and contains example invocations."""
    result = runner.invoke(app, ["manual", "examples"])
    assert result.exit_code == 0
    clean = _strip_ansi(result.output)
    assert "barb analyze" in clean


def test_manual_unknown_topic_shows_overview():
    """Unknown topic prints 'Unknown topic' and falls through to overview."""
    result = runner.invoke(app, ["manual", "bogus"])
    assert result.exit_code == 0
    clean = _strip_ansi(result.output)
    assert "Unknown topic" in clean
    # Overview should still appear
    assert __version__ in clean
