"""CLI-level coverage for the F2 cut-1 unified LLM-provider-failure posture.

Reference: ``2026-07-03-f2-llm-failure-posture.md`` (MeetUp decision, signed
off). sift shipped the reference implementation (sift 1.3.3,
``sift/tests/test_llm_failure_posture.py``); this is barb's copy of the spec.

barb's structure differs from sift: barb produces a per-URL rule-based VERDICT
(the PRIMARY output) plus an OPTIONAL ``--explain`` (LLM, secondary). The bug
this closes:
  * anthropic/openai explain failures were UNCAUGHT — the process crashed and
    exited 1, colliding with the SUSPICIOUS/HIGH_RISK verdict exit code (a
    crash read as a real risk verdict = a false-escalation generator);
  * ollama explain failures were SILENTLY substituted with a rule-based
    TemplateExplainer result — the analyst got a template believing it was an
    LLM explanation (the exact masquerade that triggered the F2 MeetUp).

The new posture, proven end-to-end via the CLI:
  (a) no TemplateExplainer output is substituted for a failed LLM;
  (b) ``explanation`` is null and ``explanation_degraded``/``explanation_provider``
      are set (additive machine markers);
  (c) the run exits with the reserved degraded exit code (4), distinct from the
      verdict codes (0/1/2) and the CLI-usage code (3);
  (d) a loud ``EXPLANATION UNAVAILABLE`` notice goes to STDERR only — a
      ``-o json`` run's STDOUT stays ``json.loads``-parseable; the rich/console
      RENDERERS also scream the banner (on stdout, where the analyst reads);
  (e) the per-URL VERDICT (barb's primary output) still completes and is present;
  (f) a DELIBERATE ``provider: template`` run (no LLM requested) is never
      degraded — exit stands at the verdict code, no marker, no notice;
  (g) an anthropic/openai failure no longer crashes — the only exception
      CliRunner records is the controlled ``SystemExit(4)`` from ``typer.Exit``,
      never the raw provider ``APIError`` (which the old code let fly to exit 1);
  (h) no ``--on-llm-failure`` flag and no TTY prompt exist (both DEFERRED to
      slice-2 per the MeetUp decision).

barb's ``analyze`` command has NO ``--provider`` CLI flag — the provider comes
from ``config.explain.provider`` (config file / env). So these tests write a
hermetic ``~/.barb/config.yaml`` into a temp ``_APP_DIR`` (same isolation
pattern as ``tests/test_config.py``) to select the provider, then patch the
provider's transport/SDK seam to fail. No live network, no real API keys.
"""

from __future__ import annotations

import json
import urllib.error
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

import barb.config
from barb.explain.llm import AnthropicExplainer, OpenAIExplainer
from barb.main import app

runner = CliRunner()

_PHISH_URL = "http://192.168.1.1/paypal-login"


@pytest.fixture
def _hermetic_config(tmp_path, monkeypatch):
    """Isolate barb's app dir so a real ``~/.barb/config.yaml`` (which may set
    ``explain.provider: anthropic`` from real usage) never leaks in, and so a
    test can write its own provider config. Mirrors tests/test_config.py."""
    app_dir = tmp_path / ".barb"
    app_dir.mkdir()
    monkeypatch.chdir(tmp_path)  # no stray cwd config.yaml
    monkeypatch.setattr(barb.config, "_APP_DIR", app_dir)
    monkeypatch.delenv("BARB_LLM_KEY", raising=False)

    def _write(yaml_text: str) -> None:
        (app_dir / "config.yaml").write_text(yaml_text)

    return _write


def _fail_ollama(monkeypatch) -> None:
    """Patch the urllib seam OllamaExplainer POSTs through so every Ollama call
    raises (same technique as tests/test_explain.py)."""

    def fake_urlopen(req, *args, **kwargs):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)


# ---------------------------------------------------------------------------
# (a)+(b)+(c)+(d)+(e) — ollama failure: no template, markers set, exit 4,
# stderr-only notice, JSON stays parseable, verdict still present.
# ---------------------------------------------------------------------------


class TestOllamaFailureJSON:
    def test_json_run_exit_4_markers_set_verdict_present(self, _hermetic_config, monkeypatch):
        _hermetic_config("explain:\n  provider: ollama\n  ollama_host: http://localhost:11434\n")
        _fail_ollama(monkeypatch)
        result = runner.invoke(app, ["analyze", _PHISH_URL, "-o", "json", "-q", "--explain"])

        # (c) reserved degraded exit code
        assert result.exit_code == 4
        # (d) stdout is exactly one JSON document — nothing leaked in
        data = json.loads(result.stdout)
        # (a)+(b) no template; degraded markers set
        assert data["explanation"] is None
        assert data["explanation_degraded"] is True
        assert data["explanation_provider"] == "ollama"
        # (e) the PRIMARY output — the verdict/score/signals — still completes
        assert data["verdict"] in ("SUSPICIOUS", "HIGH_RISK", "PHISHING")
        assert data["risk_score"] > 0
        assert len(data["signals"]) >= 1

    def test_loud_notice_on_stderr_not_stdout_for_json(self, _hermetic_config, monkeypatch):
        _hermetic_config("explain:\n  provider: ollama\n")
        _fail_ollama(monkeypatch)
        result = runner.invoke(app, ["analyze", _PHISH_URL, "-o", "json", "-q", "--explain"], catch_exceptions=False)
        # (d) the notice must never leak into stdout for -o json (pipe safety)
        assert "EXPLANATION UNAVAILABLE" not in result.stdout
        assert "EXPLANATION UNAVAILABLE" in result.stderr
        assert "ollama" in result.stderr


# ---------------------------------------------------------------------------
# (d) — the DEFAULT renderers (rich/console) scream the banner on stdout.
# ---------------------------------------------------------------------------


class TestLoudDefaultRenderers:
    def test_rich_shows_loud_unavailable_banner(self, _hermetic_config, monkeypatch):
        _hermetic_config("explain:\n  provider: ollama\n")
        _fail_ollama(monkeypatch)
        result = runner.invoke(app, ["analyze", _PHISH_URL, "-o", "rich", "-q", "--explain"])
        assert "EXPLANATION UNAVAILABLE" in result.stdout  # in the renderer itself
        assert result.exit_code == 4

    def test_console_shows_loud_unavailable_banner(self, _hermetic_config, monkeypatch):
        _hermetic_config("explain:\n  provider: ollama\n")
        _fail_ollama(monkeypatch)
        result = runner.invoke(app, ["analyze", _PHISH_URL, "-o", "console", "-q", "--explain"])
        assert "EXPLANATION UNAVAILABLE" in result.stdout
        assert result.exit_code == 4


# ---------------------------------------------------------------------------
# (g) — anthropic/openai failure no longer crashes (no uncaught traceback),
# exits the controlled 4, and degrades with a marker.
# ---------------------------------------------------------------------------


class TestCloudProviderFailureDoesNotCrash:
    def test_anthropic_api_failure_exits_4_no_uncaught_crash(self, _hermetic_config):
        import anthropic
        import httpx

        _hermetic_config("explain:\n  provider: anthropic\n  api_key: fake-key\n")
        req = httpx.Request("POST", "https://api.anthropic.com/v1/messages")

        def _boom(self, *a, **k):
            raise anthropic.APIError("boom", request=req, body=None)

        with patch.object(AnthropicExplainer, "explain", _boom):
            result = runner.invoke(app, ["analyze", _PHISH_URL, "-o", "json", "-q", "--explain"])

        # (g) the OLD bug: an uncaught APIError was recorded as result.exception
        # and click exited 1 (== SUSPICIOUS). Now the ONLY exception is the
        # controlled SystemExit(4) from typer.Exit — never the raw APIError.
        assert result.exit_code == 4
        assert isinstance(result.exception, SystemExit)
        assert not isinstance(result.exception, anthropic.APIError)
        data = json.loads(result.stdout)
        assert data["explanation"] is None
        assert data["explanation_degraded"] is True
        assert data["explanation_provider"] == "anthropic"

    def test_openai_api_failure_exits_4_no_uncaught_crash(self, _hermetic_config):
        import httpx
        import openai

        _hermetic_config("explain:\n  provider: openai\n  api_key: fake-key\n")
        req = httpx.Request("POST", "https://api.openai.com/v1/chat/completions")

        def _boom(self, *a, **k):
            raise openai.APIError("boom", request=req, body=None)

        with patch.object(OpenAIExplainer, "explain", _boom):
            result = runner.invoke(app, ["analyze", _PHISH_URL, "-o", "json", "-q", "--explain"])

        assert result.exit_code == 4
        assert isinstance(result.exception, SystemExit)
        assert not isinstance(result.exception, openai.APIError)
        data = json.loads(result.stdout)
        assert data["explanation_degraded"] is True
        assert data["explanation_provider"] == "openai"

    def test_missing_api_key_is_degraded_not_silent_blank(self, _hermetic_config):
        """A provider explicitly configured as anthropic with NO key used to
        echo an error and return a blank explanation (no marker, no exit code).
        F2: an explicit-provider failure must fail loud + marked."""
        _hermetic_config("explain:\n  provider: anthropic\n")  # no api_key
        result = runner.invoke(app, ["analyze", _PHISH_URL, "-o", "json", "-q", "--explain"])
        assert result.exit_code == 4
        assert isinstance(result.exception, SystemExit)  # controlled exit, not a crash
        data = json.loads(result.stdout)
        assert data["explanation"] is None
        assert data["explanation_degraded"] is True
        assert data["explanation_provider"] == "anthropic"
        assert "EXPLANATION UNAVAILABLE" in result.stderr


# ---------------------------------------------------------------------------
# (f) — a deliberate `template` provider run is NOT degraded.
# ---------------------------------------------------------------------------


class TestDeliberateTemplateIsNotDegraded:
    def test_template_provider_not_degraded(self, _hermetic_config, monkeypatch):
        """provider=template (the default) is an explicit no-LLM choice: even
        though Ollama's transport is patched to fail, it is never invoked; the
        run behaves exactly as a normal template explanation always has."""
        _hermetic_config("explain:\n  provider: template\n")
        _fail_ollama(monkeypatch)  # proves the transport is simply never called
        result = runner.invoke(app, ["analyze", _PHISH_URL, "-o", "json", "-q", "--explain"])
        # exit stands at the verdict code (this URL is suspicious/phishing -> 1/2)
        assert result.exit_code in (0, 1, 2)
        data = json.loads(result.stdout)
        assert data["explanation"] is not None  # a template explanation IS produced
        assert data["explanation_degraded"] is False
        assert data["explanation_provider"] is None
        assert "EXPLANATION UNAVAILABLE" not in result.stderr

    def test_no_explain_flag_is_not_degraded(self, _hermetic_config):
        """The absolute baseline: no --explain at all -> no marker, verdict exit."""
        _hermetic_config("explain:\n  provider: anthropic\n")  # provider set but unused
        result = runner.invoke(app, ["analyze", _PHISH_URL, "-o", "json", "-q"])
        assert result.exit_code in (0, 1, 2)
        data = json.loads(result.stdout)
        assert data["explanation_degraded"] is False
        assert data["explanation_provider"] is None


# ---------------------------------------------------------------------------
# (h) — no --on-llm-failure flag / no TTY prompt (DEFERRED to slice-2).
# ---------------------------------------------------------------------------


class TestNoFlagNoPrompt:
    def test_no_on_llm_failure_flag_exists(self):
        result = runner.invoke(app, ["analyze", "--help"])
        assert "--on-llm-failure" not in result.stdout
