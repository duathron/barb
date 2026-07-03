"""Tests for explanation providers."""

from __future__ import annotations

import json
import urllib.error
from datetime import datetime
from unittest.mock import MagicMock, patch

from barb.config import AppConfig, ExplainConfig
from barb.explain.template import TemplateExplainer
from barb.models import (
    AnalysisResult,
    ParsedURL,
    RiskVerdict,
    Signal,
    SignalSeverity,
)


def test_template_explainer_safe():
    explainer = TemplateExplainer()
    result = AnalysisResult(
        url="https://www.google.com",
        defanged_url="hxxps[://]www[.]google[.]com",
        parsed_url=ParsedURL(original="https://www.google.com", scheme="https", host="www.google.com", path="/"),
        signals=[],
        risk_score=0.0,
        verdict=RiskVerdict.SAFE,
        analyzed_at=datetime.now(),
    )
    explanation = explainer.explain(result)
    assert "safe" in explanation.lower()


def test_template_explainer_phishing():
    explainer = TemplateExplainer()
    result = AnalysisResult(
        url="http://192.168.1.1/paypal",
        defanged_url="hxxp[://]192[.]168[.]1[.]1/paypal",
        parsed_url=ParsedURL(
            original="http://192.168.1.1/paypal",
            scheme="http",
            host="192.168.1.1",
            path="/paypal",
            is_ip=True,
        ),
        signals=[
            Signal(analyzer="ip_url", severity=SignalSeverity.HIGH, label="IP-based URL", detail="Uses IP address"),
        ],
        risk_score=15.0,
        verdict=RiskVerdict.PHISHING,
        analyzed_at=datetime.now(),
    )
    explanation = explainer.explain(result)
    assert "phishing" in explanation.lower()
    assert "IP-based URL" in explanation


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_phishing_result() -> AnalysisResult:
    return AnalysisResult(
        url="http://192.168.1.1/paypal",
        defanged_url="hxxp[://]192[.]168[.]1[.]1/paypal",
        parsed_url=ParsedURL(
            original="http://192.168.1.1/paypal",
            scheme="http",
            host="192.168.1.1",
            path="/paypal",
            is_ip=True,
        ),
        signals=[
            Signal(analyzer="ip_url", severity=SignalSeverity.HIGH, label="IP-based URL", detail="Uses IP address"),
        ],
        risk_score=15.0,
        verdict=RiskVerdict.PHISHING,
        analyzed_at=datetime.now(),
    )


def _fake_urlopen_response(text: str):
    """Return a mock context-manager whose .read() returns a JSON-encoded Ollama response."""
    raw = json.dumps({"response": text}).encode()
    mock_resp = MagicMock()
    mock_resp.read.return_value = raw
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    return mock_resp


# ---------------------------------------------------------------------------
# OllamaExplainer tests
# ---------------------------------------------------------------------------


def test_ollama_explainer_returns_response():
    """OllamaExplainer.explain returns the 'response' field from Ollama JSON."""
    from barb.explain.llm import OllamaExplainer

    result = _make_phishing_result()
    expected = "This URL is a phishing attempt targeting PayPal."

    with patch("urllib.request.urlopen", return_value=_fake_urlopen_response(expected)) as mock_open:
        explainer = OllamaExplainer(host="http://localhost:11434", model="llama3.1")
        explanation = explainer.explain(result, send_url=True)

    assert explanation == expected
    mock_open.assert_called_once()


def test_ollama_explainer_send_url_false_omits_url():
    """When send_url=False, the URL must not appear in the POST body."""
    from barb.explain.llm import OllamaExplainer

    result = _make_phishing_result()

    with patch("urllib.request.urlopen", return_value=_fake_urlopen_response("ok")) as mock_open:
        explainer = OllamaExplainer()
        explainer.explain(result, send_url=False)

    # Retrieve the Request object passed to urlopen
    req = mock_open.call_args[0][0]
    posted_body = json.loads(req.data.decode())
    # The defanged URL must not appear in the prompt
    assert result.defanged_url not in posted_body["prompt"]
    assert result.url not in posted_body["prompt"]


def test_ollama_explainer_raises_on_connection_error():
    """OllamaExplainer.explain raises RuntimeError when urlopen fails."""
    from barb.explain.llm import OllamaExplainer

    result = _make_phishing_result()
    err = urllib.error.URLError("Connection refused")

    with patch("urllib.request.urlopen", side_effect=err):
        explainer = OllamaExplainer()
        try:
            explainer.explain(result)
            assert False, "Expected RuntimeError"
        except RuntimeError as exc:
            assert "ollama serve" in str(exc).lower()


def test_ollama_explainer_raises_on_bad_json():
    """OllamaExplainer.explain raises RuntimeError when response JSON is malformed."""
    from barb.explain.llm import OllamaExplainer

    result = _make_phishing_result()
    mock_resp = MagicMock()
    mock_resp.read.return_value = b"not-json"
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)

    with patch("urllib.request.urlopen", return_value=mock_resp):
        explainer = OllamaExplainer()
        try:
            explainer.explain(result)
            assert False, "Expected RuntimeError"
        except RuntimeError as exc:
            assert "ollama serve" in str(exc).lower()


def test_ollama_explainer_raises_on_missing_key():
    """OllamaExplainer.explain raises RuntimeError when JSON has no 'response' key."""
    from barb.explain.llm import OllamaExplainer

    result = _make_phishing_result()
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps({"something_else": "value"}).encode()
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)

    with patch("urllib.request.urlopen", return_value=mock_resp):
        explainer = OllamaExplainer()
        try:
            explainer.explain(result)
            assert False, "Expected RuntimeError"
        except RuntimeError as exc:
            assert "ollama serve" in str(exc).lower()


# ---------------------------------------------------------------------------
# Dispatch posture test: _explain() with provider="ollama" + Ollama down
#
# FLIPPED for F2 cut-1 (2026-07-03 MeetUp — 2026-07-03-f2-llm-failure-posture.md).
#   OLD posture (pinned here before the flip): when provider=ollama failed,
#     `_explain` SILENTLY substituted the TemplateExplainer output and returned
#     it as the explanation string — the analyst received a rule-based template
#     believing it was an LLM explanation (the exact masquerade the F2 MeetUp
#     was called to kill; the smoke trigger was the sibling `sift triage
#     --provider ollama` 404 -> silent template).
#   NEW posture (asserted below): `_explain` mutates `result` in place — no
#     template is substituted (`result.explanation is None`), the failure is
#     machine-marked (`explanation_degraded=True`, `explanation_provider=
#     "ollama"`), and the process does not crash. The loud stderr notice and
#     the exit-code-4 behavior are covered at the CLI level in
#     tests/test_llm_failure_posture.py.
#   WHY: BLOCK condition (2026-07-03 F2) — "any output where a template reaches
#     the analyst without a machine degraded/provider marker" must be flipped
#     with documented before/after. Silent template on an explicitly-requested
#     provider is a trust violation.
# ---------------------------------------------------------------------------


def test_explain_dispatch_ollama_failure_degrades_not_silent_template():
    """provider=ollama + Ollama unreachable -> degraded marker, NO template, no crash."""
    from barb.main import _explain

    result = _make_phishing_result()

    config = AppConfig()
    config.explain = ExplainConfig(provider="ollama", ollama_host="http://localhost:11434")

    template_text = TemplateExplainer().explain(result)

    with patch("barb.explain.llm.OllamaExplainer.explain", side_effect=RuntimeError("connection refused")):
        # Must not raise — the old crash-vs-silent-fallback split is gone.
        _explain(result, config)

    assert result.explanation is None
    assert result.explanation != template_text  # no silent template substitution
    assert result.explanation_degraded is True
    assert result.explanation_provider == "ollama"
