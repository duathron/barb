"""Characterization tests for barb's LLM-backed explanation providers.

W3 PREREQUISITE: these tests pin what AnthropicExplainer, OpenAIExplainer, and
OllamaExplainer *actually do today* — the request they build, how they parse a
response, and their error/fallback behavior — before the provider logic is
extracted into a shared ``shipwright_kit.llm`` layer (the same extraction sift's
summarizers already went through; see sift/tests/test_llm_provider_requests.py
for the sibling characterization). This is characterization, not specification:
where a provider's current behavior looks inconsistent, asymmetric, or outright
fragile (e.g. Anthropic/OpenAI API errors propagating completely unwrapped, or
Ollama being the only provider with any fallback path at all), the test pins
the behavior AS-IS and calls it out in a comment/docstring. Nothing under
``barb/explain/`` is changed by this file.

STRUCTURAL NOTE vs sift: barb's explain() returns a raw freeform text string
(a human-readable verdict explanation for a SOC analyst), not a JSON payload.
There is therefore no JSON-parse/schema-validation step anywhere in barb's LLM
providers, and consequently no "malformed LLM output falls back to template"
path the way sift's summarizers have one. Only the OllamaExplainer's own HTTP
transport failures raise, and only barb's CLI dispatch layer (barb.main._explain)
catches that raise and falls back to TemplateExplainer — the provider class
itself does not know about the template fallback.

All external clients are mocked — the ``anthropic`` SDK client, the ``openai``
SDK client, and ``urllib.request.urlopen`` for Ollama. No live network, no real
API keys. Anthropic/OpenAI test classes are skipped when the ``llm`` extra is
not installed (see the barb-vs-sift extras-availability note in the report).
"""

from __future__ import annotations

import json
import urllib.error
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from barb.config import AppConfig, ExplainConfig
from barb.explain.llm import AnthropicExplainer, OllamaExplainer, OpenAIExplainer
from barb.explain.prompt import SYSTEM_PROMPT, build_prompt
from barb.main import _explain
from barb.models import AnalysisResult, ParsedURL, RiskVerdict, Signal, SignalSeverity

try:
    import anthropic
except ImportError:
    anthropic = None

try:
    import openai
except ImportError:
    openai = None

requires_anthropic = pytest.mark.skipif(
    anthropic is None, reason="anthropic extra not installed — see pyproject.toml [project.optional-dependencies] llm"
)
requires_openai = pytest.mark.skipif(
    openai is None, reason="openai extra not installed — see pyproject.toml [project.optional-dependencies] llm"
)
requires_no_anthropic = pytest.mark.skipif(
    anthropic is not None, reason="documents behavior only observable when the anthropic extra is absent"
)
requires_no_openai = pytest.mark.skipif(
    openai is not None, reason="documents behavior only observable when the openai extra is absent"
)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _make_result(*, signals: list[Signal] | None = None) -> AnalysisResult:
    signals = (
        signals
        if signals is not None
        else [
            Signal(analyzer="ip_url", severity=SignalSeverity.HIGH, label="IP-based URL", detail="Uses IP address"),
        ]
    )
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
        signals=signals,
        risk_score=15.0,
        verdict=RiskVerdict.PHISHING,
        analyzed_at=datetime.now(timezone.utc),
    )


def _expected_user_prompt(result: AnalysisResult, send_url: bool = True) -> str:
    signals_text = "\n".join(f"  [{s.severity.value}] {s.analyzer}: {s.detail}" for s in result.signals)
    defanged_url = result.defanged_url if send_url else None
    return build_prompt(
        verdict=result.verdict.value,
        risk_score=result.risk_score,
        signals_text=signals_text,
        defanged_url=defanged_url,
    )


def _fake_urlopen_response(text: str):
    raw = json.dumps({"response": text}).encode()
    mock_resp = MagicMock()
    mock_resp.read.return_value = raw
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    return mock_resp


# ---------------------------------------------------------------------------
# Ollama — request construction (extends tests/test_explain.py, not duplicated)
# ---------------------------------------------------------------------------


class TestOllamaRequestConstruction:
    def test_payload_key_set_includes_system_barb_specific(self):
        """BARB-SPECIFIC vs sift: barb sends "system" as its own top-level payload
        key on Ollama's /api/generate. sift's OllamaSummarizer instead PREPENDS the
        system prompt into the "prompt" string and never sends a "system" key. Same
        endpoint, different payload shape — exactly the divergence W3 must reconcile."""
        result = _make_result()
        with patch("urllib.request.urlopen", return_value=_fake_urlopen_response("ok")) as mock_open:
            OllamaExplainer().explain(result)
        posted = json.loads(mock_open.call_args[0][0].data.decode())
        assert set(posted.keys()) == {"model", "system", "prompt", "stream"}

    def test_payload_system_field_equals_system_prompt_constant(self):
        result = _make_result()
        with patch("urllib.request.urlopen", return_value=_fake_urlopen_response("ok")) as mock_open:
            OllamaExplainer().explain(result)
        posted = json.loads(mock_open.call_args[0][0].data.decode())
        assert posted["system"] == SYSTEM_PROMPT

    def test_payload_prompt_matches_prompt_module_wiring(self):
        result = _make_result()
        with patch("urllib.request.urlopen", return_value=_fake_urlopen_response("ok")) as mock_open:
            OllamaExplainer().explain(result, send_url=True)
        posted = json.loads(mock_open.call_args[0][0].data.decode())
        assert posted["prompt"] == _expected_user_prompt(result, send_url=True)

    def test_stream_is_false(self):
        result = _make_result()
        with patch("urllib.request.urlopen", return_value=_fake_urlopen_response("ok")) as mock_open:
            OllamaExplainer().explain(result)
        posted = json.loads(mock_open.call_args[0][0].data.decode())
        assert posted["stream"] is False

    def test_no_temperature_or_options_key_sent(self):
        """Matches sift's Ollama on this one point: neither sends temperature."""
        result = _make_result()
        with patch("urllib.request.urlopen", return_value=_fake_urlopen_response("ok")) as mock_open:
            OllamaExplainer().explain(result)
        posted = json.loads(mock_open.call_args[0][0].data.decode())
        assert "temperature" not in posted
        assert "options" not in posted

    def test_default_host_and_model(self):
        result = _make_result()
        with patch("urllib.request.urlopen", return_value=_fake_urlopen_response("ok")) as mock_open:
            OllamaExplainer().explain(result)
        req = mock_open.call_args[0][0]
        posted = json.loads(req.data.decode())
        assert req.full_url == "http://localhost:11434/api/generate"
        assert posted["model"] == "llama3.1"

    def test_custom_host_trailing_slash_stripped(self):
        result = _make_result()
        with patch("urllib.request.urlopen", return_value=_fake_urlopen_response("ok")) as mock_open:
            OllamaExplainer(host="http://gpu-box:11434/").explain(result)
        req = mock_open.call_args[0][0]
        assert req.full_url == "http://gpu-box:11434/api/generate"

    def test_request_method_is_post(self):
        result = _make_result()
        with patch("urllib.request.urlopen", return_value=_fake_urlopen_response("ok")) as mock_open:
            OllamaExplainer().explain(result)
        req = mock_open.call_args[0][0]
        assert req.get_method() == "POST"

    def test_content_type_header_is_json(self):
        result = _make_result()
        with patch("urllib.request.urlopen", return_value=_fake_urlopen_response("ok")) as mock_open:
            OllamaExplainer().explain(result)
        req = mock_open.call_args[0][0]
        # urllib title-cases header keys it was given ("Content-Type" -> "Content-type").
        assert dict(req.header_items()).get("Content-type") == "application/json"

    def test_timeout_passed_to_urlopen_is_60(self):
        """Pins the class-level _TIMEOUT = 60 constant used on every call."""
        result = _make_result()
        with patch("urllib.request.urlopen", return_value=_fake_urlopen_response("ok")) as mock_open:
            OllamaExplainer().explain(result)
        assert mock_open.call_args.kwargs["timeout"] == 60

    def test_send_url_true_includes_defanged_url_in_prompt(self):
        result = _make_result()
        with patch("urllib.request.urlopen", return_value=_fake_urlopen_response("ok")) as mock_open:
            OllamaExplainer().explain(result, send_url=True)
        posted = json.loads(mock_open.call_args[0][0].data.decode())
        assert result.defanged_url in posted["prompt"]

    def test_response_text_is_stripped(self):
        result = _make_result()
        with patch("urllib.request.urlopen", return_value=_fake_urlopen_response("  padded response  \n")):
            explanation = OllamaExplainer().explain(result)
        assert explanation == "padded response"


# ---------------------------------------------------------------------------
# Ollama — error handling supplement (HTTPError specifically; URLError already
# covered by tests/test_explain.py::test_ollama_explainer_raises_on_connection_error)
# ---------------------------------------------------------------------------


class TestOllamaErrorHandlingSupplement:
    """FLIPPED for F2 cut-1 (2026-07-03 MeetUp — 2026-07-03-f2-llm-failure-posture.md).

    The RAW OllamaExplainer class still wraps transport errors as RuntimeError
    (see TestCrossProviderTemperatureAndErrorHandlingComparison, unchanged) —
    that class-level contract is NOT what F2 changes. F2 changes the POSTURE one
    layer up, in barb.main._explain: an ollama failure used to become a SILENT
    TemplateExplainer substitution; it now degrades loudly with a machine
    marker. These two tests are re-scoped from the bare class (which only ever
    raised) to _explain (where the observable posture lives).
    """

    def test_http_error_via_dispatch_degrades_not_silent_template(self):
        """OLD: an Ollama HTTPError (500) -> RuntimeError -> `_explain` silently
        returned a TemplateExplainer string. NEW: `_explain` marks the result
        degraded (provider='ollama'), substitutes no template, and does not
        crash. WHY: F2 2026-07-03 BLOCK — no silent template on a requested
        provider failure."""
        result = _make_result()
        config = AppConfig()
        config.explain = ExplainConfig(provider="ollama", ollama_host="http://localhost:11434")
        http_err = urllib.error.HTTPError(
            url="http://localhost:11434/api/generate", code=500, msg="Internal Server Error", hdrs=None, fp=None
        )
        with patch("urllib.request.urlopen", side_effect=http_err):
            _explain(result, config)  # must not raise
        assert result.explanation is None
        assert result.explanation_degraded is True
        assert result.explanation_provider == "ollama"

    def test_custom_host_url_error_via_dispatch_degrades(self):
        """OLD: a URLError against a custom host -> RuntimeError mentioning the
        host -> silent template. NEW: degraded marker via `_explain`, no crash,
        no template. WHY: F2 2026-07-03 (as above)."""
        result = _make_result()
        config = AppConfig()
        config.explain = ExplainConfig(provider="ollama", ollama_host="http://gpu-box:11434")
        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("refused")):
            _explain(result, config)  # must not raise
        assert result.explanation is None
        assert result.explanation_degraded is True
        assert result.explanation_provider == "ollama"


# ---------------------------------------------------------------------------
# Anthropic — request construction
# ---------------------------------------------------------------------------


@requires_no_anthropic
class TestAnthropicMissingExtra:
    def test_import_error_message_when_anthropic_not_installed(self):
        with pytest.raises(ImportError, match="anthropic package required"):
            AnthropicExplainer(api_key="fake-key")


@requires_anthropic
class TestAnthropicRequestConstruction:
    def _explainer_with_mock_client(self, model: str | None = None):
        explainer = AnthropicExplainer(api_key="fake-key", **({"model": model} if model else {}))
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.content = [MagicMock(text="This URL is a phishing attempt.")]
        mock_client.messages.create.return_value = mock_response
        explainer._client = mock_client
        return explainer, mock_client

    def test_sends_model_hardcoded_max_tokens_system_and_user_message(self):
        """max_tokens=512 is a HARDCODED literal in explain() — unlike sift's
        AnthropicSummarizer, which sources max_tokens from SummarizeConfig. There is
        no config knob for it anywhere in barb's ExplainConfig or dispatch code."""
        explainer, mock_client = self._explainer_with_mock_client(model="claude-sonnet-4-6")
        result = _make_result()
        explainer.explain(result)

        kwargs = mock_client.messages.create.call_args.kwargs
        assert kwargs["model"] == "claude-sonnet-4-6"
        assert kwargs["max_tokens"] == 512
        assert kwargs["system"] == SYSTEM_PROMPT
        assert kwargs["messages"] == [{"role": "user", "content": _expected_user_prompt(result)}]

    def test_default_model_used_when_not_overridden(self):
        explainer, mock_client = self._explainer_with_mock_client()
        explainer.explain(_make_result())
        assert mock_client.messages.create.call_args.kwargs["model"] == "claude-sonnet-4-20250514"

    def test_temperature_is_NOT_sent(self):
        """Matches sift's Anthropic on this point: SDK default temperature applies."""
        explainer, mock_client = self._explainer_with_mock_client()
        explainer.explain(_make_result())
        assert "temperature" not in mock_client.messages.create.call_args.kwargs

    def test_no_response_format_or_tools_param_sent(self):
        explainer, mock_client = self._explainer_with_mock_client()
        explainer.explain(_make_result())
        kwargs = mock_client.messages.create.call_args.kwargs
        assert "response_format" not in kwargs
        assert "tools" not in kwargs

    def test_send_url_false_omits_url_from_prompt(self):
        """barb-specific surface: explain(result, send_url=bool) toggles whether the
        (defanged) URL is included in the outbound prompt at all — a privacy knob
        that has no equivalent concept in sift's cluster-alert prompts."""
        explainer, mock_client = self._explainer_with_mock_client()
        result = _make_result()
        explainer.explain(result, send_url=False)
        sent_prompt = mock_client.messages.create.call_args.kwargs["messages"][0]["content"]
        assert result.defanged_url not in sent_prompt
        assert result.url not in sent_prompt


@requires_anthropic
class TestAnthropicResponseParsing:
    def test_returns_content_0_text_raw_no_json_parsing(self):
        """STRUCTURAL: barb's explain() returns raw prose text directly — there is
        no json.loads()/schema-validation step at all, unlike sift's summarizers."""
        explainer = AnthropicExplainer(api_key="fake-key")
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.content = [MagicMock(text="Plain-text analyst explanation.")]
        mock_client.messages.create.return_value = mock_response
        explainer._client = mock_client

        assert explainer.explain(_make_result()) == "Plain-text analyst explanation."

    def test_empty_content_list_raises_index_error_uncaught(self):
        """QUIRK (reported, not fixed): `response.content[0].text` is indexed
        unconditionally. An empty content list raises a bare IndexError that
        propagates all the way to the caller — no defensive handling, unlike sift's
        AnthropicSummarizer which loop-scans for the first block exposing `.text`."""
        explainer = AnthropicExplainer(api_key="fake-key")
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.content = []
        mock_client.messages.create.return_value = mock_response
        explainer._client = mock_client

        with pytest.raises(IndexError):
            explainer.explain(_make_result())

    def test_first_block_without_text_attribute_raises_attribute_error_uncaught(self):
        """QUIRK (reported, not fixed): if content[0] doesn't expose `.text` (e.g. a
        tool_use block ordered first), barb raises AttributeError uncaught. sift's
        AnthropicSummarizer instead scans all blocks for the first one with `.text`."""

        class NoTextBlock:
            type = "tool_use"

        explainer = AnthropicExplainer(api_key="fake-key")
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.content = [NoTextBlock()]
        mock_client.messages.create.return_value = mock_response
        explainer._client = mock_client

        with pytest.raises(AttributeError):
            explainer.explain(_make_result())


@requires_anthropic
class TestAnthropicErrorHandling:
    def test_api_error_propagates_unwrapped_not_reraised(self):
        """FLIPPED for F2 cut-1 (2026-07-03 MeetUp — 2026-07-03-f2-llm-failure-posture.md).

        OLD posture (pinned pre-flip): `explain()` had no try/except and
        `barb.main._explain()` had none around the anthropic branch either, so a
        live `anthropic.APIError` flew UNCAUGHT to the CLI — exiting 1, which
        COLLIDES with the SUSPICIOUS/HIGH_RISK verdict exit code (a crash read
        as a real risk verdict = a false-escalation generator).

        NEW posture (asserted): the raw AnthropicExplainer class still raises
        (unchanged — see the comparison table class below), but `_explain` now
        CATCHES it: `result.explanation` stays None, `explanation_degraded` is
        True, `explanation_provider == "anthropic"`, and NOTHING propagates (no
        crash, no silent template).

        WHY: F2 2026-07-03 item 7 — normalize barb's crash-vs-fallback split so
        a provider failure fails loud-and-controlled, never an uncaught
        traceback exiting 1-as-SUSPICIOUS."""
        import httpx

        result = _make_result()
        config = AppConfig()
        config.explain = ExplainConfig(provider="anthropic", api_key="fake-key")

        req = httpx.Request("POST", "https://api.anthropic.com/v1/messages")

        def _boom(self, *a, **k):
            raise anthropic.APIError("boom", request=req, body=None)

        with patch.object(AnthropicExplainer, "explain", _boom):
            _explain(result, config)  # must not raise

        assert result.explanation is None
        assert result.explanation_degraded is True
        assert result.explanation_provider == "anthropic"


# ---------------------------------------------------------------------------
# OpenAI — request construction
# ---------------------------------------------------------------------------


@requires_no_openai
class TestOpenAIMissingExtra:
    def test_import_error_message_when_openai_not_installed(self):
        with pytest.raises(ImportError, match="openai package required"):
            OpenAIExplainer(api_key="fake-key")


@requires_openai
class TestOpenAIRequestConstruction:
    def _explainer_with_mock_client(self, model: str | None = None):
        explainer = OpenAIExplainer(api_key="fake-key", **({"model": model} if model else {}))
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(content="This URL is a phishing attempt."))]
        mock_client.chat.completions.create.return_value = mock_response
        explainer._client = mock_client
        return explainer, mock_client

    def test_sends_model_hardcoded_max_tokens_and_two_role_messages(self):
        explainer, mock_client = self._explainer_with_mock_client(model="gpt-4o")
        result = _make_result()
        explainer.explain(result)

        kwargs = mock_client.chat.completions.create.call_args.kwargs
        assert kwargs["model"] == "gpt-4o"
        assert kwargs["max_tokens"] == 512
        messages = kwargs["messages"]
        assert len(messages) == 2
        assert messages[0] == {"role": "system", "content": SYSTEM_PROMPT}
        assert messages[1] == {"role": "user", "content": _expected_user_prompt(result)}

    def test_default_model_used_when_not_overridden(self):
        explainer, mock_client = self._explainer_with_mock_client()
        explainer.explain(_make_result())
        assert mock_client.chat.completions.create.call_args.kwargs["model"] == "gpt-4o-mini"

    def test_temperature_is_NOT_sent_barb_wide_consistency(self):
        """KEY BARB-VS-SIFT FINDING: sift's OpenAISummarizer is the ONE provider
        that forwards config.temperature (default 0.1) — an asymmetry sift itself
        flags. barb's OpenAIExplainer sends NO temperature at all, same as its own
        Anthropic and Ollama providers. barb is internally consistent (no provider
        ever sends temperature); sift is internally inconsistent (OpenAI alone
        sends it). W3's shared layer must pick one convention across both tools."""
        explainer, mock_client = self._explainer_with_mock_client()
        explainer.explain(_make_result())
        assert "temperature" not in mock_client.chat.completions.create.call_args.kwargs

    def test_no_response_format_or_tools_param_sent(self):
        explainer, mock_client = self._explainer_with_mock_client()
        explainer.explain(_make_result())
        kwargs = mock_client.chat.completions.create.call_args.kwargs
        assert "response_format" not in kwargs
        assert "tools" not in kwargs
        assert "functions" not in kwargs


@requires_openai
class TestOpenAIResponseParsing:
    def test_returns_choices_0_message_content_raw(self):
        explainer = OpenAIExplainer(api_key="fake-key")
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(content="Plain-text analyst explanation."))]
        mock_client.chat.completions.create.return_value = mock_response
        explainer._client = mock_client

        assert explainer.explain(_make_result()) == "Plain-text analyst explanation."

    def test_none_content_degrades_to_empty_string_not_a_crash(self):
        """QUIRK: `response.choices[0].message.content or ""` — a None content (e.g.
        model emitted only a tool call) silently becomes "". Unlike sift's
        OpenAISummarizer, where a None content fails JSON parsing and triggers the
        template fallback, barb has no fallback concept here: explain() just
        returns "" as the final, user-visible explanation string."""
        explainer = OpenAIExplainer(api_key="fake-key")
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(content=None))]
        mock_client.chat.completions.create.return_value = mock_response
        explainer._client = mock_client

        assert explainer.explain(_make_result()) == ""


@requires_openai
class TestOpenAIErrorHandling:
    def test_api_error_propagates_unwrapped_not_reraised(self):
        """FLIPPED for F2 cut-1 (2026-07-03 MeetUp — 2026-07-03-f2-llm-failure-posture.md).

        OLD posture: identical to Anthropic — no try/except anywhere, so an
        `openai.APIError` reached the CLI uncaught (exit 1, colliding with the
        SUSPICIOUS verdict code). NEW posture: `_explain` catches it -> degraded
        marker (provider='openai'), no crash, no silent template. WHY: F2
        2026-07-03 item 7 (same rationale as the Anthropic flip above)."""
        import httpx

        result = _make_result()
        config = AppConfig()
        config.explain = ExplainConfig(provider="openai", api_key="fake-key")

        req = httpx.Request("POST", "https://api.openai.com/v1/chat/completions")

        def _boom(self, *a, **k):
            raise openai.APIError("boom", request=req, body=None)

        with patch.object(OpenAIExplainer, "explain", _boom):
            _explain(result, config)  # must not raise

        assert result.explanation is None
        assert result.explanation_degraded is True
        assert result.explanation_provider == "openai"


# ---------------------------------------------------------------------------
# Cross-provider comparison table — consolidated pin for the W3 MeetUp.
# ---------------------------------------------------------------------------


class TestCrossProviderTemperatureAndErrorHandlingComparison:
    """Consolidated pin of the temperature and error-handling posture across all
    3 LLM providers within barb itself, for direct comparison against sift's
    equivalent table (sift/tests/test_llm_provider_requests.py, class
    TestCrossProviderTemperatureAsymmetry).

    Temperature (barb):
    | provider  | temperature sent? | value |
    |-----------|--------------------|-------|
    | anthropic | NO                 | omitted; SDK/API default applies |
    | openai    | NO                 | omitted; SDK/API default applies |
    | ollama    | NO                 | omitted; no "options" dict sent  |
    barb is internally consistent: NO provider ever sends temperature.
    sift is internally inconsistent: only its OpenAISummarizer sends temperature
    (config.temperature, default 0.1); Anthropic and Ollama omit it there too.

    Error handling on a provider-level failure (barb):
    | provider  | provider raises?         | anything catches it?                         |
    |-----------|---------------------------|-----------------------------------------------|
    | anthropic | yes — raw SDK exception   | NOTHING — propagates uncaught to the CLI       |
    | openai    | yes — raw SDK exception   | NOTHING — propagates uncaught to the CLI       |
    | ollama    | yes — RuntimeError        | barb.main._explain() catches RuntimeError and  |
    |           | (wrapped by the provider) | falls back to TemplateExplainer (stderr note)  |

    sift, by contrast: Anthropic/OpenAI catch the SDK's APIError and re-raise it
    as a RuntimeError with a friendly message (still a raise, not a fallback);
    Ollama wraps its ENTIRE call in a bare `except Exception` and ALWAYS falls
    back to the template silently, including on network failures. So sift's
    Ollama is more forgiving than sift's cloud providers, and MUCH more forgiving
    than barb's Ollama (which raises, and depends on a separate CLI-layer catch to
    achieve any fallback at all — the OllamaExplainer class by itself has zero
    fallback behavior; only barb.main._explain() supplies it, and only for the
    ollama provider branch).

    NOTE (F2 cut-1, 2026-07-03 MeetUp — 2026-07-03-f2-llm-failure-posture.md):
    the RAW PROVIDER-CLASS behavior pinned in this table is unchanged — Ollama
    still wraps as RuntimeError, Anthropic/OpenAI still raise their bare SDK
    exception. What changed is barb.main._explain(), which now UNIFORMLY catches
    all three (build + explain in one try) and DEGRADES loudly instead of
    crashing (anthropic/openai) or silently substituting a template (ollama).
    The two tests below still assert the class-level raise, which remains true;
    the posture flip is asserted in the per-provider ErrorHandling classes and
    at the CLI level in tests/test_llm_failure_posture.py.
    """

    def test_no_provider_in_barb_sends_temperature(self):
        result = _make_result()

        with patch("urllib.request.urlopen", return_value=_fake_urlopen_response("ok")) as mock_open:
            OllamaExplainer().explain(result)
        ollama_payload = json.loads(mock_open.call_args[0][0].data.decode())
        assert "temperature" not in ollama_payload

    @requires_anthropic
    def test_anthropic_omits_temperature(self):
        explainer = AnthropicExplainer(api_key="fake-key")
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.content = [MagicMock(text="ok")]
        mock_client.messages.create.return_value = mock_response
        explainer._client = mock_client
        explainer.explain(_make_result())
        assert "temperature" not in mock_client.messages.create.call_args.kwargs

    @requires_openai
    def test_openai_omits_temperature(self):
        explainer = OpenAIExplainer(api_key="fake-key")
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(content="ok"))]
        mock_client.chat.completions.create.return_value = mock_response
        explainer._client = mock_client
        explainer.explain(_make_result())
        assert "temperature" not in mock_client.chat.completions.create.call_args.kwargs

    def test_only_ollama_provider_class_itself_raises_a_wrapped_runtime_error(self):
        """OllamaExplainer wraps transport failures as RuntimeError; this is the
        ONLY provider class in barb that does any error translation at all."""
        result = _make_result()
        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("refused")):
            with pytest.raises(RuntimeError):
                OllamaExplainer().explain(result)

    @requires_anthropic
    def test_anthropic_provider_class_does_no_error_translation(self):
        """Contrast with the Ollama case above: Anthropic's own SDK exception type
        (not RuntimeError) is what comes out, because explain() does not catch it."""
        import httpx

        explainer = AnthropicExplainer(api_key="fake-key")
        mock_client = MagicMock()
        req = httpx.Request("POST", "https://api.anthropic.com/v1/messages")
        mock_client.messages.create.side_effect = anthropic.APIError("boom", request=req, body=None)
        explainer._client = mock_client

        with pytest.raises(anthropic.APIError):
            explainer.explain(_make_result())
