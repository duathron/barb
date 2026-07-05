"""LLM-based explanation providers — Anthropic, OpenAI, and Ollama support."""

from __future__ import annotations

import json
import urllib.error

from shipwright_kit.llm import anthropic_complete, ollama_generate, openai_complete

from ..models import AnalysisResult
from .injection import PromptInjectionDetector
from .prompt import SYSTEM_PROMPT, build_prompt


class AnthropicExplainer:
    """Explanation provider using Anthropic Claude API."""

    def __init__(self, api_key: str, model: str = "claude-sonnet-4-20250514") -> None:
        try:
            import anthropic
        except ImportError:
            raise ImportError(
                "anthropic package required for Anthropic LLM explanations. Install with: pip install barb-phish[llm]"
            )
        self._client = anthropic.Anthropic(api_key=api_key)
        self._model = model

    def explain(self, result: AnalysisResult, send_url: bool = True) -> str:
        """Generate an explanation using Anthropic Claude."""
        _detector = PromptInjectionDetector()
        signals_text = "\n".join(
            f"  [{s.severity.value}] {s.analyzer}: {_detector.sanitize(s.detail, field_name='signal.detail')}"
            for s in result.signals
        )
        defanged_url = (
            _detector.sanitize(result.defanged_url, field_name="url", is_ioc_field=True) if send_url else None
        )
        user_prompt = build_prompt(
            verdict=result.verdict.value,
            risk_score=result.risk_score,
            signals_text=signals_text,
            defanged_url=defanged_url,
        )

        return anthropic_complete(
            client=self._client,
            model=self._model,
            max_tokens=512,
            system=SYSTEM_PROMPT,
            user=user_prompt,
            extract="index0",
        )


class OpenAIExplainer:
    """Explanation provider using OpenAI API."""

    def __init__(self, api_key: str, model: str = "gpt-4o-mini") -> None:
        try:
            import openai
        except ImportError:
            raise ImportError(
                "openai package required for OpenAI LLM explanations. Install with: pip install barb-phish[llm]"
            )
        self._client = openai.OpenAI(api_key=api_key)
        self._model = model

    def explain(self, result: AnalysisResult, send_url: bool = True) -> str:
        """Generate an explanation using OpenAI."""
        _detector = PromptInjectionDetector()
        signals_text = "\n".join(
            f"  [{s.severity.value}] {s.analyzer}: {_detector.sanitize(s.detail, field_name='signal.detail')}"
            for s in result.signals
        )
        defanged_url = (
            _detector.sanitize(result.defanged_url, field_name="url", is_ioc_field=True) if send_url else None
        )
        user_prompt = build_prompt(
            verdict=result.verdict.value,
            risk_score=result.risk_score,
            signals_text=signals_text,
            defanged_url=defanged_url,
        )

        return openai_complete(
            client=self._client,
            model=self._model,
            max_tokens=512,
            system=SYSTEM_PROMPT,
            user=user_prompt,
        )


class OllamaExplainer:
    """Explanation provider using a local Ollama server.

    Privacy-positive: all requests go to a local Ollama instance.
    No API key required; no data leaves the host.
    Uses stdlib urllib — no extra dependencies.
    """

    _TIMEOUT = 60  # seconds — local models can be slow

    def __init__(self, host: str = "http://localhost:11434", model: str = "llama3.1") -> None:
        self._host = host.rstrip("/")
        self._model = model

    def explain(self, result: AnalysisResult, send_url: bool = True) -> str:
        """Generate an explanation using the local Ollama server."""
        _detector = PromptInjectionDetector()
        signals_text = "\n".join(
            f"  [{s.severity.value}] {s.analyzer}: {_detector.sanitize(s.detail, field_name='signal.detail')}"
            for s in result.signals
        )
        defanged_url = (
            _detector.sanitize(result.defanged_url, field_name="url", is_ioc_field=True) if send_url else None
        )
        user_prompt = build_prompt(
            verdict=result.verdict.value,
            risk_score=result.risk_score,
            signals_text=signals_text,
            defanged_url=defanged_url,
        )

        try:
            response_text = ollama_generate(
                base_url=self._host,
                model=self._model,
                system=SYSTEM_PROMPT,
                user=user_prompt,
                timeout=self._TIMEOUT,
                system_mode="field",
            )
            return response_text.strip()
        except (urllib.error.URLError, OSError) as exc:
            raise RuntimeError(f"Ollama request failed (is `ollama serve` running at {self._host}?): {exc}") from exc
        except (json.JSONDecodeError, KeyError) as exc:
            raise RuntimeError(f"Ollama request failed (is `ollama serve` running at {self._host}?): {exc}") from exc
