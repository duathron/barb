"""LLM-based explanation providers — Anthropic, OpenAI, and Ollama support."""

from __future__ import annotations

import json
import urllib.error
import urllib.request

from ..models import AnalysisResult
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
        signals_text = "\n".join(f"  [{s.severity.value}] {s.analyzer}: {s.detail}" for s in result.signals)
        defanged_url = result.defanged_url if send_url else None
        user_prompt = build_prompt(
            verdict=result.verdict.value,
            risk_score=result.risk_score,
            signals_text=signals_text,
            defanged_url=defanged_url,
        )

        response = self._client.messages.create(
            model=self._model,
            max_tokens=512,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_prompt}],
        )
        return response.content[0].text


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
        signals_text = "\n".join(f"  [{s.severity.value}] {s.analyzer}: {s.detail}" for s in result.signals)
        defanged_url = result.defanged_url if send_url else None
        user_prompt = build_prompt(
            verdict=result.verdict.value,
            risk_score=result.risk_score,
            signals_text=signals_text,
            defanged_url=defanged_url,
        )

        response = self._client.chat.completions.create(
            model=self._model,
            max_tokens=512,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
        )
        return response.choices[0].message.content or ""


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
        signals_text = "\n".join(f"  [{s.severity.value}] {s.analyzer}: {s.detail}" for s in result.signals)
        defanged_url = result.defanged_url if send_url else None
        user_prompt = build_prompt(
            verdict=result.verdict.value,
            risk_score=result.risk_score,
            signals_text=signals_text,
            defanged_url=defanged_url,
        )

        payload = json.dumps(
            {
                "model": self._model,
                "system": SYSTEM_PROMPT,
                "prompt": user_prompt,
                "stream": False,
            }
        ).encode()

        try:
            req = urllib.request.Request(
                f"{self._host}/api/generate",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=self._TIMEOUT) as resp:
                body = json.loads(resp.read().decode())
            return body["response"].strip()
        except (urllib.error.URLError, OSError) as exc:
            raise RuntimeError(f"Ollama request failed (is `ollama serve` running at {self._host}?): {exc}") from exc
        except (json.JSONDecodeError, KeyError) as exc:
            raise RuntimeError(f"Ollama request failed (is `ollama serve` running at {self._host}?): {exc}") from exc
