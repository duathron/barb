"""LLM-based explanation providers — Anthropic and OpenAI support."""

from __future__ import annotations

from ..models import AnalysisResult
from .prompt import SYSTEM_PROMPT, build_prompt


class AnthropicExplainer:
    """Explanation provider using Anthropic Claude API."""

    def __init__(self, api_key: str, model: str = "claude-sonnet-4-20250514") -> None:
        try:
            import anthropic
        except ImportError:
            raise ImportError(
                "anthropic package required for Anthropic LLM explanations. "
                "Install with: pip install barb-phish[llm]"
            )
        self._client = anthropic.Anthropic(api_key=api_key)
        self._model = model

    def explain(self, result: AnalysisResult, send_url: bool = True) -> str:
        """Generate an explanation using Anthropic Claude."""
        signals_text = "\n".join(
            f"  [{s.severity.value}] {s.analyzer}: {s.detail}" for s in result.signals
        )
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
                "openai package required for OpenAI LLM explanations. "
                "Install with: pip install barb-phish[llm]"
            )
        self._client = openai.OpenAI(api_key=api_key)
        self._model = model

    def explain(self, result: AnalysisResult, send_url: bool = True) -> str:
        """Generate an explanation using OpenAI."""
        signals_text = "\n".join(
            f"  [{s.severity.value}] {s.analyzer}: {s.detail}" for s in result.signals
        )
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
