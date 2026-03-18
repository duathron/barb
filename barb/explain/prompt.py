"""Prompt templates for LLM-based explanations."""

from __future__ import annotations

SYSTEM_PROMPT = (
    "You are a security analyst assistant. Given a URL analysis result with detected"
    " phishing indicators, provide a concise, actionable explanation for a SOC analyst.\n"
    "\nYour explanation should:\n"
    "1. Summarize what was detected and why it matters\n"
    "2. Explain the risk in plain language\n"
    "3. Recommend specific next steps\n"
    "\nKeep your response under 200 words. Be direct and technical but accessible."
)

USER_PROMPT_TEMPLATE = """Analyze this URL assessment:

Verdict: {verdict} (Risk Score: {risk_score})
{url_line}
Signals detected:
{signals}

Provide a concise analyst-facing explanation."""


def build_prompt(verdict: str, risk_score: float, signals_text: str, defanged_url: str | None = None) -> str:
    """Build the user prompt for the LLM."""
    url_line = f"URL: {defanged_url}" if defanged_url else ""
    return USER_PROMPT_TEMPLATE.format(
        verdict=verdict,
        risk_score=risk_score,
        url_line=url_line,
        signals=signals_text,
    )
