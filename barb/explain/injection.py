"""Prompt-injection detection for attacker-influenced strings in barb prompts.

Pattern set + detect engine come from shipwright_kit.security.injection (shared
with sift + vex). barb adds string-level sanitize() for prompt insertion — the
phishing URL and analyzer signal details are attacker-influenceable and must be
redacted before they reach the LLM prompt. Mirrors vex/ai/injection_detector.py.
"""

from __future__ import annotations

import logging

from shipwright_kit.security.injection import (
    PromptInjectionDetector as _CoreDetector,
)
from shipwright_kit.security.injection import SeverityLevel

__all__ = ["PromptInjectionDetector"]

logger = logging.getLogger(__name__)


class PromptInjectionDetector(_CoreDetector):
    """Shared detector + barb's prompt-insertion sanitize()."""

    def sanitize(
        self,
        value: str,
        field_name: str = "",
        *,
        is_ioc_field: bool = False,
    ) -> str:
        findings = self.detect(value, field_name=field_name, is_ioc_field=is_ioc_field)
        if not findings:
            return value
        for f in findings:
            logger.warning(
                "Prompt injection %s in field %r: pattern=%s preview=%r",
                f.severity.name,
                field_name or "<unknown>",
                f.pattern_type,
                f.value_preview,
            )
        critical = [f for f in findings if f.severity == SeverityLevel.CRITICAL]
        if critical:
            return critical[0].redaction
        return value
