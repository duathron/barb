"""Tests for explanation providers."""

from __future__ import annotations

from datetime import datetime

from phishing_analyzer.explain.template import TemplateExplainer
from phishing_analyzer.models import (
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
        parsed_url=ParsedURL(original="http://192.168.1.1/paypal", scheme="http", host="192.168.1.1", path="/paypal", is_ip=True),
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
