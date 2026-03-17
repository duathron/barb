"""Tests for JSON and CSV export."""

from __future__ import annotations

import json
from datetime import datetime

from barb.models import (
    AnalysisResult,
    ParsedURL,
    RiskVerdict,
    Signal,
    SignalSeverity,
)
from barb.output.export import to_csv, to_json, to_json_list


def _make_result(
    url: str = "https://example.com",
    verdict: RiskVerdict = RiskVerdict.SAFE,
    score: float = 0.0,
    signals: list[Signal] | None = None,
) -> AnalysisResult:
    return AnalysisResult(
        url=url,
        defanged_url=url.replace("https", "hxxps").replace(".", "[.]"),
        parsed_url=ParsedURL(original=url, scheme="https", host="example.com", path="/"),
        signals=signals or [],
        risk_score=score,
        verdict=verdict,
        analyzed_at=datetime(2026, 3, 17, 12, 0, 0),
    )


def test_to_json_single():
    result = _make_result()
    output = to_json(result)
    data = json.loads(output)
    assert data["url"] == "https://example.com"
    assert data["verdict"] == "SAFE"
    assert data["risk_score"] == 0.0


def test_to_json_with_signals():
    signals = [
        Signal(analyzer="ip_url", severity=SignalSeverity.HIGH, label="IP URL", detail="Uses IP"),
    ]
    result = _make_result(signals=signals, score=3.0, verdict=RiskVerdict.LOW_RISK)
    data = json.loads(to_json(result))
    assert len(data["signals"]) == 1
    assert data["signals"][0]["analyzer"] == "ip_url"
    assert data["risk_score"] == 3.0


def test_to_json_list():
    results = [_make_result(url="https://a.com"), _make_result(url="https://b.com")]
    output = to_json_list(results)
    data = json.loads(output)
    assert isinstance(data, list)
    assert len(data) == 2
    assert data[0]["url"] == "https://a.com"
    assert data[1]["url"] == "https://b.com"


def test_to_csv_header_and_rows():
    signals = [
        Signal(analyzer="tld", severity=SignalSeverity.MEDIUM, label="Bad TLD", detail=".tk"),
    ]
    results = [_make_result(signals=signals, score=2.0, verdict=RiskVerdict.LOW_RISK)]
    output = to_csv(results)
    lines = output.strip().split("\n")
    assert len(lines) == 2  # header + 1 row
    assert "url" in lines[0]
    assert "verdict" in lines[0]
    assert "LOW_RISK" in lines[1]
    assert "tld" in lines[1]


def test_to_csv_multiple():
    results = [_make_result(url="https://a.com"), _make_result(url="https://b.com")]
    output = to_csv(results)
    lines = output.strip().split("\n")
    assert len(lines) == 3  # header + 2 rows
