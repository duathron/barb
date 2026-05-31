"""Tests for JSON and CSV export."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from barb.models import (
    AnalysisResult,
    ParsedURL,
    RiskVerdict,
    Signal,
    SignalSeverity,
)
from barb.output.export import to_csv, to_json, to_json_list, to_ndjson, to_stix


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


# ---------------------------------------------------------------------------
# NDJSON tests
# ---------------------------------------------------------------------------


def test_to_ndjson_line_count():
    results = [_make_result(url="https://a.com"), _make_result(url="https://b.com")]
    output = to_ndjson(results)
    lines = [line for line in output.split("\n") if line]
    assert len(lines) == 2


def test_to_ndjson_each_line_is_valid_json():
    results = [
        _make_result(url="https://a.com", verdict=RiskVerdict.SAFE),
        _make_result(url="https://b.com", verdict=RiskVerdict.PHISHING, score=15.0),
    ]
    output = to_ndjson(results)
    for line in output.strip().split("\n"):
        data = json.loads(line)
        assert "url" in data
        assert "verdict" in data


def test_to_ndjson_no_indent():
    result = _make_result()
    output = to_ndjson([result])
    line = output.strip()
    # Compact JSON has no newlines within the object
    assert "\n" not in line


def test_to_ndjson_trailing_newline():
    output = to_ndjson([_make_result()])
    assert output.endswith("\n")


def test_to_ndjson_defang_true():
    result = _make_result(url="https://example.com")
    output = to_ndjson([result], defang=True)
    data = json.loads(output.strip())
    # defanged_url should differ from url (contains hxxps / [.])
    assert data["defanged_url"] != data["url"]


def test_to_ndjson_defang_false():
    result = _make_result(url="https://example.com")
    output = to_ndjson([result], defang=False)
    data = json.loads(output.strip())
    assert data["defanged_url"] == "https://example.com"


def test_to_ndjson_single_result():
    result = _make_result(url="https://only.com")
    output = to_ndjson([result])
    lines = [line for line in output.split("\n") if line]
    assert len(lines) == 1
    assert json.loads(lines[0])["url"] == "https://only.com"


# ---------------------------------------------------------------------------
# STIX 2.1 tests
# ---------------------------------------------------------------------------


def _make_result_tz(
    url: str,
    verdict: RiskVerdict,
    score: float = 5.0,
    signals: list[Signal] | None = None,
) -> AnalysisResult:
    """Make a result with a timezone-aware analyzed_at for STIX tests."""
    return AnalysisResult(
        url=url,
        defanged_url=url.replace("https", "hxxps").replace(".", "[.]"),
        parsed_url=ParsedURL(original=url, scheme="https", host=url.split("/")[2], path="/"),
        signals=signals or [],
        risk_score=score,
        verdict=verdict,
        analyzed_at=datetime(2026, 3, 17, 12, 0, 0, tzinfo=timezone.utc),
    )


def test_to_stix_bundle_structure():
    results = [_make_result_tz("https://evil.tk/a", RiskVerdict.PHISHING)]
    bundle = json.loads(to_stix(results))
    assert bundle["type"] == "bundle"
    assert bundle["id"].startswith("bundle--")
    assert isinstance(bundle["objects"], list)


def test_to_stix_skips_safe_and_low_risk():
    results = [
        _make_result_tz("https://safe.com", RiskVerdict.SAFE, score=0.0),
        _make_result_tz("https://low.com", RiskVerdict.LOW_RISK, score=1.0),
    ]
    bundle = json.loads(to_stix(results))
    assert bundle["objects"] == []


def test_to_stix_includes_suspicious_high_risk_phishing():
    results = [
        _make_result_tz("https://sus.tk", RiskVerdict.SUSPICIOUS, score=5.0),
        _make_result_tz("https://high.tk", RiskVerdict.HIGH_RISK, score=8.0),
        _make_result_tz("https://evil.tk/pay", RiskVerdict.PHISHING, score=15.0),
    ]
    bundle = json.loads(to_stix(results))
    assert len(bundle["objects"]) == 3


def test_to_stix_indicator_fields():
    results = [_make_result_tz("https://phish.tk/login", RiskVerdict.PHISHING)]
    obj = json.loads(to_stix(results))["objects"][0]
    assert obj["type"] == "indicator"
    assert obj["spec_version"] == "2.1"
    assert obj["pattern_type"] == "stix"
    assert obj["pattern_version"] == "2.1"
    assert "malicious-activity" in obj["indicator_types"]
    assert "phishing" in obj["indicator_types"]
    assert obj["confidence"] == 95


def test_to_stix_phishing_not_in_indicator_types_for_suspicious():
    results = [_make_result_tz("https://sus.tk", RiskVerdict.SUSPICIOUS)]
    obj = json.loads(to_stix(results))["objects"][0]
    assert "phishing" not in obj["indicator_types"]
    assert obj["confidence"] == 50


def test_to_stix_high_risk_confidence():
    results = [_make_result_tz("https://bad.tk", RiskVerdict.HIGH_RISK)]
    obj = json.loads(to_stix(results))["objects"][0]
    assert obj["confidence"] == 75


def test_to_stix_pattern_contains_real_url():
    url = "https://evil.tk/verify"
    results = [_make_result_tz(url, RiskVerdict.PHISHING)]
    obj = json.loads(to_stix(results))["objects"][0]
    assert url in obj["pattern"]
    assert obj["pattern"] == f"[url:value = '{url}']"


def test_to_stix_pattern_escapes_single_quote():
    url = "https://evil.tk/it's"
    results = [_make_result_tz(url, RiskVerdict.PHISHING)]
    obj = json.loads(to_stix(results))["objects"][0]
    assert "it''s" in obj["pattern"]


def test_to_stix_deterministic_id():
    url = "https://evil.tk/verify"
    results = [_make_result_tz(url, RiskVerdict.PHISHING)]
    bundle1 = json.loads(to_stix(results))
    bundle2 = json.loads(to_stix(results))
    assert bundle1["objects"][0]["id"] == bundle2["objects"][0]["id"]
    expected_id = "indicator--" + str(uuid.uuid5(uuid.NAMESPACE_URL, url))
    assert bundle1["objects"][0]["id"] == expected_id


def test_to_stix_uses_real_url_not_defanged():
    url = "https://evil.tk/verify"
    results = [_make_result_tz(url, RiskVerdict.PHISHING)]
    obj = json.loads(to_stix(results))["objects"][0]
    # Must contain the real URL, not a defanged variant
    assert "hxxps" not in obj["pattern"]
    assert "[.]" not in obj["pattern"]


def test_to_stix_empty_bundle_when_no_qualifying_results():
    results: list[AnalysisResult] = []
    bundle = json.loads(to_stix(results))
    assert bundle["type"] == "bundle"
    assert bundle["objects"] == []


def test_to_stix_mixed_verdicts_only_qualifying_included():
    results = [
        _make_result_tz("https://safe.com", RiskVerdict.SAFE, score=0.0),
        _make_result_tz("https://evil.tk", RiskVerdict.PHISHING, score=15.0),
        _make_result_tz("https://low.com", RiskVerdict.LOW_RISK, score=1.0),
    ]
    bundle = json.loads(to_stix(results))
    assert len(bundle["objects"]) == 1
    assert "evil.tk" in bundle["objects"][0]["pattern"]
