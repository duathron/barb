"""Tests for JSON and CSV export."""

from __future__ import annotations

import csv
import io
import json
import uuid
from datetime import datetime, timezone

import pytest

from barb.models import (
    AnalysisResult,
    ParsedURL,
    RiskVerdict,
    Signal,
    SignalSeverity,
)
from barb.output import export
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


def _stix_pattern(url: str) -> str:
    return json.loads(to_stix([_make_result_tz(url, RiskVerdict.PHISHING)]))["objects"][0]["pattern"]


def test_stix_pattern_escapes_single_quote_with_backslash():
    assert _stix_pattern("http://e.example/it's") == r"[url:value = 'http://e.example/it\'s']"


def test_stix_pattern_escapes_backslash():
    assert _stix_pattern("http://e.example/a\\b") == r"[url:value = 'http://e.example/a\\b']"


def test_stix_pattern_injection_payload_is_one_literal():
    url = "http://e.example/x'] OR [url:value = 'y"
    assert _stix_pattern(url) == r"[url:value = 'http://e.example/x\'] OR [url:value = \'y']"


_STIX_URLS = [
    "http://e.example/it's",
    "http://e.example/a\\b",
    "http://e.example/x'] OR [url:value = 'y",
    "http://e.example/trailing\\",
]


@pytest.mark.parametrize("url", _STIX_URLS)
def test_stix_pattern_validates(url):
    validator = pytest.importorskip("stix2patterns.validator")
    assert validator.run_validator(_stix_pattern(url)) == []


def test_stix_validator_rejects_the_old_doubled_quote_form():
    """Vacuity guard: the validator must actually fail on the previous escaping."""
    validator = pytest.importorskip("stix2patterns.validator")
    old_form = "[url:value = '" + "http://e.example/it's".replace("'", "''") + "']"
    assert validator.run_validator(old_form) != []
    injected = "[url:value = '" + "http://e.example/x'] OR [url:value = 'y".replace("'", "''") + "']"
    assert validator.run_validator(injected) != []


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


# --- CSV formula neutralisation ------------------------------------------------


def _csv_row(**fields) -> dict[str, str]:
    result = _make_result(**{k: v for k, v in fields.items() if k in ("url",)})
    if "defanged_url" in fields:
        result = result.model_copy(update={"defanged_url": fields["defanged_url"]})
    if "explanation" in fields:
        result = result.model_copy(update={"explanation": fields["explanation"]})
    rows = list(csv.DictReader(io.StringIO(to_csv([result]))))
    assert len(rows) == 1
    return rows[0]


@pytest.mark.parametrize("lead", ["=", "+", "-", "@"])
@pytest.mark.parametrize("column", ["url", "defanged_url", "explanation"])
def test_csv_formula_cells_are_neutralized(lead, column):
    original = f'{lead}HYPERLINK("http://x.example","c")'
    cell = _csv_row(**{column: original})[column]
    assert cell.startswith("'")
    assert cell[1:] == original


@pytest.mark.parametrize("lead", ["=", "+", "-", "@", "\t", "\r", "\n"])
def test_csv_safe_prefixes_every_trigger_character(lead):
    assert export._csv_safe(lead + "x") == "'" + lead + "x"


def test_csv_empty_cells_unchanged():
    assert export._csv_safe("") == ""
    row = _csv_row()
    assert row["explanation"] == ""


def test_csv_plain_cells_unchanged():
    row = _csv_row(url="https://example.com/a?b=c", explanation="Looks fine.")
    assert row["url"] == "https://example.com/a?b=c"
    assert row["explanation"] == "Looks fine."


def test_csv_numeric_cells_not_prefixed():
    signals = [Signal(analyzer="tld", severity=SignalSeverity.MEDIUM, label="Bad TLD", detail=".tk")]
    result = _make_result(signals=signals, score=15.0, verdict=RiskVerdict.PHISHING)
    row = next(csv.DictReader(io.StringIO(to_csv([result]))))
    assert row["risk_score"] == "15.0"
    assert row["signal_count"] == "1"
    assert row["signals_summary"] == "MEDIUM:tld:Bad TLD"
