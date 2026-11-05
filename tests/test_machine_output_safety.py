"""Machine formats printed to stdout must not carry raw terminal control characters.

A URL is attacker-controlled; ``barb analyze -o json|ndjson|csv|stix`` is often run
interactively, so an unescaped ESC / C1 / bidi / tag character in a value reaches
the terminal (CWE-150). JSON-family output is escaped to ``\\uXXXX``; CSV cells
are stripped.
"""

from __future__ import annotations

import csv
import io
import json

import pytest
from typer.testing import CliRunner

from barb.main import app

_PHISH = "http://paypal.secure-login.verify-account.update.xyz/login/account/verify.exe.zip"
_HOSTILE = "\x1b]0;PWN\x07\x9b2J‮\U000e0041x"
_FORBIDDEN = ["\x1b", "\x07", "\x9b", "‮", "\U000e0041"]


def _run(url: str, fmt: str):
    res = CliRunner().invoke(app, ["analyze", url, "-o", fmt, "-q"], color=True)
    assert res.exit_code in (0, 1, 2), res.output
    return res.output


@pytest.mark.parametrize("fmt", ["json", "ndjson", "stix", "csv"])
def test_hostile_url_leaves_no_raw_control_characters_on_stdout(fmt):
    out = _run(_PHISH + "/" + _HOSTILE + "?q=1", fmt)
    assert "paypal" in out  # the sample really produced output
    for bad in _FORBIDDEN:
        assert bad not in out, (fmt, repr(bad))


def test_json_list_two_urls_leaves_no_raw_control_characters():
    res = CliRunner().invoke(
        app,
        ["analyze", _PHISH + "/" + _HOSTILE, _PHISH + "/b\u00fc", "-o", "json", "-q"],
        color=True,
    )
    assert res.exit_code in (0, 1, 2), res.output
    data = json.loads(res.output)
    assert isinstance(data, list) and len(data) == 2
    for bad in _FORBIDDEN:
        assert bad not in res.output, repr(bad)
    assert data[0]["url"] == _PHISH + "/" + _HOSTILE


@pytest.mark.parametrize("fmt", ["json", "ndjson"])
def test_json_output_still_parses_and_round_trips_escaped_value(fmt):
    url = _PHISH + "/" + _HOSTILE
    out = _run(url, fmt)
    data = json.loads(out.splitlines()[0] if fmt == "ndjson" else out)
    assert data["url"] == url


def test_stix_hostile_url_pattern_round_trips():
    url = _PHISH + "/" + _HOSTILE
    obj = json.loads(_run(url, "stix"))["objects"][0]
    assert url.replace("\\", "\\\\").replace("'", "\\'") in obj["pattern"]


@pytest.mark.parametrize("fmt", ["json", "ndjson", "stix"])
def test_idn_url_still_round_trips_through_json(fmt):
    url = "http://paypal.secure-login.verify-account.update.xyz/login/account/verify.exe.zip/über"
    out = _run(url, fmt)
    parsed = json.loads(out.splitlines()[0] if fmt == "ndjson" else out)
    if fmt == "stix":
        assert "über" in parsed["objects"][0]["pattern"]
    else:
        assert parsed["url"] == url


def test_csv_hostile_url_is_single_line_and_clean():
    out = _run(_PHISH + "/p\r\nVerdict: SAFE\t" + _HOSTILE, "csv")
    rows = list(csv.reader(io.StringIO(out)))
    assert len(rows) == 2  # header + exactly one data row
    for cell in rows[1]:
        assert "\r" not in cell and "\n" not in cell


def test_csv_signal_summary_cell_is_cleaned():
    from datetime import datetime, timezone

    from barb.models import AnalysisResult, ParsedURL, RiskVerdict, Signal, SignalSeverity
    from barb.output.export import to_csv

    sig = Signal(analyzer="osint:x", severity=SignalSeverity.LOW, label="a\x1b]0;t\x07b‮", detail="d")
    result = AnalysisResult(
        url="http://e.example/",
        defanged_url="hxxp[://]e[.]example/",
        parsed_url=ParsedURL(original="http://e.example/", scheme="http", host="e.example", path="/"),
        signals=[sig],
        risk_score=1.0,
        verdict=RiskVerdict.LOW_RISK,
        analyzed_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    out = to_csv([result])
    assert "\x1b" not in out and "‮" not in out and "\x07" not in out


def test_to_json_list_is_ascii_only():
    from datetime import datetime, timezone

    from barb.models import AnalysisResult, ParsedURL, RiskVerdict
    from barb.output.export import to_json_list

    u = "http://e.example/\u202e\x9b\U000e0041\u00fc"
    r = AnalysisResult(
        url=u,
        defanged_url=u,
        parsed_url=ParsedURL(original=u, scheme="http", host="e.example", path="/"),
        signals=[],
        risk_score=0.0,
        verdict=RiskVerdict.SAFE,
        analyzed_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    out = to_json_list([r, r])
    assert out.isascii()
    assert json.loads(out)[0]["url"] == u


_TWO = [_PHISH + "/a" + _HOSTILE, _PHISH + "/b\u00fc" + _HOSTILE]


@pytest.mark.parametrize("fmt", ["json", "ndjson", "csv", "stix"])
def test_two_urls_leave_no_raw_control_characters(fmt):
    res = CliRunner().invoke(app, ["analyze", *_TWO, "-o", fmt, "-q"], color=True)
    assert res.exit_code in (0, 1, 2), res.output
    for bad in _FORBIDDEN:
        assert bad not in res.output, (fmt, repr(bad))


def _csv_result(**kw):
    from datetime import datetime, timezone

    from barb.models import AnalysisResult, ParsedURL, RiskVerdict

    base = dict(
        url="http://e.example/",
        defanged_url="hxxp[://]e[.]example/",
        parsed_url=ParsedURL(original="http://e.example/", scheme="http", host="e.example", path="/"),
        signals=[],
        risk_score=1.0,
        verdict=RiskVerdict.LOW_RISK,
        analyzed_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    base.update(kw)
    return AnalysisResult(**base)


@pytest.mark.parametrize("lead", ["\x1b=x", "\u200b=x", "\x00+x", "\ufeff@x"])
@pytest.mark.parametrize("column", ["url", "defanged_url", "explanation"])
def test_csv_control_prefixed_formula_is_neutralized(lead, column):
    """Sanitise first, then test the trigger: a stripped lead must not hide a formula."""
    from barb.output.export import to_csv

    row = next(csv.DictReader(io.StringIO(to_csv([_csv_result(**{column: lead})]))))
    assert row[column].startswith("'"), repr(row[column])


def test_csv_hostile_explanation_is_single_clean_line():
    from barb.output.export import to_csv

    out = to_csv([_csv_result(explanation="ok\x1b]0;t\x07\nVerdict: SAFE\u202e")])
    rows = list(csv.reader(io.StringIO(out)))
    assert len(rows) == 2
    assert "\n" not in rows[1][6] and "\x1b" not in out and "\u202e" not in out


def test_csv_signal_label_newline_stays_single_line():
    from barb.models import Signal, SignalSeverity
    from barb.output.export import to_csv

    sig = Signal(analyzer="a", severity=SignalSeverity.LOW, label="x\nVerdict: SAFE", detail="d")
    rows = list(csv.reader(io.StringIO(to_csv([_csv_result(signals=[sig])]))))
    assert len(rows) == 2 and "\n" not in rows[1][5]
