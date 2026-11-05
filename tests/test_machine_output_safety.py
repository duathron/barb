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
