from datetime import datetime, timezone

from rich.console import Console

from barb.models import AnalysisResult, ParsedURL, RiskVerdict


def _result_with_explanation(explanation: str) -> AnalysisResult:
    return AnalysisResult(
        url="http://evil.example/x",
        defanged_url="hxxp[://]evil[.]example/x",
        parsed_url=ParsedURL(original="http://evil.example/x", scheme="http", host="evil.example", path="/x"),
        signals=[],
        risk_score=15.0,
        verdict=RiskVerdict.PHISHING,
        explanation=explanation,
        analyzed_at=datetime.now(timezone.utc),
    )


def test_format_rich_escapes_explanation_markup(monkeypatch):
    from barb.output import formatter

    rec = Console(record=True, force_terminal=True, width=200)
    monkeypatch.setattr(formatter, "console", rec)  # module-level console (formatter.py:39)
    formatter.format_rich(_result_with_explanation("[red]spoof[/] \x1b]0;title\x07"))
    out = rec.export_text()
    assert "[red]" in out  # markup shown literally
    assert "\x1b]0;" not in out  # OSC stripped


def test_format_console_strips_control_keeps_brackets(capsys):
    from barb.output import formatter

    formatter.format_console(_result_with_explanation("[keep]brackets \x1b[31mansi\x1b[0m"))
    out = capsys.readouterr().out
    assert "[keep]brackets" in out  # plain print: brackets literal, no spurious backslash
    assert "\x1b[31m" not in out  # ANSI stripped
