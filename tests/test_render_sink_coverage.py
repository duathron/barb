"""Terminal render-sink coverage: attacker-controlled text must be neutralised
at every Rich and plain-text output sink, and every string field of the data
models must be classified so a new field cannot silently become a new sink.
"""

from __future__ import annotations

import io
import sys
import typing
from datetime import datetime, timezone

import pytest
import typer
from pydantic import create_model
from rich.console import Console
from rich.errors import MarkupError
from typer.testing import CliRunner

from barb.config import AppConfig
from barb.main import app
from barb.models import AnalysisResult, ParsedURL, RiskVerdict, Signal, SignalSeverity
from barb.output import formatter

runner = CliRunner()

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _signal(
    detail: str = "benign detail",
    analyzer: str = "lexical",
    label: str = "benign label",
) -> Signal:
    return Signal(analyzer=analyzer, severity=SignalSeverity.HIGH, label=label, detail=detail, weight=1.0)


def _result(
    url: str = "http://evil.example/x",
    defanged_url: str = "hxxp[://]evil[.]example/x",
    signals: list[Signal] | None = None,
    verdict: RiskVerdict = RiskVerdict.PHISHING,
) -> AnalysisResult:
    return AnalysisResult(
        url=url,
        defanged_url=defanged_url,
        parsed_url=ParsedURL(original=url, scheme="http", host="evil.example", path="/x"),
        signals=signals if signals is not None else [],
        risk_score=15.0,
        verdict=verdict,
        analyzed_at=datetime.now(timezone.utc),
    )


def _rich_capture(monkeypatch, *, terminal: bool) -> tuple[Console, io.StringIO]:
    buf = io.StringIO()
    rec = Console(record=True, file=buf, force_terminal=terminal, width=300)
    monkeypatch.setattr(formatter, "console", rec)
    return rec, buf


# ---------------------------------------------------------------------------
# a1-1 .. a1-6, a1-9, a1-10: concrete reproductions
# ---------------------------------------------------------------------------


def test_format_rich_url_markup_close_does_not_crash(monkeypatch):
    rec, _ = _rich_capture(monkeypatch, terminal=True)
    url = "http://evil.example/[/x]login"
    formatter.format_rich(_result(url=url, defanged_url=url), defang=False)  # MarkupError today
    assert "[/x]" in rec.export_text()


def test_cli_phishing_url_with_markup_keeps_exit_2():
    url = "http://paypal.secure-login.verify-account.update.xyz/login/account/verify.exe.zip?q=[/x]"
    res = runner.invoke(app, ["analyze", url, "-o", "rich", "--no-cache"])
    assert not isinstance(res.exception, MarkupError)
    assert res.exit_code == 2


def test_format_rich_link_markup_cannot_forge_osc8(monkeypatch):
    rec, buf = _rich_capture(monkeypatch, terminal=True)
    url = "http://evil.example/[link=http://good.example/x]click[/link]"
    formatter.format_rich(_result(url=url, defanged_url=url), defang=False)
    assert "\x1b]8;" not in buf.getvalue()
    assert "[link=" in rec.export_text()


def test_format_rich_and_console_strip_esc_in_url_and_detail(monkeypatch, capsys):
    from barb.main import _analyze_single

    result = _analyze_single("http://u\x1bc:pw@192.0.2.1/", AppConfig(), use_cache=False)
    _, buf = _rich_capture(monkeypatch, terminal=False)
    formatter.format_rich(result, defang=False)
    assert "\x1bc" not in buf.getvalue()
    formatter.format_console(result, defang=False)
    assert "\x1bc" not in capsys.readouterr().out


def test_batch_summary_cell_escapes_markup_and_esc(monkeypatch):
    _, buf = _rich_capture(monkeypatch, terminal=False)
    hostile = "[/x][link=http://a]b[/link]\x1b]0;t\x07\x1b[2A‮"
    formatter.format_batch_summary([_result(defanged_url=hostile), _result()])
    assert "\x1b" not in buf.getvalue()
    assert "‮" not in buf.getvalue()


def test_batch_error_line_strips_esc():
    # '[' makes urlparse raise ValueError: this IS the path that prints the
    # truncated `Error (<url[:80]>)` line.
    res = runner.invoke(app, ["analyze", "http://ok.example/", "http://ev\x1b[1Ail.example/", "--no-cache"], color=True)
    assert "\x1b[1A" not in res.output


_NFKC_URL = "http://a℀\x1bb.example/"  # NFKC turns U+2100 into 'a/c'; the ValueError text echoes the netloc


def test_single_error_line_strips_esc_from_exception_text():
    res = runner.invoke(app, ["analyze", _NFKC_URL, "--no-cache"], color=True)
    assert res.exit_code == 3
    assert "\x1b" not in res.output


def test_batch_error_line_strips_esc_from_exception_text():
    res = runner.invoke(app, ["analyze", "http://ok.example/", _NFKC_URL, "--no-cache"], color=True)
    assert "\x1b" not in res.output


def test_llm_provider_error_text_strips_esc(monkeypatch):
    from barb.main import _analyze_single, _explain

    cfg = AppConfig()
    cfg.explain.provider = "ollama"
    result = _analyze_single("http://ok.example/", cfg, use_cache=False)

    class _Boom:
        def __init__(self, *a, **k):
            raise RuntimeError("x\x1b]0;t\x07y")

    mini = typer.Typer()

    @mini.command()
    def go() -> None:
        _explain(result, cfg)

    import barb.explain.llm as llm

    monkeypatch.setattr(llm, "OllamaExplainer", _Boom)
    res = runner.invoke(mini, [], color=True)
    assert "EXPLANATION UNAVAILABLE" in res.output
    assert "\x1b" not in res.output


def test_banner_update_notice_strips_esc(monkeypatch, capsys):
    import barb.version_check as vc
    from barb.banner import show_banner

    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(vc, "check_for_update", lambda *a, **k: "9.9.9\x1b]0;t\x07\x1b[2A")
    show_banner(quiet=False, allowlist_check_enabled=False)
    err = capsys.readouterr().err
    assert "Update available" in err
    assert "\x1b" not in err


def test_hostile_cached_analyzer_cannot_forge_osc8(monkeypatch, capsys):
    hostile = "osint:[link=http://x/]a[/link]\x1bc"
    result = _result(signals=[_signal(analyzer=hostile)])
    rec, buf = _rich_capture(monkeypatch, terminal=True)
    formatter.format_rich(result, defang=False)
    assert "\x1b]8;" not in buf.getvalue()
    assert "[link" in rec.export_text()  # Analyzer column is 12 wide: the text is cut, not interpreted
    formatter.format_console(result, defang=False)
    out = capsys.readouterr().out
    assert "\x1b" not in out
    assert "osint:[link=http://x/]a[/link]c" in out


# ---------------------------------------------------------------------------
# a1-8: reachable (sink, field, defang) pairs x payloads
# ---------------------------------------------------------------------------

_PAYLOADS = {
    "close-tag": "[/x]",
    "link-tag": "[link=http://a]b[/link]",
    "osc": "\x1b]0;t\x07",
    "csi": "\x1b[2A",
    "bidi": "‮",
}

# Explicit reachable pairs. format_rich/format_console render defanged_url when
# defang=True and url when defang=False; batch summary renders defanged_url;
# the aggregate sinks render "analyzer: label" only.
_PAIRS = [
    ("format_rich", "url", False),
    ("format_rich", "defanged_url", True),
    ("format_rich", "signal.detail", True),
    ("format_rich", "signal.detail", False),
    ("format_rich", "signal.analyzer", True),
    ("format_rich", "signal.analyzer", False),
    ("format_console", "url", False),
    ("format_console", "defanged_url", True),
    ("format_console", "signal.detail", True),
    ("format_console", "signal.detail", False),
    ("format_console", "signal.analyzer", True),
    ("format_console", "signal.analyzer", False),
    ("format_batch_summary", "defanged_url", None),
    ("format_aggregate_summary", "signal.analyzer", None),
    ("format_aggregate_summary", "signal.label", None),
    ("format_console_aggregate_summary", "signal.analyzer", None),
    ("format_console_aggregate_summary", "signal.label", None),
]


def _build(field: str, payload: str) -> AnalysisResult:
    if field == "url":
        return _result(url="http://evil.example/" + payload)
    if field == "defanged_url":
        return _result(defanged_url=payload)
    if field == "signal.detail":
        return _result(signals=[_signal(detail=payload)])
    if field == "signal.analyzer":
        return _result(signals=[_signal(analyzer="a" + payload)])
    if field == "signal.label":
        return _result(signals=[_signal(label=payload)])
    raise AssertionError(field)


@pytest.mark.parametrize("payload_name", list(_PAYLOADS))
@pytest.mark.parametrize(("sink", "field", "defang"), _PAIRS)
def test_attacker_fields_safe_at_every_sink(monkeypatch, capsys, sink, field, defang, payload_name):
    payload = _PAYLOADS[payload_name]
    result = _build(field, payload)
    fn = getattr(formatter, sink)
    args: list = (
        [[result, result]] if "aggregate" in sink else ([[result]] if sink == "format_batch_summary" else [result])
    )
    kwargs = {} if defang is None else {"defang": defang}
    if sink in ("format_rich", "format_batch_summary", "format_aggregate_summary"):
        # non-terminal console: any ESC in the output is attacker-origin
        _, buf = _rich_capture(monkeypatch, terminal=False)
        fn(*args, **kwargs)
        out = buf.getvalue()
    else:
        fn(*args, **kwargs)
        out = capsys.readouterr().out
    assert "\x1b" not in out
    assert "‮" not in out
    if payload_name in ("close-tag", "link-tag"):
        # printable markup stays visible instead of being interpreted; the
        # 12-wide Analyzer column of the Rich table cuts long values
        needle = payload[:5] if (sink == "format_rich" and field == "signal.analyzer") else payload
        assert needle in out


# ---------------------------------------------------------------------------
# backslash fidelity of the Rich helper
# ---------------------------------------------------------------------------


def _url_cell(text: str) -> str:
    for line in text.splitlines():
        stripped = line.strip("│ ")
        if stripped.startswith("URL"):
            return stripped[len("URL") :].strip()
    raise AssertionError(f"no URL row in {text!r}")


def test_backslash_url_renders_verbatim(monkeypatch):
    rec, _ = _rich_capture(monkeypatch, terminal=False)
    url = "http://e.example/a\\b"
    formatter.format_rich(_result(url=url, defanged_url=url), defang=False)
    assert _url_cell(rec.export_text()) == "http://e.example/a\\b"


def test_trailing_backslash_is_doubled_known_open(monkeypatch):
    # Accepted known-open behaviour: rich.markup.escape doubles a TRAILING
    # backslash by design (cosmetic only; consistent with the other tools of
    # the fleet). This test documents it so a change is noticed.
    rec, _ = _rich_capture(monkeypatch, terminal=False)
    url = "http://e.example/x\\"
    formatter.format_rich(_result(url=url, defanged_url=url), defang=False)
    assert _url_cell(rec.export_text()) == "http://e.example/x\\\\"


def test_explanation_panel_backslash_and_markup(monkeypatch):
    rec, buf = _rich_capture(monkeypatch, terminal=True)
    result = _result()
    result.explanation = "path a\\b and [link=http://a]x[/link]"
    formatter.format_rich(result, defang=False)
    assert "\x1b]8;" not in buf.getvalue()
    text = rec.export_text()
    assert "a\\b" in text
    assert "a\\\\b" not in text
    assert "[link=http://a]x[/link]" in text


# ---------------------------------------------------------------------------
# kit floor: behavioural, not a version-number assertion
# ---------------------------------------------------------------------------


def test_safe_render_strips_format_and_tag_characters():
    from shipwright_kit.security.render import safe_render

    out = safe_render("a‮b\U000e0041c", escape_markup=False)
    assert "‮" not in out
    assert "\U000e0041" not in out


# ---------------------------------------------------------------------------
# a1-7: classification guard
# ---------------------------------------------------------------------------

ATTACKER_RENDERED = {
    "AnalysisResult.url",
    "AnalysisResult.defanged_url",
    "AnalysisResult.explanation",
    "AnalysisResult.explanation_provider",
    "Signal.analyzer",
    "Signal.label",
    "Signal.detail",
}
ATTACKER_UNRENDERED = {
    "ParsedURL.original",
    "ParsedURL.scheme",
    "ParsedURL.userinfo",
    "ParsedURL.host",
    "ParsedURL.path",
    "ParsedURL.query",
    "ParsedURL.fragment",
}
TRUSTED: set[str] = set()


def _is_str_annotation(annotation) -> bool:
    # identity-based: enums that subclass str must NOT count
    return annotation is str or str in typing.get_args(annotation)


def _unclassified_str_fields(models) -> list[str]:
    known = ATTACKER_RENDERED | ATTACKER_UNRENDERED | TRUSTED
    missing = []
    for model in models:
        for name, info in model.model_fields.items():
            qualified = f"{model.__name__}.{name}"
            if _is_str_annotation(info.annotation) and qualified not in known:
                missing.append(qualified)
    return missing


def test_every_str_field_is_classified():
    assert _unclassified_str_fields([AnalysisResult, ParsedURL, Signal]) == []


def test_classification_guard_detects_a_new_str_field():
    # mutation proof for the guard itself: a freshly added str field is flagged,
    # an enum (str subclass) field is not.
    Widened = create_model("Signal", __base__=Signal, extra_text=(str, ""), extra_opt=(typing.Optional[str], None))
    assert _unclassified_str_fields([Widened]) == ["Signal.extra_text", "Signal.extra_opt"]
