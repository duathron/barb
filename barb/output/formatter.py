"""Rich and console output formatting for barb analysis results."""

from __future__ import annotations

import re
from collections import Counter

from rich import box
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from shipwright_kit.security.render import safe_render

from ..models import AnalysisResult, RiskVerdict, SignalSeverity

_VERDICT_STYLE = {
    RiskVerdict.SAFE: "bold green",
    RiskVerdict.LOW_RISK: "bold blue",
    RiskVerdict.SUSPICIOUS: "bold yellow",
    RiskVerdict.HIGH_RISK: "bold rgb(255,165,0)",
    RiskVerdict.PHISHING: "bold red",
}

_VERDICT_ICON = {
    RiskVerdict.SAFE: "[green]\u2713 SAFE[/green]",
    RiskVerdict.LOW_RISK: "[blue]\u2713 LOW RISK[/blue]",
    RiskVerdict.SUSPICIOUS: "[yellow]\u26a0 SUSPICIOUS[/yellow]",
    RiskVerdict.HIGH_RISK: "[rgb(255,165,0)]\u26a0 HIGH RISK[/rgb(255,165,0)]",
    RiskVerdict.PHISHING: "[red]\u2717 PHISHING[/red]",
}

_SEVERITY_STYLE = {
    SignalSeverity.INFO: "dim",
    SignalSeverity.LOW: "blue",
    SignalSeverity.MEDIUM: "yellow",
    SignalSeverity.HIGH: "rgb(255,165,0)",
    SignalSeverity.CRITICAL: "bold red",
}

# emoji=False: ``:shortcode:`` text in an attacker URL must not become a glyph.
# The trusted UI markup uses literal glyphs only.
console = Console(emoji=False)
err_console = Console(stderr=True, emoji=False)


_LINE_BREAKS = re.compile(r"[\r\n\t\x0b\x0c\x85\u2028\u2029]")


def _collapse(value: object, single_line: bool) -> str:
    text = "" if value is None else str(value)
    return _LINE_BREAKS.sub(" ", text) if single_line else text


def _rich_safe(value: object, *, single_line: bool = True) -> str:
    """Neutralise attacker-controlled text for a Rich markup sink.

    Line breaks and tabs become one space first (log/verdict-row forging,
    CWE-117) unless ``single_line=False`` (multi-line explanation). Control,
    bidi and tag characters are then stripped by ``safe_render`` and Rich markup
    (``[/x]``, ``[link=...]``) is escaped with ``rich.markup.escape``.
    ``safe_render(escape_markup=True)`` is not used because it doubles every
    backslash. ``escape`` doubles a TRAILING backslash by design (cosmetic).

    Only attacker-derived values go through here; the trusted UI markup
    (``_VERDICT_ICON`` etc.) must never be passed through it.
    """
    return escape(safe_render(_collapse(value, single_line), escape_markup=False))


def _plain_safe(value: object, *, single_line: bool = True) -> str:
    """Neutralise attacker-controlled text for a plain-text sink."""
    return safe_render(_collapse(value, single_line), escape_markup=False)


def format_rich(result: AnalysisResult, defang: bool = True) -> None:
    """Print a single analysis result as a Rich panel with signal table."""
    url_display = result.defanged_url if defang else result.url

    # Header grid
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold cyan", no_wrap=True)
    grid.add_column()

    grid.add_row("URL", _rich_safe(url_display))
    grid.add_row("Verdict", _VERDICT_ICON.get(result.verdict, result.verdict.value))
    grid.add_row("Risk Score", f"[bold]{result.risk_score:.1f}[/bold]")

    # Build panel
    border_style = _VERDICT_STYLE.get(result.verdict, "white")
    console.print(Panel(grid, title="barb", border_style=border_style))

    # Signal table — for SAFE verdict, omit INFO-severity signals from non-osint analyzers.
    # Signals from osint:* analyzers are always shown (explicitly requested enrichment context).
    display_signals = result.signals
    if result.verdict == RiskVerdict.SAFE:
        display_signals = [
            s for s in result.signals if not (s.severity == SignalSeverity.INFO and not s.analyzer.startswith("osint:"))
        ]

    if display_signals:
        sig_table = Table(box=box.SIMPLE, show_edge=False, pad_edge=False)
        sig_table.add_column("Severity", style="bold", width=10)
        sig_table.add_column("Analyzer", style="cyan", width=12)
        sig_table.add_column("Finding")

        for signal in sorted(display_signals, key=lambda s: s.severity.points, reverse=True):
            sev_style = _SEVERITY_STYLE.get(signal.severity, "white")
            sig_table.add_row(
                Text(signal.severity.value, style=sev_style),
                _rich_safe(signal.analyzer),
                _rich_safe(signal.detail),
            )
        console.print(sig_table)
    elif result.signals and result.verdict == RiskVerdict.SAFE:
        # All signals were non-osint INFO — show clean placeholder
        console.print("[dim]No significant signals[/dim]")

    # Explanation. F2 cut-1 (2026-07-03 MeetUp): a degraded explanation (a
    # requested LLM provider failed) screams a loud banner instead of a
    # silent template — the verdict above is unaffected.
    if result.explanation_degraded:
        console.print()
        console.print(
            Panel(
                f"[bold red]⚠ EXPLANATION UNAVAILABLE[/bold red] — provider "
                f"'{_rich_safe(result.explanation_provider)}' failed. The verdict above is unaffected; "
                "no explanation was generated.",
                title="Explanation",
                border_style="red",
            )
        )
    elif result.explanation:
        console.print()
        console.print(Panel(_rich_safe(result.explanation, single_line=False), title="Explanation", border_style="dim"))

    console.print()


def format_console(result: AnalysisResult, defang: bool = True) -> None:
    """Print a single analysis result as plain text (no Rich markup)."""
    url_display = result.defanged_url if defang else result.url

    print(f"URL:      {_plain_safe(url_display)}")
    print(f"Verdict:  {result.verdict.value}")
    print(f"Score:    {result.risk_score:.1f}")

    if result.signals:
        print("Signals:")
        for signal in sorted(result.signals, key=lambda s: s.severity.points, reverse=True):
            print(f"  [{signal.severity.value:8s}] {_plain_safe(signal.analyzer):12s} {_plain_safe(signal.detail)}")

    # F2 cut-1 (2026-07-03 MeetUp): loud degraded banner, never a silent template.
    if result.explanation_degraded:
        print()
        print(
            f"⚠ EXPLANATION UNAVAILABLE — provider '{_plain_safe(result.explanation_provider)}' failed. "
            "The verdict above is unaffected; no explanation was generated."
        )
    elif result.explanation:
        print()
        print("Explanation:")
        print(_plain_safe(result.explanation, single_line=False))

    print()


def format_batch_summary(results: list[AnalysisResult]) -> None:
    """Print a summary table for batch analysis results."""
    table = Table(title="Batch Analysis Summary", box=box.ROUNDED)
    table.add_column("#", style="dim", width=4)
    table.add_column("URL", max_width=50)
    table.add_column("Verdict", width=14)
    table.add_column("Score", justify="right", width=8)
    table.add_column("Signals", justify="right", width=8)

    for i, result in enumerate(results, 1):
        verdict_display = _VERDICT_ICON.get(result.verdict, result.verdict.value)
        table.add_row(
            str(i),
            _rich_safe(result.defanged_url[:50]),
            verdict_display,
            f"{result.risk_score:.1f}",
            str(len(result.signals)),
        )

    console.print(table)
    console.print()


# Ordered verdict tiers for display (worst-first)
_VERDICT_ORDER = [
    RiskVerdict.PHISHING,
    RiskVerdict.HIGH_RISK,
    RiskVerdict.SUSPICIOUS,
    RiskVerdict.LOW_RISK,
    RiskVerdict.SAFE,
]


def format_aggregate_summary(
    results: list[AnalysisResult],
    threshold: int = 0,
) -> None:
    """Print an aggregated header block for N>1 batch results.

    Shows a verdict histogram, top signals across all URLs, and the share
    over *threshold*.  For N≤1 this is a no-op (single-URL path unchanged).

    Output goes to the module-level ``console`` (stdout).  Machine formats
    (JSON/NDJSON/CSV/pipe) never call this function.
    """
    if len(results) <= 1:
        return

    n = len(results)

    # --- Verdict histogram ---
    hist: Counter[RiskVerdict] = Counter(r.verdict for r in results)

    hist_table = Table(title=f"Aggregate Summary  ({n} URLs)", box=box.ROUNDED)
    hist_table.add_column("Verdict", width=14)
    hist_table.add_column("Count", justify="right", width=8)
    hist_table.add_column("Share", justify="right", width=8)

    for verdict in _VERDICT_ORDER:
        count = hist.get(verdict, 0)
        pct = count * 100 / n
        icon = _VERDICT_ICON.get(verdict, verdict.value)
        hist_table.add_row(icon, str(count), f"{pct:.0f}%")

    console.print(hist_table)

    # --- Threshold share ---
    if threshold > 0:
        over = sum(1 for r in results if r.risk_score >= threshold)
        pct_over = over * 100 / n
        console.print(f"  [bold]{over}[/bold] / {n} URLs exceeded threshold {threshold} ({pct_over:.0f}%)")
        console.print()

    # --- Top signals across all URLs ---
    signal_counts: Counter[str] = Counter()
    for r in results:
        for s in r.signals:
            signal_counts[f"{s.analyzer}: {s.label}"] += 1

    if signal_counts:
        top_n = min(5, len(signal_counts))
        sig_table = Table(title="Top Signals (batch-wide)", box=box.SIMPLE, show_edge=False)
        sig_table.add_column("Signal", style="cyan")
        sig_table.add_column("URLs affected", justify="right", width=14)

        for label, count in signal_counts.most_common(top_n):
            sig_table.add_row(_rich_safe(label), str(count))

        console.print(sig_table)
        console.print()


def format_console_aggregate_summary(
    results: list[AnalysisResult],
    threshold: int = 0,
) -> None:
    """Print a plain-text aggregated summary block for N>1 results.

    For N≤1 this is a no-op (single-URL path unchanged).
    Output goes to stdout via plain ``print``.
    """
    if len(results) <= 1:
        return

    n = len(results)
    hist: Counter[RiskVerdict] = Counter(r.verdict for r in results)

    print("=== Batch Aggregate Summary ===")
    print(f"Total URLs: {n}")
    print("Verdict breakdown:")
    for verdict in _VERDICT_ORDER:
        count = hist.get(verdict, 0)
        pct = count * 100 / n
        print(f"  {verdict.value:12s} {count:4d}  ({pct:.0f}%)")

    if threshold > 0:
        over = sum(1 for r in results if r.risk_score >= threshold)
        pct_over = over * 100 / n
        print(f"Over threshold {threshold}: {over} / {n} ({pct_over:.0f}%)")

    # Top 5 signals
    signal_counts: Counter[str] = Counter()
    for r in results:
        for s in r.signals:
            signal_counts[f"{s.analyzer}: {s.label}"] += 1

    if signal_counts:
        top_n = min(5, len(signal_counts))
        print("Top signals:")
        for label, count in signal_counts.most_common(top_n):
            print(f"  {count:3d}x  {_plain_safe(label)}")

    print()
