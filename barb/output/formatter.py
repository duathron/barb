"""Rich and console output formatting for barb analysis results."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

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

console = Console()
err_console = Console(stderr=True)


def format_rich(result: AnalysisResult, defang: bool = True) -> None:
    """Print a single analysis result as a Rich panel with signal table."""
    url_display = result.defanged_url if defang else result.url

    # Header grid
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold cyan", no_wrap=True)
    grid.add_column()

    grid.add_row("URL", url_display)
    grid.add_row("Verdict", _VERDICT_ICON.get(result.verdict, result.verdict.value))
    grid.add_row("Risk Score", f"[bold]{result.risk_score:.1f}[/bold]")

    # Build panel
    border_style = _VERDICT_STYLE.get(result.verdict, "white")
    console.print(Panel(grid, title="barb", border_style=border_style))

    # Signal table
    if result.signals:
        sig_table = Table(box=box.SIMPLE, show_edge=False, pad_edge=False)
        sig_table.add_column("Severity", style="bold", width=10)
        sig_table.add_column("Analyzer", style="cyan", width=12)
        sig_table.add_column("Finding")

        for signal in sorted(result.signals, key=lambda s: s.severity.points, reverse=True):
            sev_style = _SEVERITY_STYLE.get(signal.severity, "white")
            sig_table.add_row(
                Text(signal.severity.value, style=sev_style),
                signal.analyzer,
                signal.detail,
            )
        console.print(sig_table)

    # Explanation
    if result.explanation:
        console.print()
        console.print(Panel(result.explanation, title="Explanation", border_style="dim"))

    console.print()


def format_console(result: AnalysisResult, defang: bool = True) -> None:
    """Print a single analysis result as plain text (no Rich markup)."""
    url_display = result.defanged_url if defang else result.url

    print(f"URL:      {url_display}")
    print(f"Verdict:  {result.verdict.value}")
    print(f"Score:    {result.risk_score:.1f}")

    if result.signals:
        print("Signals:")
        for signal in sorted(result.signals, key=lambda s: s.severity.points, reverse=True):
            print(f"  [{signal.severity.value:8s}] {signal.analyzer:12s} {signal.detail}")

    if result.explanation:
        print()
        print("Explanation:")
        print(result.explanation)

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
            result.defanged_url[:50],
            verdict_display,
            f"{result.risk_score:.1f}",
            str(len(result.signals)),
        )

    console.print(table)
    console.print()
