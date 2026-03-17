"""Typer CLI application for barb."""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Optional

import typer

from barb import __version__
from barb.banner import show_banner
from barb.config import AppConfig, load_config
from barb.defang import defang_url
from barb.models import AnalysisResult, RiskVerdict
from barb.scoring import compute_risk_score, determine_verdict
from barb.url_parser import parse_url

app = typer.Typer(
    name="barb",
    help="Heuristic phishing URL analyzer for SOC/DFIR workflows.",
    no_args_is_help=True,
)

# ---------------------------------------------------------------------------
# Analyzer registry — lazily instantiated
# ---------------------------------------------------------------------------

_analyzers = None


def _get_analyzers() -> list:
    """Lazily instantiate all 8 heuristic analyzers."""
    global _analyzers
    if _analyzers is None:
        from barb.analyzers.brand import BrandAnalyzer
        from barb.analyzers.encoding import EncodingAnalyzer
        from barb.analyzers.entropy import EntropyAnalyzer
        from barb.analyzers.homoglyph import HomoglyphAnalyzer
        from barb.analyzers.ip_url import IPURLAnalyzer
        from barb.analyzers.shortener import ShortenerAnalyzer
        from barb.analyzers.subdomain import SubdomainAnalyzer
        from barb.analyzers.tld import TLDAnalyzer

        _analyzers = [
            EntropyAnalyzer(),
            HomoglyphAnalyzer(),
            TLDAnalyzer(),
            SubdomainAnalyzer(),
            BrandAnalyzer(),
            ShortenerAnalyzer(),
            EncodingAnalyzer(),
            IPURLAnalyzer(),
        ]
    return _analyzers


# ---------------------------------------------------------------------------
# Core analysis function
# ---------------------------------------------------------------------------


def _analyze_single(url: str, config: AppConfig, explain: bool = False) -> AnalysisResult:
    """Run all analyzers on a single URL and return the result."""
    parsed = parse_url(url)
    analyzers = _get_analyzers()

    # Collect signals from all analyzers
    signals = []
    for analyzer in analyzers:
        signals.extend(analyzer.analyze(parsed))

    # Score and verdict
    score = compute_risk_score(signals, config)
    verdict = determine_verdict(score, config)

    # Build result
    result = AnalysisResult(
        url=url,
        defanged_url=defang_url(url),
        parsed_url=parsed,
        signals=signals,
        risk_score=score,
        verdict=verdict,
        analyzed_at=datetime.now(timezone.utc),
    )

    # Explanation (if requested)
    if explain:
        result.explanation = _explain(result, config)

    return result


def _explain(result: AnalysisResult, config: AppConfig) -> str:
    """Generate explanation using configured provider."""
    provider = config.explain.provider

    if provider == "anthropic":
        from barb.explain.llm import AnthropicExplainer

        if not config.explain.api_key:
            typer.echo("Error: API key required for Anthropic. Set BARB_LLM_KEY or configure in ~/.barb/config.yaml", err=True)
            return ""
        explainer = AnthropicExplainer(
            api_key=config.explain.api_key,
            model=config.explain.model or "claude-sonnet-4-20250514",
        )
        return explainer.explain(result, send_url=config.explain.send_url)

    elif provider == "openai":
        from barb.explain.llm import OpenAIExplainer

        if not config.explain.api_key:
            typer.echo("Error: API key required for OpenAI. Set BARB_LLM_KEY or configure in ~/.barb/config.yaml", err=True)
            return ""
        explainer = OpenAIExplainer(
            api_key=config.explain.api_key,
            model=config.explain.model or "gpt-4o-mini",
        )
        return explainer.explain(result, send_url=config.explain.send_url)

    else:
        # Template fallback (default — no API key needed)
        from barb.explain.template import TemplateExplainer

        return TemplateExplainer().explain(result)


# ---------------------------------------------------------------------------
# CLI commands
# ---------------------------------------------------------------------------


@app.command()
def analyze(
    urls: Annotated[Optional[list[str]], typer.Argument(help="One or more URLs to analyze")] = None,
    file: Annotated[Optional[Path], typer.Option("--file", "-f", help="File containing URLs (one per line)")] = None,
    output: Annotated[str, typer.Option("--output", "-o", help="Output format: rich|console|json|csv")] = "rich",
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="Suppress banner")] = False,
    explain: Annotated[bool, typer.Option("--explain", "-e", help="Add explanation to output")] = False,
    threshold: Annotated[int, typer.Option("--threshold", "-t", help="Minimum risk score to report")] = 0,
    no_defang: Annotated[bool, typer.Option("--no-defang", help="Disable URL defanging in output")] = False,
) -> None:
    """Analyze one or more URLs for phishing indicators."""
    config = load_config()

    # Show banner for rich/console output
    if output in ("rich", "console"):
        show_banner(
            quiet=quiet or config.output.quiet,
            update_check_enabled=config.update_check.enabled,
            check_interval_hours=config.update_check.check_interval_hours,
        )

    # Collect URLs from all sources
    all_urls: list[str] = []
    if urls:
        all_urls.extend(urls)
    if file:
        if not file.exists():
            typer.echo(f"Error: File not found: {file}", err=True)
            raise typer.Exit(3)
        text = file.read_text()
        all_urls.extend(line.strip() for line in text.splitlines() if line.strip())
    if not sys.stdin.isatty() and not urls and not file:
        # Read from stdin
        all_urls.extend(line.strip() for line in sys.stdin if line.strip())

    if not all_urls:
        typer.echo("Error: No URLs provided. Pass URLs as arguments, via --file, or pipe to stdin.", err=True)
        raise typer.Exit(3)

    # Analyze
    if len(all_urls) == 1:
        results = [_analyze_single(all_urls[0], config, explain=explain)]
    else:
        from barb.batch import batch_analyze

        results = batch_analyze(
            all_urls,
            lambda url: _analyze_single(url, config, explain=explain),
        )

    # Apply threshold filter
    if threshold > 0:
        results = [r for r in results if r.risk_score >= threshold]

    if not results:
        typer.echo("No URLs exceeded the threshold.", err=True)
        raise typer.Exit(0)

    # Output
    defang = not no_defang
    _output_results(results, output, defang)

    # Exit code = worst verdict
    worst = max(results, key=lambda r: r.risk_score)
    raise typer.Exit(worst.verdict.exit_code)


def _output_results(results: list[AnalysisResult], fmt: str, defang: bool) -> None:
    """Route results to the appropriate output formatter."""
    if fmt == "json":
        from barb.output.export import to_json, to_json_list

        if len(results) == 1:
            typer.echo(to_json(results[0]))
        else:
            typer.echo(to_json_list(results))

    elif fmt == "csv":
        from barb.output.export import to_csv

        typer.echo(to_csv(results), nl=False)

    elif fmt == "console":
        from barb.output.formatter import format_console

        for result in results:
            format_console(result, defang=defang)

    else:
        # Rich (default)
        from barb.output.formatter import format_batch_summary, format_rich

        if len(results) == 1:
            format_rich(results[0], defang=defang)
        else:
            format_batch_summary(results)
            for result in results:
                format_rich(result, defang=defang)


@app.command()
def config(
    show: Annotated[bool, typer.Option("--show", help="Show current configuration")] = False,
) -> None:
    """View or modify configuration."""
    if show:
        cfg = load_config()
        import yaml

        typer.echo(yaml.dump(cfg.model_dump(), default_flow_style=False, sort_keys=False))
    else:
        typer.echo("Use --show to display current configuration.")
        typer.echo(f"Config file: ~/.barb/config.yaml")


@app.command()
def version() -> None:
    """Show version information."""
    typer.echo(f"barb {__version__}")


def main() -> None:
    """Entry point for the CLI."""
    app()


if __name__ == "__main__":
    main()
