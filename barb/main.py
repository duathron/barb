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
from barb.defang import defang_url, refang_url
from barb.help import _MANUAL_TOPICS
from barb.models import AnalysisResult
from barb.scoring import compute_risk_score, determine_verdict
from barb.url_parser import parse_url

# F2 cut-1 (2026-07-03 MeetUp — 2026-07-03-f2-llm-failure-posture.md): reserved
# exit code for a degraded explanation (a REQUESTED LLM provider failed).
# Distinct from the verdict codes (0/1/2) and the CLI-usage error code (3).
_EXIT_EXPLANATION_DEGRADED = 4


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"barb {__version__}")
        raise typer.Exit(0)


app = typer.Typer(
    name="barb",
    help="Heuristic phishing URL analyzer for SOC/DFIR workflows.",
    no_args_is_help=True,
)


@app.callback()
def _app_callback(
    version: Annotated[
        Optional[bool],
        typer.Option("--version", callback=_version_callback, is_eager=True, help="Show version and exit."),
    ] = None,
) -> None:
    """Heuristic phishing URL analyzer for SOC/DFIR workflows."""


# ---------------------------------------------------------------------------
# Analyzer registry — lazily instantiated
# ---------------------------------------------------------------------------

_analyzers = None


def _get_analyzers() -> list:
    """Lazily instantiate all 12 heuristic analyzers."""
    global _analyzers
    if _analyzers is None:
        from barb.analyzers.brand import BrandAnalyzer
        from barb.analyzers.encoding import EncodingAnalyzer
        from barb.analyzers.entropy import EntropyAnalyzer
        from barb.analyzers.file_ext import FileExtAnalyzer
        from barb.analyzers.homoglyph import HomoglyphAnalyzer
        from barb.analyzers.ip_url import IPURLAnalyzer
        from barb.analyzers.keyword import KeywordAnalyzer
        from barb.analyzers.lexical import LexicalAnalyzer
        from barb.analyzers.shortener import ShortenerAnalyzer
        from barb.analyzers.subdomain import SubdomainAnalyzer
        from barb.analyzers.tld import TLDAnalyzer
        from barb.analyzers.typosquat import TyposquatAnalyzer

        _analyzers = [
            EntropyAnalyzer(),
            HomoglyphAnalyzer(),
            TLDAnalyzer(),
            SubdomainAnalyzer(),
            BrandAnalyzer(),
            ShortenerAnalyzer(),
            EncodingAnalyzer(),
            IPURLAnalyzer(),
            KeywordAnalyzer(),
            LexicalAnalyzer(),
            TyposquatAnalyzer(),
            FileExtAnalyzer(),
        ]
    return _analyzers


def _run_enrichers(parsed_url, config: AppConfig, use_cache: bool = True) -> list:
    """Run OSINT enrichers and return combined signals. Fail-open on any error.

    Results are cached per host (``osint.cache_ttl_hours`` TTL) to avoid repeat
    network lookups; pass ``use_cache=False`` to bypass the cache (``--no-cache``).
    """
    from barb.enrichers.asn import ASNEnricher
    from barb.enrichers.crtsh import CrtShEnricher
    from barb.enrichers.dns import DNSEnricher
    from barb.enrichers.rdap import RDAPEnricher

    host = parsed_url.host.lower()
    cache = None
    if use_cache:
        from barb.cache import get_cache

        cache = get_cache()
        cached = cache.get(host, config.osint.cache_ttl_hours * 3600)
        if cached is not None:
            return cached

    enrichers = [
        DNSEnricher(timeout=config.osint.dns_timeout),
        RDAPEnricher(timeout=config.osint.rdap_timeout),
        CrtShEnricher(timeout=config.osint.crtsh_timeout),
        ASNEnricher(timeout=config.osint.asn_timeout),
    ]
    signals = []
    for enricher in enrichers:
        try:
            signals.extend(enricher.enrich(parsed_url))
        except Exception:
            pass  # Individual enricher failure never blocks analysis

    if cache is not None:
        cache.set(host, signals)
    return signals


# ---------------------------------------------------------------------------
# Core analysis function
# ---------------------------------------------------------------------------


def _analyze_single(
    url: str,
    config: AppConfig,
    explain: bool = False,
    osint: bool = False,
    use_cache: bool = True,
) -> AnalysisResult:
    """Run all analyzers on a single URL and return the result."""
    parsed = parse_url(url)
    analyzers = _get_analyzers()

    # Collect signals from all heuristic analyzers
    signals = []
    for analyzer in analyzers:
        signals.extend(analyzer.analyze(parsed))

    # Allowlist suppression: drop noisy signals for known-good domains
    from barb.allowlist import is_allowlisted

    _SUPPRESSED_ANALYZERS = {"tld", "typosquat", "homoglyph"}
    _SUPPRESSED_ENTROPY_LABEL = "High entropy domain"
    if is_allowlisted(parsed.host):
        signals = [
            s
            for s in signals
            if not (
                s.analyzer in _SUPPRESSED_ANALYZERS
                or (s.analyzer == "entropy" and s.label == _SUPPRESSED_ENTROPY_LABEL)
            )
        ]

    # OSINT enrichment (opt-in, network-dependent)
    if osint:
        osint_signals = _run_enrichers(parsed, config, use_cache=use_cache)
        signals.extend(osint_signals)

    # Score and verdict
    score = compute_risk_score(signals, config)
    verdict = determine_verdict(score, signals, config)

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

    # Explanation (if requested) — _explain mutates result in place.
    if explain:
        _explain(result, config)

    return result


def _explain(result: AnalysisResult, config: AppConfig) -> None:
    """Populate ``result.explanation`` using the configured provider.

    Mutates *result* in place (rather than returning a string) because on an
    LLM-provider failure it must set three fields, not one.

    F2 cut-1 (2026-07-03 MeetUp — 2026-07-03-f2-llm-failure-posture.md):
    a REQUESTED LLM provider (anthropic/openai/ollama) that fails must NEVER
    (a) silently substitute a TemplateExplainer — the analyst would read a
    rule-based template believing it was an LLM explanation — nor (b) crash
    the process. The old anthropic/openai branches had no try/except, so an
    uncaught SDK error exited 1, colliding with the SUSPICIOUS/HIGH_RISK
    verdict code (a crash read as a real risk verdict); the old ollama branch
    caught and silently fell back to a template. Both are the bug. Now every
    provider's build + explain() is wrapped in one handler: on failure the URL
    VERDICT still stands (barb's primary output — never lost), the explanation
    is left unavailable (``explanation=None``), and it is loudly flagged on
    stderr + machine-marked (``explanation_degraded``/``explanation_provider``)
    for the degraded exit code in ``analyze()``. A deliberate ``template``
    provider (no LLM requested) is never degraded.
    """
    provider = config.explain.provider

    if provider == "template":
        # Deliberate, no LLM requested — never degraded.
        from barb.explain.template import TemplateExplainer

        result.explanation = TemplateExplainer().explain(result)
        return

    if provider not in ("anthropic", "openai", "ollama"):
        # Unrecognized provider — preserve the historical template fallback
        # (not an LLM request, so not a "provider failure").
        from barb.explain.template import TemplateExplainer

        result.explanation = TemplateExplainer().explain(result)
        return

    # A REAL LLM provider was requested. Build + call inside ONE try so that a
    # build-time failure (missing SDK -> ImportError; missing API key ->
    # RuntimeError) routes through the same never-silent-template, never-crash
    # handler as a runtime API failure.
    try:
        if provider == "anthropic":
            from barb.explain.llm import AnthropicExplainer

            if not config.explain.api_key:
                raise RuntimeError(
                    "API key required for Anthropic. Set BARB_LLM_KEY or configure in ~/.barb/config.yaml"
                )
            explainer = AnthropicExplainer(
                api_key=config.explain.api_key,
                model=config.explain.model or "claude-sonnet-4-20250514",
            )
            result.explanation = explainer.explain(result, send_url=config.explain.send_url)

        elif provider == "openai":
            from barb.explain.llm import OpenAIExplainer

            if not config.explain.api_key:
                raise RuntimeError("API key required for OpenAI. Set BARB_LLM_KEY or configure in ~/.barb/config.yaml")
            explainer = OpenAIExplainer(
                api_key=config.explain.api_key,
                model=config.explain.model or "gpt-4o-mini",
            )
            result.explanation = explainer.explain(result, send_url=config.explain.send_url)

        else:  # provider == "ollama"
            from barb.explain.llm import OllamaExplainer

            explainer = OllamaExplainer(
                host=config.explain.ollama_host,
                model=config.explain.model or "llama3.1",
            )
            result.explanation = explainer.explain(result, send_url=config.explain.send_url)
    except Exception as exc:  # noqa: BLE001 — any provider failure degrades, never crashes
        typer.echo(
            f"⚠ EXPLANATION UNAVAILABLE — provider '{provider}' failed: {exc}",
            err=True,
        )
        result.explanation = None
        result.explanation_degraded = True
        result.explanation_provider = provider


# ---------------------------------------------------------------------------
# CLI commands
# ---------------------------------------------------------------------------


@app.command()
def analyze(
    urls: Annotated[Optional[list[str]], typer.Argument(help="One or more URLs to analyze")] = None,
    file: Annotated[Optional[Path], typer.Option("--file", "-f", help="File containing URLs (one per line)")] = None,
    output: Annotated[  # noqa: E501
        str,
        typer.Option("--output", "-o", help="Output format: rich|console|json|ndjson|csv|stix"),
    ] = "rich",
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="Suppress banner")] = False,
    explain: Annotated[bool, typer.Option("--explain", "-e", help="Add explanation to output")] = False,
    threshold: Annotated[int, typer.Option("--threshold", "-t", help="Minimum risk score to report")] = 0,
    no_defang: Annotated[bool, typer.Option("--no-defang", help="Disable URL defanging in output")] = False,
    summary_only: Annotated[
        bool,
        typer.Option(
            "--summary-only",
            help=(
                "For N>1 URLs: show only the aggregated summary block; suppress per-URL detail output. "
                "No effect on JSON/NDJSON/CSV/pipe formats or single-URL analysis."
            ),
        ),
    ] = False,
    osint: Annotated[
        bool,
        typer.Option(
            "--osint",
            help=(
                "Enable opt-in OSINT enrichment about the domain: DNS resolution, RDAP registration age, "
                "crt.sh certificate-transparency (recent-cert age), and ASN hosting lookup. "
                "Queries infrastructure metadata only — never fetches the analyzed URL itself."
            ),
        ),
    ] = False,
    no_cache: Annotated[
        bool,
        typer.Option(
            "--no-cache",
            help="Bypass the OSINT result cache and force fresh DNS/RDAP lookups (default TTL: 6 h).",
        ),
    ] = False,
) -> None:
    """Analyze one or more URLs for phishing indicators."""
    config = load_config()

    # Validate output format before doing any work
    _VALID_FORMATS = {"rich", "console", "json", "ndjson", "csv", "stix"}
    if output not in _VALID_FORMATS:
        typer.echo(
            f"Error: Unknown output format '{output}'. Valid: rich, console, json, ndjson, csv, stix",
            err=True,
        )
        raise typer.Exit(3)

    # Warn if --explain is used with stix (no effect)
    if explain and output == "stix":
        typer.echo("Note: --explain has no effect with -o stix (machine format).", err=True)

    # Show banner for rich/console output
    if output in ("rich", "console"):
        show_banner(
            quiet=quiet or config.output.quiet,
            update_check_enabled=config.update_check.enabled,
            check_interval_hours=config.update_check.check_interval_hours,
            allowlist_check_enabled=config.allowlist_check.enabled,
            allowlist_max_age_days=config.allowlist_check.max_age_days,
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
        all_urls.extend(line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith("#"))
    if not sys.stdin.isatty() and not urls and not file:
        # Read from stdin
        all_urls.extend(line.strip() for line in sys.stdin if line.strip() and not line.strip().startswith("#"))

    # Refang defanged IOCs before validation/analysis (offline string transform,
    # never fetches the URL).  Idempotent — live URLs are returned unchanged.
    all_urls = [refang_url(u) for u in all_urls]

    if not all_urls:
        typer.echo("Error: No URLs provided. Pass URLs as arguments, via --file, or pipe to stdin.", err=True)
        raise typer.Exit(3)

    # Analyze
    if len(all_urls) == 1:
        try:
            results = [_analyze_single(all_urls[0], config, explain=explain, osint=osint, use_cache=not no_cache)]
        except ValueError as exc:
            typer.echo(f"Error: {exc}", err=True)
            raise typer.Exit(3) from None
    else:
        valid_results: list[AnalysisResult] = []
        errors = 0
        for url in all_urls:
            try:
                valid_results.append(_analyze_single(url, config, explain=explain, osint=osint, use_cache=not no_cache))
            except ValueError as exc:
                typer.echo(f"Error ({url[:80]}): {exc}", err=True)
                errors += 1
        results = valid_results
        if not results:
            typer.echo(f"All {errors} URL(s) failed validation.", err=True)
            raise typer.Exit(3)

    # Apply threshold filter
    if threshold > 0:
        results = [r for r in results if r.risk_score >= threshold]

    if not results:
        typer.echo("No URLs exceeded the threshold.", err=True)
        raise typer.Exit(0)

    # Output
    defang = not no_defang
    _output_results(results, output, defang, summary_only=summary_only, threshold=threshold)

    # Exit code. F2 cut-1 (2026-07-03 MeetUp): a degraded explanation (a
    # REQUESTED LLM provider failed) exits with a NEW reserved code (4),
    # distinct from barb's verdict codes (0/1/2) and the CLI-usage error code
    # (3). It takes priority over the verdict code — a degraded run always
    # needs operator attention, and reusing a verdict code would recreate the
    # crash-exits-1-as-SUSPICIOUS collision this fix exists to kill. The
    # `explanation_degraded` field is the machine-legible signal; the verdict
    # itself (barb's primary, still-valid output) is unaffected.
    if any(r.explanation_degraded for r in results):
        raise typer.Exit(_EXIT_EXPLANATION_DEGRADED)

    # Exit code = worst verdict
    worst = max(results, key=lambda r: r.risk_score)
    raise typer.Exit(worst.verdict.exit_code)


def _output_results(
    results: list[AnalysisResult],
    fmt: str,
    defang: bool,
    summary_only: bool = False,
    threshold: int = 0,
) -> None:
    """Route results to the appropriate output formatter."""
    if fmt == "json":
        from barb.output.export import to_json, to_json_list

        if len(results) == 1:
            typer.echo(to_json(results[0], defang=defang))
        else:
            typer.echo(to_json_list(results, defang=defang))

    elif fmt == "ndjson":
        from barb.output.export import to_ndjson

        typer.echo(to_ndjson(results, defang=defang), nl=False)

    elif fmt == "stix":
        from barb.output.export import to_stix

        typer.echo(to_stix(results))

    elif fmt == "csv":
        from barb.output.export import to_csv

        typer.echo(to_csv(results), nl=False)

    elif fmt == "console":
        from barb.output.formatter import format_console, format_console_aggregate_summary

        # Aggregate summary for N>1 (plain console format previously had none)
        if len(results) > 1:
            format_console_aggregate_summary(results, threshold=threshold)

        # Per-URL detail blocks (suppressed by --summary-only for N>1)
        if not (summary_only and len(results) > 1):
            for result in results:
                format_console(result, defang=defang)

    else:
        # Rich (default)
        from barb.output.formatter import format_aggregate_summary, format_batch_summary, format_rich

        if len(results) == 1:
            format_rich(results[0], defang=defang)
        else:
            # Aggregated header block (new)
            format_aggregate_summary(results, threshold=threshold)
            # Existing per-URL summary table (always shown)
            format_batch_summary(results)
            # Per-URL detail blocks (suppressed by --summary-only)
            if not summary_only:
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
        typer.echo("Config file: ~/.barb/config.yaml")


@app.command(name="update-data")
def update_data(
    top_n: Annotated[
        int,
        typer.Option("--top-n", help="Number of top Tranco domains to include in the allowlist."),
    ] = 5000,
    source: Annotated[
        str,
        typer.Option(
            "--source",
            help=(
                "HTTPS URL of the Tranco list to download. "
                "Must start with https://. "
                "Default: https://tranco-list.eu/top-1m.csv.zip"
            ),
        ),
    ] = "https://tranco-list.eu/top-1m.csv.zip",
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="Suppress progress messages.")] = False,
) -> None:
    """Refresh the Tranco-based allowlist from upstream (opt-in, HTTPS only).

    Downloads the Tranco top-1M list and writes the top --top-n domains
    to ~/.barb/data/allowlist.json (user-override location), merged with
    the bundled curated brand list.  The bundled list is NEVER overwritten.

    NOTE: This EXPANDS false-positive suppression — more domains will be
    treated as known-good, which may reduce phishing signals for recently
    added or obscure domains.  Run only when you understand this tradeoff.

    Users who never run this command continue to use the bundled curated
    list — default detection behavior is completely unchanged.
    """
    from barb.data_update import fetch_tranco, parse_tranco, write_user_allowlist

    if not source.startswith("https://"):
        typer.echo(
            f"Error: HTTPS required — rejected non-https source URL: {source!r}. "
            "barb only downloads data over an encrypted connection.",
            err=True,
        )
        raise typer.Exit(3)

    if not quiet:
        typer.echo(
            "NOTE: update-data EXPANDS false-positive suppression — more domains will be treated "
            "as known-good after this update.  This is an opt-in operation."
        )

    if not quiet:
        typer.echo(f"Fetching: {source}")

    try:
        raw = fetch_tranco(source)
    except RuntimeError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(3)

    if not quiet:
        typer.echo(f"Parsing top {top_n} domains …")

    try:
        domains = parse_tranco(raw, top_n)
    except Exception as exc:
        typer.echo(f"Error parsing list: {exc}", err=True)
        raise typer.Exit(3)

    try:
        dest = write_user_allowlist(domains)
    except Exception as exc:
        typer.echo(f"Error writing allowlist: {exc}", err=True)
        raise typer.Exit(3)

    # Count total entries in the written file
    import json as _json

    try:
        total = len(_json.loads(dest.read_text()))
    except Exception:
        total = len(domains)

    typer.echo(f"Source:   {source}")
    typer.echo(f"Domains:  {total} written (top {top_n} Tranco + bundled curated entries)")
    typer.echo(f"Location: {dest}")
    typer.echo("barb analyze will now use the expanded allowlist for false-positive suppression.")


@app.command(name="manual", help="[bold blue]Show usage guide[/bold blue] — run without topic for overview.")
def manual(
    topic: Annotated[
        Optional[str],
        typer.Argument(help="Topic: analyzers, osint, output, config, pipeline, examples. Omit for overview."),
    ] = None,
) -> None:
    """Display built-in usage guide. Omit TOPIC for the overview."""
    from rich.console import Console

    console = Console()

    if topic and topic.lower() in _MANUAL_TOPICS:
        console.print(_MANUAL_TOPICS[topic.lower()])
        return

    if topic:
        console.print(f"[red]Unknown topic:[/red] '{topic}'")
        console.print()

    # Overview
    console.print("[bold cyan]BARB MANUAL[/bold cyan]")
    console.print()
    console.print(f"  barb {__version__} — Heuristic phishing URL analyzer")
    console.print("  https://github.com/duathron/barb")
    console.print("  https://pypi.org/project/barb-phish/")
    console.print()
    console.print("[bold]Available topics:[/bold]")
    console.print("  [green]barb manual analyzers[/green]   The 12 heuristic analyzers, scoring model, thresholds")
    console.print("  [green]barb manual osint[/green]       OSINT enrichers, opt-in, fail-open, cache, privacy")
    console.print("  [green]barb manual output[/green]      Six output formats and defang rules")
    console.print("  [green]barb manual config[/green]      ~/.barb/config.yaml, priority chain, BARB_LLM_KEY")
    console.print("  [green]barb manual pipeline[/green]    barb → vex pipeline integration")
    console.print("  [green]barb manual examples[/green]    Real one-line invocations")
    console.print()
    console.print("[bold]Quick start:[/bold]")
    console.print("  [green]barb analyze <url>[/green]")
    console.print("  [green]barb analyze <url> --explain[/green]")
    console.print("  [green]barb analyze <url> --osint[/green]")
    console.print()
    console.print("[dim]Pipeline: barb analyze <url> -o json | vex triage --from-barb[/dim]")


@app.command()
def version() -> None:
    """Show version information."""
    typer.echo(f"barb {__version__}")


def main() -> None:
    """Entry point for the CLI."""
    app()


if __name__ == "__main__":
    main()
