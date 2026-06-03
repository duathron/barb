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
from barb.models import AnalysisResult
from barb.scoring import compute_risk_score, determine_verdict
from barb.url_parser import parse_url


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
            typer.echo(
                "Error: API key required for Anthropic. Set BARB_LLM_KEY or configure in ~/.barb/config.yaml",
                err=True,
            )
            return ""
        explainer = AnthropicExplainer(
            api_key=config.explain.api_key,
            model=config.explain.model or "claude-sonnet-4-20250514",
        )
        return explainer.explain(result, send_url=config.explain.send_url)

    elif provider == "openai":
        from barb.explain.llm import OpenAIExplainer

        if not config.explain.api_key:
            typer.echo(
                "Error: API key required for OpenAI. Set BARB_LLM_KEY or configure in ~/.barb/config.yaml",
                err=True,
            )
            return ""
        explainer = OpenAIExplainer(
            api_key=config.explain.api_key,
            model=config.explain.model or "gpt-4o-mini",
        )
        return explainer.explain(result, send_url=config.explain.send_url)

    elif provider == "ollama":
        from barb.explain.llm import OllamaExplainer

        explainer = OllamaExplainer(
            host=config.explain.ollama_host,
            model=config.explain.model or "llama3.1",
        )
        try:
            return explainer.explain(result, send_url=config.explain.send_url)
        except RuntimeError as exc:
            typer.echo(
                f"Note: Ollama explanation failed ({exc}); falling back to template explanation.",
                err=True,
            )
            from barb.explain.template import TemplateExplainer

            return TemplateExplainer().explain(result)

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
    output: Annotated[  # noqa: E501
        str,
        typer.Option("--output", "-o", help="Output format: rich|console|json|ndjson|csv|stix"),
    ] = "rich",
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="Suppress banner")] = False,
    explain: Annotated[bool, typer.Option("--explain", "-e", help="Add explanation to output")] = False,
    threshold: Annotated[int, typer.Option("--threshold", "-t", help="Minimum risk score to report")] = 0,
    no_defang: Annotated[bool, typer.Option("--no-defang", help="Disable URL defanging in output")] = False,
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
    _output_results(results, output, defang)

    # Exit code = worst verdict
    worst = max(results, key=lambda r: r.risk_score)
    raise typer.Exit(worst.verdict.exit_code)


def _output_results(results: list[AnalysisResult], fmt: str, defang: bool) -> None:
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


_MANUAL_TOPICS: dict[str, str] = {
    "analyzers": r"""\
[bold cyan]ANALYZERS — 12 offline heuristic detectors[/bold cyan]

All analyzers run on every [bold]barb analyze[/bold] invocation. No network calls, no API key.

  [cyan]entropy[/cyan]      High Shannon entropy in host or path (generated/random labels)
  [cyan]homoglyph[/cyan]    Unicode confusables and mixed-script labels (Latin+Cyrillic)
  [cyan]tld[/cyan]          Suspicious TLDs associated with phishing abuse
  [cyan]subdomain[/cyan]    Excessive subdomain depth or domain-squatting patterns
  [cyan]brand[/cyan]        Brand name in a domain that is not the brand's own
  [cyan]shortener[/cyan]    Known URL shortener services that obscure the destination
  [cyan]encoding[/cyan]     Percent-encoding or punycode abuse to disguise host/path
  [cyan]ip_url[/cyan]       IP address as host; @-obfuscation in host → CRITICAL
  [cyan]typosquat[/cyan]    ASCII brand lookalikes via Levenshtein 1-2 + digit↔letter swaps
  [cyan]keyword[/cyan]      Phishing keywords in path/query (login, verify, secure, …)
  [cyan]lexical[/cyan]      URL length, hyphen count, digit ratio — structural patterns
  [cyan]file_ext[/cyan]     Suspicious extensions: double-extension → HIGH, .exe/.ps1 → LOW

[bold]SCORING:[/bold]
  INFO=0  LOW=1  MEDIUM=2  HIGH=3  CRITICAL=5
  risk_score = Σ ( severity.points × signal.weight × analyzer_weight )

[bold]VERDICT THRESHOLDS:[/bold]
  < 1   [green]SAFE[/green]       ≥ 1  [blue]LOW_RISK[/blue]    ≥ 4  [yellow]SUSPICIOUS[/yellow]
  ≥ 8   [dark_orange]HIGH_RISK[/dark_orange]   ≥ 13 [red]PHISHING[/red]

[bold]SEVERITY FLOOR:[/bold]  CRITICAL signal → min HIGH_RISK;  HIGH signal → min SUSPICIOUS
  Floor only escalates — never lowers a score-based verdict.

barb is a high-precision URL pre-filter (precision 1.00 on the real corpus).
Low recall is by design: URL structure only, no fetching. Close the recall gap
with [bold]--osint[/bold] and the [bold]vex[/bold] pipeline.
""",
    "osint": r"""\
[bold cyan]OSINT ENRICHMENT — opt-in infrastructure checks[/bold cyan]

Pass [bold]--osint[/bold] to layer four network checks about the domain. barb NEVER
fetches the analyzed URL itself — only infrastructure metadata about it.

[bold]THE FOUR ENRICHERS:[/bold]
  [cyan]dns[/cyan]     socket.getaddrinfo (stdlib, 2 s timeout)
            HIGH on loopback/sinkhole; MEDIUM on private IP or NXDOMAIN
  [cyan]rdap[/cyan]    IANA RDAP bootstrap → TLD registry (stdlib urllib, no API key, 5 s)
            HIGH if domain < 30 days old; MEDIUM < 90 days; LOW if registrant redacted
  [cyan]crtsh[/cyan]   crt.sh CT-log aggregator (stdlib urllib, no API key, 8 s)
            MEDIUM if newest cert < 7 days; LOW < 30 days; INFO if no records found
  [cyan]asn[/cyan]     Team Cymru WHOIS whois.cymru.com:43 (stdlib socket, 3 s)
            INFO — AS number, name, country, BGP prefix; zero score impact

[bold]KEY BEHAVIORS:[/bold]
  Opt-in:    [bold]--osint[/bold] must be passed explicitly; never active by default
  Fail-open: any timeout or error drops that enricher's signals; analysis continues
  Cache:     results stored per host in ~/.barb/cache.db (default TTL: 6 h)
  No-cache:  [green]barb analyze <url> --osint --no-cache[/green] forces fresh lookups

[bold]PRIVACY:[/bold]
  - Analyzed URL host is never contacted (no GET/HEAD to the target)
  - Only infrastructure metadata is queried (DNS, registration age, crt.sh CT, IP ASN)
  - OSINT signals appear in output alongside offline signals
""",
    "output": r"""\
[bold cyan]OUTPUT FORMATS — six shapes for every workflow[/bold cyan]

Select with [bold]-o[/bold] / [bold]--output[/bold].

  [cyan]rich[/cyan]      Terminal tables with color, verdict box, signals (default)
  [cyan]console[/cyan]   Plain-text, grep-friendly; same fields as rich, no markup
  [cyan]json[/cyan]      Pretty-printed JSON array — for jq, vex, downstream parsing
  [cyan]ndjson[/cyan]    One compact JSON object per line — streaming/log pipelines
  [cyan]csv[/cyan]       Spreadsheet import; signals joined in signals_summary column
  [cyan]stix[/cyan]      STIX 2.1 bundle with indicator SDOs for SUSPICIOUS+ URLs

[bold]DEFANG RULES:[/bold]
  rich / console:       URLs always defanged (hxxps[://]evil[.]com) — TTY safety
  json / ndjson / csv:  Original URL preserved; defanged_url field also present
  --no-defang:          Disable defanging in rich/console output

[bold]OUTPUT ROUTING:[/bold]
  Machine formats → stdout;  banner, warnings, progress → stderr
  Use [bold]-q[/bold] to suppress the banner in scripts

[bold]THRESHOLD + EXIT CODES:[/bold]
  --threshold INT  filter: only URLs with risk_score >= N appear in output
  Exit 0 = SAFE/LOW_RISK  |  1 = SUSPICIOUS/HIGH_RISK  |  2 = PHISHING  |  3 = error
""",
    "config": r"""\
[bold cyan]CONFIGURATION REFERENCE[/bold cyan]

Priority chain (first match wins):
  CLI flags  >  environment variables  >  ~/.barb/config.yaml  >  built-in defaults

[bold]CONFIG FILE:[/bold]  ~/.barb/config.yaml  (created automatically; 0o600; directory 0o700)

[bold]QUICK INSPECT:[/bold]
  [green]barb config --show[/green]          Print the active merged configuration

[bold]KEY FIELDS:[/bold]
  scoring.weights.*          Per-analyzer score multipliers (entropy: 1.0, homoglyph: 1.5, …)
  scoring.thresholds.*       low_risk:1  suspicious:4  high_risk:8  phishing:13
  explain.provider           template | anthropic | openai | ollama  (default: template)
  explain.api_key            LLM API key (overridden by BARB_LLM_KEY env var)
  explain.send_url           true — include defanged URL in LLM prompt
  output.default_format      rich | console | json | ndjson | csv | stix
  output.quiet               suppress banner by default (false)
  osint.cache_ttl_hours      OSINT result cache TTL in ~/.barb/cache.db (default: 6)

[bold]ENVIRONMENT VARIABLE:[/bold]
  [cyan]BARB_LLM_KEY[/cyan]   API key for anthropic or openai explain providers
                 Overrides explain.api_key in config.yaml

[bold]~/.barb/ DIRECTORY:[/bold]
  config.yaml             User configuration (0o600)
  cache.db                SQLite OSINT result cache
  data/allowlist.json     User-override Tranco allowlist (written by update-data)
  rdap_bootstrap.json     IANA RDAP bootstrap cache (auto-managed, 7-day refresh)
""",
    "pipeline": r"""\
[bold cyan]PIPELINE — barb → vex → sift[/bold cyan]

barb is stage 1 in a three-tool SOC/DFIR chain:
  barb (heuristic URL pre-filter) → vex (VT reputation enrichment) → sift (alert triage)

[bold]BARB → VEX (primary handoff):[/bold]
  [green]barb analyze <url> -o json -q | vex triage --from-barb[/green]
  [green]barb analyze <url> -o json -q | vex triage --from-barb -o rich[/green]
  [green]barb analyze -f urls.txt -o json -q | vex triage --from-barb --alert SUSPICIOUS[/green]

  barb writes JSON to stdout; vex reads it via --from-barb and submits the URLs
  to VirusTotal, displaying barb's pre-scan verdict alongside the VT result.

[bold]FILTERING BEFORE HANDOFF:[/bold]
  [green]barb analyze -f urls.txt -o json -q | jq -c '.[] | select(.risk_score >= 4)' | vex triage --from-barb[/green]

[bold]CONTRACT (what vex reads from barb JSON):[/bold]
  Required: url
  Enrichment: verdict, risk_score, signals, defanged_url
  The contract is stable regardless of internal changes in either tool.

[bold]WHY PIPE-ONLY:[/bold]
  barb never imports vex/sift code. The integration is a plain UNIX pipe.
  Tools can be deployed, versioned, and updated independently.
  barb offline = no API keys, no rate limits — pre-screen large batches
  before spending VT API quota on only the suspicious URLs.

[dim]barb analyze <url> -o json | vex triage --from-barb[/dim]
""",
    "examples": r"""\
[bold cyan]USAGE EXAMPLES[/bold cyan]

[bold]Single URL:[/bold]
  [green]barb analyze "http://paypal.com@evil-login.tk/verify" -q[/green]
  [green]barb analyze "https://suspicious-site.tk/paypal-login" -o console -q[/green]

[bold]Defanged IOC input (paste directly from threat reports):[/bold]
  [green]barb analyze 'hxxp://evil[.]com/login' -q[/green]
  [green]barb analyze 'hxxps[://]micros0ft[.]tk/verify' -q[/green]
  Supported: hxxp/hxxps/hxtp, [://], [.]/(.)/\{.\}/[dot], [at]/(at), fullwidth, zero-width


[bold]With explanation:[/bold]
  [green]barb analyze "https://pаypal.com" --explain -q[/green]

[bold]Batch from file:[/bold]
  [green]barb analyze -f urls.txt -o json -q[/green]
  [green]barb analyze -f urls.txt -o csv -q > results.csv[/green]

[bold]Stdin pipe:[/bold]
  [green]cat urls.txt | barb analyze -o ndjson -q[/green]
  [green]tail -f access.log | grep -oP 'https?://\S+' | barb analyze -o ndjson -q[/green]

[bold]Threshold filter:[/bold]
  [green]barb analyze -f urls.txt -o json --threshold 4 -q[/green]

[bold]OSINT enrichment:[/bold]
  [green]barb analyze "https://suspicious-site.tk/paypal-login" --osint -q[/green]
  [green]barb analyze "https://new-domain.xyz/login" --osint --no-cache -q[/green]

[bold]Output formats:[/bold]
  [green]barb analyze <url> -o stix -q > indicators.json[/green]   # SIEM ingest
  [green]barb analyze <url> -o json -q | jq '.[].verdict'[/green]

[bold]Pipeline (barb → vex):[/bold]
  [green]barb analyze -f urls.txt -o json -q | vex triage --from-barb[/green]

[bold]Refresh allowlist (opt-in):[/bold]
  [green]barb update-data[/green]

[bold]Automation (exit codes):[/bold]
  [green]barb analyze "$URL" -q && echo "clean" || echo "alert"[/green]
  Exit 0 = SAFE/LOW_RISK  |  1 = SUSPICIOUS/HIGH_RISK  |  2 = PHISHING  |  3 = error
""",
}


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
