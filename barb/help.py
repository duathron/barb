"""Built-in manual topics for `barb manual` — extracted from main.py to keep the CLI entrypoint lean."""

from __future__ import annotations

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

[bold]BATCH SUMMARY (N>1 URLs):[/bold]
  rich / console output opens with an aggregate block: verdict histogram,
  top signals across the batch, share at or above --threshold.
  [bold]--summary-only[/bold]  suppress per-URL detail — show only the aggregate block.
  JSON / NDJSON / CSV / STIX are unchanged; piping to downstream tools is unaffected.

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
  allowlist_check.enabled    true — set false to silence the staleness hint
  allowlist_check.max_age_days  90 — warn when the allowlist is older than this

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

[bold]Batch summary (aggregate view):[/bold]
  [green]barb analyze -f urls.txt -q[/green]                  # opens with verdict histogram + top signals
  [green]barb analyze -f urls.txt --summary-only -q[/green]   # aggregate only; per-URL detail suppressed
  Note: json/ndjson/csv/stix output is unaffected by --summary-only

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
