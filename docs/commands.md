# Commands

[← Docs index](README.md)

Every command and flag below is taken verbatim from `barb <cmd> --help` on
`barb 1.5.1`. Nothing here is invented.

```
barb [OPTIONS] COMMAND [ARGS]...
```

| Command | Purpose |
|---------|---------|
| [`analyze`](#analyze) | Analyze one or more URLs for phishing indicators. |
| [`config`](#config) | View or modify configuration. |
| [`manual`](#manual) | Built-in terminal usage guide. |
| [`update-data`](#update-data) | Refresh the Tranco-based allowlist from upstream (opt-in, HTTPS only). |
| [`version`](#version) | Show version information. |

Top-level `--version` flag also reports the installed version.

---

## analyze

```
barb analyze [OPTIONS] [URLS]...
```

Analyze one or more URLs for phishing indicators. `URLS` can be passed as
arguments, read from a file (`--file`), or piped from stdin. All three sources
can be combined in a single invocation.

### Input flags

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `URLS` (arg) | — | text | — | One or more URLs to analyze. |
| `--file` | `-f` | path | — | File containing URLs (one per line). |

### Output flags

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--output` | `-o` | text | `rich` | Output format: `rich` \| `console` \| `json` \| `ndjson` \| `csv` \| `stix` |
| `--quiet` | `-q` | flag | off | Suppress the banner. |
| `--no-defang` | — | flag | off | Disable URL defanging in output (defanging is on by default for `rich`/`console`). |
| `--threshold` | `-t` | int | `0` | Minimum risk score to report. URLs below the threshold are silently dropped from output. |

### Analysis flags

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--explain` | `-e` | flag | off | Add a plain-language explanation to output. |
| `--osint` | — | flag | off | Enable opt-in OSINT enrichment (DNS, RDAP, crt.sh CT-log, ASN). Queries infrastructure metadata only — never fetches the analyzed URL itself. |
| `--no-cache` | — | flag | off | Bypass the OSINT result cache and force fresh lookups (default TTL: 6 h). |

**Example — single URL, rich output (default):**

```bash
barb analyze "http://paypal.com@evil-login.tk/verify" -q
```

```
╭──────────────────────────────────── barb ────────────────────────────────────╮
│ URL         hxxp[://]paypal[.]com@evil-login[.]tk/verify                     │
│ Verdict     ⚠ HIGH RISK                                                      │
│ Risk Score  7.6                                                              │
╰──────────────────────────────────────────────────────────────────────────────╯
Severity     Analyzer       Finding
────────────────────────────────────────────────────────────────────────────────
CRITICAL     ip_url         URL contains userinfo 'paypal.com' before '@'; the
                            real host is 'evil-login.tk'
MEDIUM       tld            TLD '.tk' is commonly associated with phishing
LOW          keyword        Matched keywords: verify
```

**Example — defanged IOC input (accepted directly from threat reports):**

```bash
barb analyze 'hxxp://evil[.]com/login' -q
```

barb refangs the URL automatically before analysis.  Common forms accepted:
`hxxp`/`hxxps`/`hxtp`, `[://]`, `[.]`/`(.)`/`{.}`/`[dot]`, `[at]`/`(at)`,
fullwidth Unicode, zero-width characters.

**Example — console format:**

```bash
barb analyze "https://suspicious-site.tk/paypal-login" -o console -q
```

```
URL:      hxxps[://]suspicious-site[.]tk/paypal-login
Verdict:  LOW_RISK
Score:    2.6
Signals:
  [MEDIUM  ] tld          TLD '.tk' is commonly associated with phishing
  [LOW     ] keyword      Matched keywords: login
```

**Example — with explanation (`--explain`):**

```bash
barb analyze "http://paypal.com@evil-login.tk/verify" -q --explain
```

```
╭──────────────────────────────────── barb ────────────────────────────────────╮
│ URL         hxxp[://]paypal[.]com@evil-login[.]tk/verify                     │
│ Verdict     ⚠ HIGH RISK                                                      │
│ Risk Score  7.6                                                              │
╰──────────────────────────────────────────────────────────────────────────────╯
Severity     Analyzer       Finding
────────────────────────────────────────────────────────────────────────────────
CRITICAL     ip_url         URL contains userinfo 'paypal.com' before '@'; the
                            real host is 'evil-login.tk'
MEDIUM       tld            TLD '.tk' is commonly associated with phishing
LOW          keyword        Matched keywords: verify

╭──────────────────────────────── Explanation ─────────────────────────────────╮
│ This URL shows strong phishing indicators. Exercise extreme caution.         │
│                                                                              │
│ Detected indicators:                                                         │
│   [CRITICAL] Userinfo in URL: URL contains userinfo 'paypal.com' before '@'; │
│ the real host is 'evil-login.tk'                                             │
│   [MEDIUM] Suspicious TLD: TLD '.tk' is commonly associated with phishing    │
│   [LOW] Phishing keywords in URL path: Matched keywords: verify              │
│                                                                              │
│ Recommendation: Block this URL and investigate the source.                   │
╰──────────────────────────────────────────────────────────────────────────────╯
```

**Example — batch file, JSON output:**

```bash
barb analyze -f urls.txt -o json -q
```

**Example — batch file with threshold filter:**

```bash
barb analyze -f urls.txt -o json --threshold 4 -q
```

Only URLs with `risk_score >= 4` appear in output. Exit code reflects the worst
verdict among reported URLs.

**Example — stdin pipe:**

```bash
cat urls.txt | barb analyze -o csv -q
```

**Example — OSINT enrichment:**

```bash
barb analyze "https://suspicious-site.tk/paypal-login" --osint -q
```

---

## config

```
barb config [OPTIONS]
```

View or modify configuration. Reads from `~/.barb/config.yaml` (and built-in
defaults when no file exists).

| Flag | Description |
|------|-------------|
| `--show` | Print the current merged configuration (file + defaults). |

**Example:**

```bash
barb config --show
```

```yaml
scoring:
  weights:
    entropy: 1.0
    homoglyph: 1.5
    tld: 1.0
    subdomain: 1.0
    brand: 1.2
    shortener: 0.8
    encoding: 1.0
    ip_url: 1.0
    typosquat: 1.3
    keyword: 0.6
    lexical: 0.5
    file_ext: 1.0
  thresholds:
    low_risk: 1
    suspicious: 4
    high_risk: 8
    phishing: 13
explain:
  provider: template
  model: null
  api_key: null
  send_url: true
  ollama_host: http://localhost:11434
output:
  default_format: rich
  quiet: false
  defang: true
update_check:
  enabled: true
  check_interval_hours: 24
osint:
  dns_timeout: 2.0
  rdap_timeout: 5.0
  crtsh_timeout: 8.0
  asn_timeout: 3.0
  cache_ttl_hours: 6
```

See [Configuration](configuration.md) for the full field reference.

---

## update-data

```
barb update-data [OPTIONS]
```

Refresh the Tranco-based domain allowlist from upstream (opt-in, HTTPS only).
Downloads the Tranco top-1M list and writes the top `--top-n` domains to
`~/.barb/data/allowlist.json` (user-override location), merged with the bundled
curated brand list. The bundled list is **never overwritten**.

> [!CAUTION]
> Running `update-data` **expands** false-positive suppression. More domains will
> be treated as known-good, which may reduce phishing signals for recently added
> or less-known legitimate domains. Run only when you understand this tradeoff.
>
> Users who never run `update-data` continue to use the bundled curated list —
> detection behavior is completely unchanged.

| Flag | Default | Description |
|------|---------|-------------|
| `--top-n` | `5000` | Number of top Tranco domains to include in the allowlist. |
| `--source` | `https://tranco-list.eu/top-1m.csv.zip` | HTTPS URL of the Tranco list to download. Must start with `https://`. |
| `--quiet` / `-q` | off | Suppress progress messages. |

**Example — default (top 5000):**

```bash
barb update-data
```

**Example — expand to top 10 000:**

```bash
barb update-data --top-n 10000
```

**Key guarantees:**

- Opt-in only — `barb analyze` never triggers a download.
- HTTPS only — a `--source` that does not start with `https://` is rejected
  before any network call (exit code `3`).
- Atomic write — temp file + `os.replace`; no partial writes visible.
- Write location: `~/.barb/data/allowlist.json` (`0o600`, directory `0o700`).
- No extra dependencies — stdlib `urllib` only.

---

## manual

```
barb manual [TOPIC]
```

Print a built-in terminal usage guide. When no topic is given, prints an overview with the version, GitHub and PyPI links, the available topics list, and a quick-start snippet. When a topic is given, prints that topic's guide directly.

| Topic | What it covers |
|-------|----------------|
| `analyzers` | All 12 offline analyzers (one-line each), scoring formula, verdict thresholds, severity-floor rule |
| `osint` | The four OSINT enrichers (DNS/RDAP/crt.sh/ASN), opt-in/fail-open behavior, cache, privacy footprint |
| `output` | All six `-o` formats and when to use each, defang rules, exit-code reference |
| `config` | `~/.barb/config.yaml`, priority chain, `BARB_LLM_KEY`, key fields, `~/.barb/` directory contents |
| `pipeline` | barb → vex pipeline with real invocation examples, filtering before handoff, why pipe-only |
| `examples` | 8+ one-line real invocations covering single/batch/stdin/threshold/osint/explain/output/update-data |

If an unknown topic is supplied, barb prints a red "Unknown topic" notice and then falls through to the full overview.

**Example — overview:**

```bash
barb manual
```

```
BARB MANUAL

  barb 1.5.0 — Heuristic phishing URL analyzer
  https://github.com/duathron/barb
  https://pypi.org/project/barb-phish/

Available topics:
  barb manual analyzers   The 12 heuristic analyzers, scoring model, thresholds
  barb manual osint       OSINT enrichers, opt-in, fail-open, cache, privacy
  barb manual output      Six output formats and defang rules
  barb manual config      ~/.barb/config.yaml, priority chain, BARB_LLM_KEY
  barb manual pipeline    barb → vex pipeline integration
  barb manual examples    Real one-line invocations

Quick start:
  barb analyze <url>
  barb analyze <url> --explain
  barb analyze <url> --osint

Pipeline: barb analyze <url> -o json | vex triage --from-barb
```

**Example — topic:**

```bash
barb manual pipeline
```

---

## version

```
barb version
```

Print the installed version and exit. No flags.

```bash
barb version
# barb 1.5.0
```

The top-level `barb --version` flag produces the same output.
