<p align="center">
  <img src="barb/barb.png" alt="barb logo" width="300"/>
</p>

<h1 align="center">barb</h1>

<p align="center">
  <b>Catch phishing URLs before they catch you.</b>
</p>

<p align="center">
  Heuristic phishing URL analyzer for SOC/DFIR workflows. Offline core — no API keys, never fetches the analyzed URL. Optional <code>--osint</code> flag adds DNS, RDAP, and crt.sh CT-log enrichment.
</p>

<p align="center">
  <img alt="PyPI" src="https://img.shields.io/pypi/v/barb-phish"> <img alt="Python" src="https://img.shields.io/pypi/pyversions/barb-phish"> <img alt="CI" src="https://img.shields.io/github/actions/workflow/status/duathron/barb/ci.yml"> <img alt="License" src="https://img.shields.io/badge/license-MIT-blue">
</p>

---

See the [full documentation](docs/README.md) for every command, flag, and output mode.

Built-in guide: `barb manual` (and `barb manual analyzers` / `osint` / `pipeline` / `config` / `output` / `examples`).

## Features

- **12 heuristic analyzers**: entropy, homoglyph, TLD, subdomain, brand impersonation, URL shortener, encoding abuse, IP-based URLs, typosquat, keyword, lexical, file extension
- **5-tier verdict**: SAFE / LOW_RISK / SUSPICIOUS / HIGH_RISK / PHISHING with severity-floor escalation
- **Zero API keys required** for core analysis — offline, no external calls
- **Opt-in `--osint` enrichment**: DNS resolution + RDAP registration lookups + crt.sh CT-log queries + ASN lookup (stdlib only, no API key); never fetches the analyzed URL
- **Allowlist false-positive suppression**: ~71 known-good domains suppress noisy domain-based signals; path/query signals still fire
- **Allowlist staleness warning**: offline stderr hint when the Tranco allowlist is older than 90 days — run `barb update-data` to refresh; opt-out via `allowlist_check.enabled: false` in config; never blocks analysis
- **OSINT result cache**: SQLite cache at `~/.barb/cache.db` (default TTL 6 h); bypass with `--no-cache`
- **Output formats**: Rich tables, console, JSON, NDJSON, CSV, STIX 2.1
- **Batch summary**: for N>1 URLs, rich/console output opens with an aggregate block — verdict histogram, top signals, share above `--threshold`; use `--summary-only` to suppress per-URL detail. Machine formats (json/ndjson/csv/stix) are unchanged.
- **`--explain` flag**: template-based explanation by default, optional LLM (Anthropic Claude, OpenAI, or local Ollama)
- **`--version` flag**: report the installed version (`barb --version` or `barb version`)
- **Offline eval harness** (`eval/`): measures precision/recall/F1 against a labeled URL corpus; wired into CI as a detection-quality regression gate
- **Batch processing**: analyze URL lists from files, stdin, or multiple arguments
- **Automation-ready**: exit codes (0=safe, 1=suspicious, 2=phishing, 3=error), `--threshold` filtering
- **IOC defanging**: automatic in terminal output (`hxxps[://]evil[.]com`); accepts defanged IOCs on input (`hxxp://`, `[.]`, `[dot]`, `[at]`, fullwidth, zero-width) — refanged before analysis
- **Configurable scoring**: per-analyzer weights and verdict thresholds via YAML
- **Minimal dependencies**: 5 core packages (typer, rich, pydantic, pyyaml, python-dotenv)

---

## Quick Start

### Installation

**From PyPI:**

```bash
pip install barb-phish
```

**With LLM support (optional):**

```bash
pip install barb-phish[llm]
```

**From source:**

```bash
git clone https://github.com/duathron/barb.git
cd barb
pip install -e ".[dev]"
```

### Usage

**Analyze a single URL:**

```bash
barb analyze https://suspicious-site.tk/paypal-login
```

**Paste a defanged IOC directly from a threat report:**

```bash
barb analyze 'hxxp://evil[.]com/login'
```

**Batch analysis from file:**

```bash
barb analyze -f urls.txt -o json
```

**With explanation:**

```bash
barb analyze https://pаypal.com --explain
```

**With OSINT enrichment (DNS + RDAP, opt-in):**

```bash
barb analyze https://suspicious-site.tk/paypal-login --osint
```

**Force fresh OSINT lookups, bypass cache:**

```bash
barb analyze https://suspicious-site.tk/paypal-login --osint --no-cache
```

**Pipe from stdin:**

```bash
cat urls.txt | barb analyze -o csv
```

**Batch summary — aggregate view across N URLs:**

```bash
barb analyze -f urls.txt             # rich output opens with a verdict histogram + top signals
barb analyze -f urls.txt --summary-only  # aggregate block only; per-URL detail suppressed
```

> [!NOTE]
> `--summary-only` affects only rich and console output. JSON, NDJSON, CSV, and STIX output are completely unchanged — piping to a downstream tool works exactly as before.

**Refresh the allowlist from Tranco (opt-in):**

```bash
barb update-data
```

---

### `barb update-data` — opt-in allowlist refresh

```
barb update-data [--top-n N] [--source URL] [--quiet]
```

Downloads the [Tranco top-1M list](https://tranco-list.eu/) over HTTPS and writes
the top `--top-n` domains (default: 5000) to `~/.barb/data/allowlist.json`.
The bundled curated list is **never overwritten** — it is always merged in.

| Flag | Default | Description |
|------|---------|-------------|
| `--top-n` | `5000` | Number of Tranco domains to include |
| `--source` | `https://tranco-list.eu/top-1m.csv.zip` | HTTPS source URL (non-https rejected) |
| `--quiet` | off | Suppress progress messages |

**Key guarantees:**

- **Opt-in only** — `barb analyze` never triggers a download. Only `barb update-data` does.
- **Never automatic** — no background refresh, no scheduled task.
- **HTTPS only** — non-`https://` source URLs are rejected immediately (no network call made).
- **Bundled list is the default** — a user who never runs `update-data` sees the bundled curated list, with zero change in detection behavior.
- **User-override location** — writes to `~/.barb/data/allowlist.json` (`0o600`, directory `0o700`), never to the package data directory.
- **Atomic write** — temp file + `os.replace`; no partial writes visible.
- **No new dependencies** — stdlib `urllib` only.

> **Tradeoff notice:** Running `update-data` EXPANDS false-positive suppression.
> More domains will be treated as known-good after the update, which may reduce
> phishing signals for less-known but legitimate domains.

---

## Output Examples

### Rich Output (default)

```
╭──────────────────────── barb ────────────────────────╮
│ URL       hxxp[://]192[.]168[.]1[.]1/paypal-login    │
│ Verdict   ⚠ SUSPICIOUS                               │
│ Score     4.0                                         │
╰──────────────────────────────────────────────────────╯
 Severity   Analyzer     Finding
 HIGH       ip_url       URL uses IP address instead of domain
 LOW        subdomain    Domain has 4 levels
```

### JSON Output

```bash
barb analyze http://evil.tk/login -o json
```

```json
{
  "url": "http://evil.tk/login",
  "verdict": "SUSPICIOUS",
  "risk_score": 4.0,
  "signals": [
    {"analyzer": "tld", "severity": "MEDIUM", "detail": "Suspicious TLD: .tk"}
  ]
}
```

### NDJSON Output

One compact JSON object per line — suitable for streaming pipelines and log aggregators.

```bash
barb analyze http://evil.tk/login -o ndjson
```

### STIX 2.1 Output

Emits a STIX bundle with `indicator` objects for SUSPICIOUS / HIGH_RISK / PHISHING verdicts (deterministic IDs, confidence mapped from verdict).

```bash
barb analyze http://evil.tk/login -o stix
```

---

## Analyzers

### Heuristic analyzers (offline)

| Analyzer | What it detects | Example |
|----------|----------------|---------|
| **Entropy** | High Shannon entropy in domain/path | `x7k2m9p.evil.com` |
| **Homoglyph** | Unicode confusables + mixed-script labels (Latin+Cyrillic); pure non-ASCII IDN emits a LOW informational signal | `pаypal.com` (Cyrillic 'а') |
| **TLD** | Suspicious top-level domains associated with phishing; data-driven list includes `.tk`, `.xyz`, `.shop`, `.ink`, `.vip`, and others (precision 1.0 maintained on every addition) | `paypal-login.shop` |
| **Subdomain** | Excessive depth / squatting patterns | `secure.paypal.com.evil.com` |
| **Brand** | Brand name in non-brand domain | `paypal-secure.evil.com` |
| **Shortener** | Known URL shortener services | `bit.ly/abc123` |
| **Encoding** | Percent-encoding / punycode abuse | `%70%61%79pal.com` |
| **IP URL** | IP address instead of domain; `@`-obfuscation on a domain host → CRITICAL | `http://192.168.1.1/login`, `paypal.com@evil.com` |
| **Typosquat** | ASCII brand lookalikes via Levenshtein 1–2 + digit↔letter swaps; skips official brand domains | `paypa1.com`, `g00gle.com` |
| **Keyword** | Phishing keywords in path/query (login, verify, secure, webscr, bank, …); one aggregated LOW signal | `/login/verify-account` |
| **Lexical** | URL length, hyphen count, digit ratio; LOW signals | `my-secure-bank-update-2024.com` |
| **File Ext** | Suspicious file extensions in the URL path; double-extension masquerade → HIGH, single executable/script → LOW, archive → INFO | `invoice.pdf.exe`, `setup.ps1` |

### OSINT enrichers (`--osint`)

Opt-in, off by default, fail-open. Queries infrastructure metadata about the domain — **never fetches the analyzed URL**.

| Enricher | What it checks | Signals |
|----------|---------------|---------|
| **DNS** | Resolves the host via `socket.getaddrinfo` (stdlib, timeout 2 s) | HIGH on loopback/sinkhole IP; MEDIUM on private IP or NXDOMAIN |
| **RDAP** | IANA RDAP bootstrap, `urllib` (stdlib, no API key, timeout 5 s) | HIGH if domain <30 days old; MEDIUM if <90 days; LOW if registrant privacy/redacted |
| **crt.sh** | Certificate-transparency log query via crt.sh (Sectigo), `urllib` (stdlib, no API key, timeout 8 s); sends only the hostname | MEDIUM if newest cert <7 days old; LOW if <30 days; INFO if no CT records found |
| **ASN** | Resolves the host to an IP, then queries Team Cymru WHOIS (`whois.cymru.com`, port 43) for the hosting ASN; stdlib socket, no API key, timeout 3 s; sends only the resolved IP | INFO — AS number, name, country, and BGP prefix for analyst pivoting; **no score impact** |

Results are cached per host in `~/.barb/cache.db` (SQLite, TTL 6 h). Use `--no-cache` to force fresh lookups.

---

## Detection quality (measured)

Evaluated against a labeled corpus of **800 URLs** — 300 phishing (OpenPhish feed) + 500 benign (Tranco top-500) — built with `eval/fetch_corpus.py` and scored with `eval/run_eval.py`. Alert tier: verdict ≥ SUSPICIOUS counts as a positive.

| Metric | v1.4.1 (offline, snapshot 2026-06-01) |
|--------|---------------------------------------|
| Precision | **1.00** — zero false positives on 500 benign URLs |
| Recall | **0.07** — 22 of 300 phishing URLs caught |
| False-positive rate | **0.00** — 0 of 500 benign URLs flagged |

`--osint` does **not** improve live-phishing recall: measured on a fresh corpus (snapshot 2026-06-07, barb 1.6.0), recall across the resolving phishing domains was identical with and without it (Δ = 0) — RDAP/crt.sh/ASN caught no live domain the offline core missed. Its only recall contribution is flagging **taken-down (non-resolving) domains** via DNS NXDOMAIN — retro-triage value for IOC-list sweeps, not live detection, at a small false-positive cost. See [docs/osint.md](docs/osint.md#recall-what---osint-does-and-does-not-add-measured) for the live/dead split.

> [!IMPORTANT]
> barb is a **high-precision URL-structure pre-filter**, not a standalone catch-all. Trust a positive — when barb flags SUSPICIOUS or higher, it is reliable. Low recall is by design: barb analyzes URL structure only and never fetches the URL, so phishing on clean domains (`github.io`, `pages.dev`, plain `.com`) is an inherent limit of URL-only heuristics. That recall gap is the downstream pipeline's job: feed barb's JSON into **vex** (reputation/VirusTotal) and **sift** (correlation). `--osint` adds infrastructure *context* (DNS, RDAP age, crt.sh, ASN) and takedown retro-triage — it does **not** measurably lift live-phishing recall.

The repo also includes a **CI regression gate** using a synthetic fixture (precision 1.00 / recall 0.76). That fixture is not a field measurement — it exists to catch score-regression between releases.

Reproduce the corpus numbers yourself:

```bash
python -m eval.fetch_corpus
python -m eval.run_eval --corpus eval/corpus/real.csv
```

---

## Configuration

Create `~/.barb/config.yaml`:

```yaml
scoring:
  weights:
    entropy: 1.0
    homoglyph: 1.5
    brand: 1.2
    typosquat: 1.3
    keyword: 0.6
    lexical: 0.5
  thresholds:
    suspicious: 4
    phishing: 13

explain:
  provider: "template"     # template | anthropic | openai | ollama
  send_url: true           # send defanged URL to LLM
  # ollama_host: "http://localhost:11434"  # local Ollama server (ollama provider only)

output:
  default_format: "rich"
  quiet: false

osint:
  dns_timeout: 2           # seconds per DNS lookup
  rdap_timeout: 5          # seconds per RDAP request
  crtsh_timeout: 8         # seconds per crt.sh request
  asn_timeout: 3           # seconds per ASN (Team Cymru) lookup
  cache_ttl_hours: 6       # SQLite cache TTL (~/.barb/cache.db)

allowlist_check:
  enabled: true            # set false to silence the staleness hint entirely
  max_age_days: 90         # warn when the effective allowlist is older than this
```

**Environment variable:** Set `BARB_LLM_KEY` for cloud LLM API key (Anthropic / OpenAI).

### Ollama (local LLM — no API key, no data leaves host)

Set `provider: ollama` to use a locally running [Ollama](https://ollama.ai) server.
No API key required; all requests go to your machine.

```yaml
explain:
  provider: "ollama"
  model: "llama3.1"              # any model pulled with `ollama pull <model>`
  ollama_host: "http://localhost:11434"  # default; change for remote/custom port
  send_url: false                # maximum privacy: omit URL from prompt
```

If Ollama is unreachable when `--explain` is used, barb automatically falls back to the template explainer and prints a note to stderr — the command always completes.

---

## Comparison

| Feature | barb | VirusTotal URL Scan | URLScan.io | PhishTank |
|---------|------|--------------------|-----------:|-----------|
| Offline analysis | Core offline; opt-in `--osint` for DNS/RDAP | No | No | No |
| API key required | No | Yes | Yes | Optional |
| Heuristic detection | 12 analyzers | Signature-based | Browser-based | Community |
| CLI tool | Yes | Web/API | Web/API | Web/API |
| LLM explanation | Optional | No | No | No |
| Self-hosted | Yes | No | No | No |

**Use barb for** offline heuristic URL triage. **Use [vex](https://github.com/duathron/vex) for** VirusTotal IOC enrichment. Pipe barb JSON output into vex for full enrichment (v1.1).

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | SAFE or LOW_RISK |
| `1` | SUSPICIOUS or HIGH_RISK |
| `2` | PHISHING |
| `3` | Error (invalid input, missing file) |

---

## Development

```bash
git clone https://github.com/duathron/barb.git
cd barb
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest tests/ -v
```

---

## Security

- **No HTTP requests are ever made to analyzed URLs** — this holds unconditionally, including when `--osint` is enabled
- The offline core is pure string-based heuristics with no external calls
- The optional `--osint` flag performs DNS resolution and RDAP lookups *about* the domain (infrastructure metadata only); it never fetches the URL itself
- URL length capped at 2048 characters
- Config directory secured with 0o700 permissions
- LLM and OSINT dependencies are optional extras — core install has zero network deps

### Privacy footprint of `--osint`

The offline core makes **zero** outbound connections. When you opt into `--osint`, barb makes three kinds of request — **never to the analyzed host itself**:

| Connection | Endpoint | What it reveals | Notes |
|------------|----------|-----------------|-------|
| DNS resolution | Your **system resolver** (`/etc/resolv.conf`: ISP/router/corporate DNS, port 53) | The domain being looked up | Same lookup any browser would do |
| RDAP bootstrap | `https://data.iana.org/rdap/dns.json` | That you use barb/RDAP | Fetched at most once per 7 days (cached at `~/.barb/rdap_bootstrap.json`) |
| RDAP query | The TLD's registry RDAP server (e.g. `rdap.verisign.com` for `.com`, `rdap.pir.org` for `.org`) | The domain being investigated | No API key; stdlib `urllib` only |
| crt.sh CT query | `https://crt.sh/` (Sectigo) | The domain being investigated | Reveals domain-of-interest to Sectigo; no API key; stdlib `urllib` only |
| ASN lookup | `whois.cymru.com` port 43 (Team Cymru) | The **resolved IP** of the domain | Sends only the IP, not the URL or hostname; stdlib socket only; no API key |

- The suspect host is **never contacted** — no HTTP GET/HEAD to the URL, no DNS beacon to attacker-controlled infrastructure beyond normal name resolution.
- No credentials are ever transmitted.
- OSINT results are cached per host in `~/.barb/cache.db` (default TTL 6 h), so repeat lookups make no network calls; `--no-cache` forces fresh requests.
- All OSINT calls are **fail-open**: a timeout or error simply drops the enrichment signals and analysis continues offline.

---

## Author

**Christian Huhn** — building security tooling for SOC/DFIR workflows.

- GitHub: [@duathron](https://github.com/duathron)
- LinkedIn: [Christian Huhn](https://www.linkedin.com/in/christian-huhn-76a407114)

## License

MIT License. See [LICENSE.md](LICENSE.md).

---

**Author:** [Christian Huhn](https://github.com/duathron)
