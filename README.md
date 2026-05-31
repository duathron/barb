<p align="center">
  <img src="barb/barb.png" alt="barb logo" width="300"/>
</p>

<h1 align="center">barb</h1>

<p align="center">
  <b>Catch phishing URLs before they catch you.</b>
</p>

<p align="center">
  Heuristic phishing URL analyzer for SOC/DFIR workflows. Offline core — no API keys, never fetches the analyzed URL. Optional <code>--osint</code> flag adds DNS/RDAP enrichment.
</p>


---

## Features

- **11 heuristic analyzers**: entropy, homoglyph, TLD, subdomain, brand impersonation, URL shortener, encoding abuse, IP-based URLs, typosquat, keyword, lexical
- **5-tier verdict**: SAFE / LOW_RISK / SUSPICIOUS / HIGH_RISK / PHISHING with severity-floor escalation
- **Zero API keys required** for core analysis — offline, no external calls
- **Opt-in `--osint` enrichment**: DNS resolution + RDAP registration lookups (stdlib only, no API key); never fetches the analyzed URL
- **Allowlist false-positive suppression**: ~71 known-good domains suppress noisy domain-based signals; path/query signals still fire
- **OSINT result cache**: SQLite cache at `~/.barb/cache.db` (default TTL 6 h); bypass with `--no-cache`
- **Output formats**: Rich tables, console, JSON, CSV
- **`--explain` flag**: template-based explanation by default, optional LLM (Anthropic Claude, OpenAI)
- **Batch processing**: analyze URL lists from files, stdin, or multiple arguments
- **Automation-ready**: exit codes (0=safe, 1=suspicious, 2=phishing, 3=error), `--threshold` filtering
- **IOC defanging**: automatic in terminal output (`hxxps[://]evil[.]com`)
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

---

## Analyzers

### Heuristic analyzers (offline)

| Analyzer | What it detects | Example |
|----------|----------------|---------|
| **Entropy** | High Shannon entropy in domain/path | `x7k2m9p.evil.com` |
| **Homoglyph** | Unicode confusables + mixed-script labels (Latin+Cyrillic); pure non-ASCII IDN emits a LOW informational signal | `pаypal.com` (Cyrillic 'а') |
| **TLD** | Suspicious top-level domains | `paypal-login.tk` |
| **Subdomain** | Excessive depth / squatting patterns | `secure.paypal.com.evil.com` |
| **Brand** | Brand name in non-brand domain | `paypal-secure.evil.com` |
| **Shortener** | Known URL shortener services | `bit.ly/abc123` |
| **Encoding** | Percent-encoding / punycode abuse | `%70%61%79pal.com` |
| **IP URL** | IP address instead of domain; `@`-obfuscation on a domain host → CRITICAL | `http://192.168.1.1/login`, `paypal.com@evil.com` |
| **Typosquat** | ASCII brand lookalikes via Levenshtein 1–2 + digit↔letter swaps; skips official brand domains | `paypa1.com`, `g00gle.com` |
| **Keyword** | Phishing keywords in path/query (login, verify, secure, webscr, bank, …); one aggregated LOW signal | `/login/verify-account` |
| **Lexical** | URL length, hyphen count, digit ratio; LOW signals | `my-secure-bank-update-2024.com` |

### OSINT enrichers (`--osint`)

Opt-in, off by default, fail-open. Queries infrastructure metadata about the domain — **never fetches the analyzed URL**.

| Enricher | What it checks | Signals |
|----------|---------------|---------|
| **DNS** | Resolves the host via `socket.getaddrinfo` (stdlib, timeout 2 s) | HIGH on loopback/sinkhole IP; MEDIUM on private IP or NXDOMAIN |
| **RDAP** | IANA RDAP bootstrap, `urllib` (stdlib, no API key, timeout 5 s) | HIGH if domain <30 days old; MEDIUM if <90 days; LOW if registrant privacy/redacted |

Results are cached per host in `~/.barb/cache.db` (SQLite, TTL 6 h). Use `--no-cache` to force fresh lookups.

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
  provider: "template"     # template | anthropic | openai
  send_url: true           # send defanged URL to LLM

output:
  default_format: "rich"
  quiet: false

osint:
  dns_timeout: 2           # seconds per DNS lookup
  rdap_timeout: 5          # seconds per RDAP request
  cache_ttl_hours: 6       # SQLite cache TTL (~/.barb/cache.db)
```

**Environment variable:** Set `BARB_LLM_KEY` for LLM API key.

---

## Comparison

| Feature | barb | VirusTotal URL Scan | URLScan.io | PhishTank |
|---------|------|--------------------|-----------:|-----------|
| Offline analysis | Core offline; opt-in `--osint` for DNS/RDAP | No | No | No |
| API key required | No | Yes | Yes | Optional |
| Heuristic detection | 11 analyzers | Signature-based | Browser-based | Community |
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

- The suspect host is **never contacted** — no HTTP GET/HEAD to the URL, no DNS beacon to attacker-controlled infrastructure beyond normal name resolution.
- No credentials are ever transmitted.
- OSINT results are cached per host in `~/.barb/cache.db` (default TTL 6 h), so repeat lookups make no network calls; `--no-cache` forces fresh requests.
- All OSINT calls are **fail-open**: a timeout or error simply drops the enrichment signals and analysis continues offline.

---

## License

MIT License. See [LICENSE.md](LICENSE.md).

---

**Author:** [Christian Huhn](https://github.com/duathron)
