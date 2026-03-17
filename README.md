<p align="center">
  <img src="barb/barb.png" alt="barb logo" width="300"/>
</p>

<h1 align="center">barb</h1>

<p align="center">
  <b>Catch phishing URLs before they catch you.</b>
</p>

<p align="center">
  Heuristic phishing URL analyzer for SOC/DFIR workflows. No API keys. No network requests. Pure offline analysis.
</p>


---

## Features

- **8 heuristic analyzers**: entropy, homoglyph, TLD, subdomain, brand impersonation, URL shortener, encoding abuse, IP-based URLs
- **5-tier verdict**: SAFE / LOW_RISK / SUSPICIOUS / HIGH_RISK / PHISHING
- **Zero API keys required** for core analysis — works fully offline
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

| Analyzer | What it detects | Example |
|----------|----------------|---------|
| **Entropy** | High Shannon entropy in domain/path | `x7k2m9p.evil.com` |
| **Homoglyph** | Unicode confusable characters | `pаypal.com` (Cyrillic 'а') |
| **TLD** | Suspicious top-level domains | `paypal-login.tk` |
| **Subdomain** | Excessive depth / squatting patterns | `secure.paypal.com.evil.com` |
| **Brand** | Brand name in non-brand domain | `paypal-secure.evil.com` |
| **Shortener** | Known URL shortener services | `bit.ly/abc123` |
| **Encoding** | Percent-encoding / punycode abuse | `%70%61%79pal.com` |
| **IP URL** | IP address instead of domain | `http://192.168.1.1/login` |

---

## Configuration

Create `~/.barb/config.yaml`:

```yaml
scoring:
  weights:
    entropy: 1.0
    homoglyph: 1.5
    brand: 1.2
  thresholds:
    suspicious: 4
    phishing: 13

explain:
  provider: "template"     # template | anthropic | openai
  send_url: true           # send defanged URL to LLM

output:
  default_format: "rich"
  quiet: false
```

**Environment variable:** Set `BARB_LLM_KEY` for LLM API key.

---

## Comparison

| Feature | barb | VirusTotal URL Scan | URLScan.io | PhishTank |
|---------|------|--------------------|-----------:|-----------|
| Offline analysis | Yes | No | No | No |
| API key required | No | Yes | Yes | Optional |
| Heuristic detection | 8 analyzers | Signature-based | Browser-based | Community |
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

- **No HTTP requests** are ever made to analyzed URLs
- All analysis is pure string-based heuristics
- URL length capped at 2048 characters
- Config directory secured with 0o700 permissions
- LLM dependencies are optional extras — core install has zero network deps

---

## License

MIT License. See [LICENSE.md](LICENSE.md).

---

**Author:** [Christian Huhn](https://github.com/duathron)
