# barb — Project Documentation

*Recorded by Project Documentation Agent — 2026-03-17*

---

## The Idea

**barb** is a Python CLI tool that performs heuristic analysis of URLs to detect phishing indicators. It was chosen unanimously (5/5) in MeetUp VEX-2026-003 as the second portfolio project following vex (VirusTotal IOC Enrichment Tool). The name was adopted in MeetUp VEX-2026-005 — a barb is the sharp backward-pointing part of a fishhook that catches and holds.

**Core principle:** The tool works entirely offline with zero API keys. All analysis is pure string-based heuristics on the URL itself — no HTTP requests are made to analyzed URLs. An optional `--explain` flag adds LLM-powered natural language explanations for analysts who want context beyond the raw signals.

**Target users:** SOC analysts, DFIR practitioners, security engineers, and anyone triaging suspicious URLs.

**Portfolio context:** Phishing is the most commonly referenced attack vector in security job postings. A tool that demonstrates understanding of phishing infrastructure patterns, combined with clean CLI design and LLM integration, serves as a strong portfolio piece.

---

## Technical Architecture

### Design Patterns (inherited from vex)

| Pattern | Implementation | vex Reference |
|---------|---------------|---------------|
| CLI Framework | Typer with subcommands | `vex/main.py` |
| Data Models | Pydantic v2 BaseModel | `vex/models.py` |
| Analyzer Interface | typing.Protocol (structural typing) | `vex/enrichers/protocol.py` |
| Config System | YAML + env vars + CLI flags, Pydantic validation | `vex/config.py` |
| Terminal Output | Rich panels, tables, color-coded verdicts | `vex/output/formatter.py` |
| Batch Processing | ThreadPoolExecutor + Rich progress bar | `vex/batch.py` |
| URL Defanging | Copied from vex (no cross-project dependency) | `vex/defang.py` |

### Module Structure

```
barb/
├── __init__.py           # __version__, __author__, __repo__
├── __main__.py           # python -m barb
├── main.py               # Typer CLI: analyze, config, version
├── banner.py             # ASCII art banner (fishhook, b&w)
├── config.py             # Pydantic v2 config with priority hierarchy
├── models.py             # AnalysisResult, Signal, RiskVerdict, ParsedURL
├── url_parser.py         # URL decomposition via urllib.parse
├── scoring.py            # Weighted signal aggregation → RiskVerdict
├── defang.py             # URL defanging/refanging (copied from vex)
├── batch.py              # Parallel batch processing
├── version_check.py      # GitHub release check
├── analyzers/
│   ├── protocol.py       # AnalyzerProtocol (typing.Protocol)
│   ├── base.py           # Shared analyzer helpers
│   ├── entropy.py        # Shannon entropy of domain/path
│   ├── homoglyph.py      # Unicode confusable detection
│   ├── tld.py            # Suspicious TLD check
│   ├── subdomain.py      # Subdomain depth & squatting patterns
│   ├── brand.py          # Brand impersonation detection
│   ├── shortener.py      # Known URL shortener detection
│   ├── encoding.py       # Percent-encoding / punycode abuse
│   └── ip_url.py         # IP-based URL detection
├── data/
│   ├── homoglyphs.json   # Unicode confusable character mapping
│   ├── brands.json       # Top brand domains for impersonation check
│   ├── shorteners.json   # Known URL shortener services
│   └── suspicious_tlds.json  # High-risk TLDs
├── explain/
│   ├── protocol.py       # ExplainerProtocol
│   ├── template.py       # Template-based fallback (no LLM)
│   ├── llm.py            # Anthropic + OpenAI integration
│   └── prompt.py         # Prompt templates for LLM
└── output/
    ├── formatter.py      # Rich + console output
    └── export.py         # JSON + CSV export
```

### Config Priority Hierarchy

1. CLI flags (`--threshold`, `--output`, `--config`)
2. Environment variables (`BARB_LLM_KEY`)
3. User config (`~/.barb/config.yaml`)
4. Package defaults (Pydantic model defaults)

### Security Model

1. **No HTTP requests** to analyzed URLs — pure string heuristics
2. **URL length cap:** 2048 characters
3. **File input cap:** 10 MB
4. **No eval/exec** — no dynamic code execution
5. **Secure storage:** Config dir `~/.barb/` with 0o700, config file 0o600
6. **Minimal dependencies:** Typer, Rich, Pydantic, PyYAML, python-dotenv (core only)
7. **Bundled static data** — no runtime network fetches for data files
8. **Input sanitization** — strip null bytes and control characters

---

## Feature Development

### v1.0 — Core Heuristic Analyzer

**8 Heuristic Analyzers (all P0):**

| Analyzer | Signal | Example |
|----------|--------|---------|
| Entropy | High Shannon entropy in domain/path | `x7k2m9p.evil.com` |
| Homoglyph | Unicode confusable characters | `pаypal.com` (Cyrillic 'а') |
| TLD | Suspicious top-level domain | `paypal-login.tk` |
| Subdomain | Excessive depth / squatting | `secure.login.paypal.com.evil.com` |
| Brand | Brand name in non-brand domain | `paypal-secure.evil.com` |
| Shortener | Known URL shortener | `bit.ly/abc123` |
| Encoding | Excessive percent-encoding / punycode | `%70%61%79pal.com` |
| IP URL | IP address instead of domain | `http://192.168.1.1/login` |

**Scoring System:**
- Each analyzer returns `list[Signal]` with severity: INFO (0), LOW (1), MEDIUM (2), HIGH (3), CRITICAL (5)
- Configurable weights per analyzer (default 1.0, adjustable in config.yaml)
- Weighted aggregation → numeric risk score
- 5-tier verdict: SAFE (0) / LOW_RISK (1-3) / SUSPICIOUS (4-7) / HIGH_RISK (8-12) / PHISHING (13+)
- All thresholds configurable

**CLI Interface:**
```
barb analyze <url> [urls...] [-f FILE] [-o FORMAT] [-q] [--explain] [--threshold N]
barb config [--show]
barb version
```

- Exit codes: 0=safe/low, 1=suspicious/high, 2=phishing, 3=error
- Defang on by default for TTY output only
- Stdin + file + multi-argument batch support
- Output formats: Rich (default TTY), console, JSON, CSV

**LLM Integration (--explain):**
- Template-based fallback as default (no API key needed)
- Anthropic Claude + OpenAI as optional providers
- LLM receives defanged URL + signals (configurable: `send_url: true/false`)
- Dependencies as optional extras: `pip install barb-phish[llm]`
- ExplainerProtocol enables easy addition of new providers

**Publication:**
- GitHub: https://github.com/duathron/barb
- PyPI: `pip install barb-phish`
- MIT License
- CI: pytest + ruff lint on PR
- CD: PyPI publish on version tag

### v1.1 — Backlog (from MeetUp decisions)

1. **Ollama local LLM support** — for airgapped/privacy-sensitive environments (AI Specialist request, deferred for timeline)
2. **Domain age via WHOIS** — network-based enrichment (deferred to keep v1.0 offline-only)
3. **STIX 2.1 export** — standardized threat intelligence format
4. **vex integration** — pipe JSON between tools for combined IOC + URL analysis
5. **SQLite cache** — avoid re-analyzing known URLs
6. **Plugin system** — custom analyzers via entry points
7. **Re-vote: `send_url` default** — revisit after user feedback (Code Security Agent dissent noted)

---

## Design Decisions

### Decision 1: Single `analyze` subcommand (not triage/investigate split)
**Vote:** Unanimous (7/7)
**Rationale:** Unlike vex where triage and investigate have fundamentally different API call depths, every URL in this tool receives the same heuristic battery. Batch processing is simply parallelized single analysis. One subcommand keeps the interface clean.

### Decision 2: 5-tier verdict system
**Vote:** 6 For / 1 Abstain
**Rationale:** UX Design and Marketing initially preferred 3-tier (SAFE/SUSPICIOUS/PHISHING) for simplicity. SOC Analyst and Architect argued 5-tier enables granular `--threshold` filtering and exit code mapping. UX Design was convinced by clear color differentiation (green/blue/yellow/orange/red). Marketing agreed to show 3 common verdicts in README for messaging simplicity while supporting 5 technically.

### Decision 3: Template-based explanation as default
**Vote:** Unanimous (7/7)
**Rationale:** The tool must work without any API key. The template explainer uses structured formatting from signal data to produce human-readable explanations. LLM integration is additive, not required.

### Decision 4: Defanged URL sent to LLM by default
**Vote:** 5 For / 1 Against / 1 Abstain
**Rationale:** Code Security Agent dissented, preferring `send_url: false` for privacy. AI Specialist argued the LLM needs URL context for useful explanations (e.g., identifying which character is a homoglyph). Compromise: default `true` with clear documentation and easy opt-out via config.

### Decision 5: Ollama deferred to v1.1
**Vote:** 5 For / 1 Against / 1 Abstain
**Rationale:** AI Specialist preferred Ollama in v1.0 for airgapped environments. Team consensus: the ExplainerProtocol architecture makes Ollama trivial to add in v1.1. The 2-3 evening constraint requires focus on core heuristics.

### Decision 6: Copy defang.py (no vex dependency)
**Vote:** Unanimous (7/7)
**Rationale:** Zero cross-project coupling. Each tool is independently installable and deployable. The defang module is small and stable enough to copy.

### Decision 7: LLM dependencies as optional extras
**Vote:** Unanimous (7/7)
**Rationale:** Core install has 5 dependencies only (typer, rich, pydantic, pyyaml, python-dotenv). LLM packages (anthropic, openai) add significant dependency weight and are only needed for `--explain` with cloud providers. `pip install barb-phish[llm]` keeps the default install minimal.

### Decision 8: CI from v1.0
**Vote:** Unanimous (7/7)
**Rationale:** Improvement over vex v1.0 which shipped without CI. pytest + ruff lint on PR ensures quality from the start. This is a portfolio project — visible CI adds credibility.

### Decision 9: Name `barb` (MeetUp VEX-2026-005)
**Vote:** Unanimous (2/2 — Marketing + UX Design)
**Rationale:** A barb is the sharp backward-pointing part of a fishhook — the mechanism that catches and holds. Short (4 chars), no CLI or PyPI conflicts, phonetically pairs with `vex`. PyPI name `barb-phish` uses suffix pattern from vex (`vex-ioc`). Banner: geometric fishhook in black & white (distinct from vex's cyan robot).

---

## Current Status

**Phase:** Project scaffold created and renamed to `barb`. Ready for implementation.
**Next steps:** Evening 1 — Foundation (config, models, URL parser, analyzer protocol, data files).

---

*Document maintained by Project Documentation Agent. English only per documentation policy.*
