# barb — Project Documentation

*Recorded by Project Documentation Agent — 2026-03-17, maintained through v1.6.1 + on-main features pending v1.7.0 (2026-06-12)*

> This document covers barb's full history: the original design phase (the
> records below under "The Idea" and "Design Decisions" are the v1.0 MeetUp
> design history and are kept verbatim) and the shipped releases v1.0.0 →
> v1.6.0. For the authoritative per-release change list, see `CHANGELOG.md`.

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
| Batch Processing | Sequential loop (offline heuristics are microsecond-fast; no parallelism needed) | `barb/main.py` |
| URL Defanging | Copied from vex (no cross-project dependency) | `vex/defang.py` |

### Module Structure (current — v1.6.0)

This is the real package as shipped, not the original v1.0 plan. barb grew from
8 to **12 offline analyzers** (the `typosquat`, `keyword`, `lexical` analyzers
arrived in v1.2.0; `file_ext` in v1.3.0), gained an `enrichers/` package for
opt-in OSINT (DNS, RDAP, crt.sh, ASN), an Ollama explain provider, a top-level
`eval/` detection-quality harness (a dev tool, not shipped in the wheel), and
the shared-library integration via `shipwright_kit`.

```
barb/
├── __init__.py           # __version__, __author__, __repo__
├── __main__.py           # python -m barb
├── main.py               # Typer CLI: analyze, config, version, manual, update-data
├── banner.py             # figlet-style banner (black & white)
├── config.py             # AppConfig (Pydantic v2); delegates resolve→load→validate
│                         #   skeleton + secure app-dir to shipwright_kit.config
├── models.py             # AnalysisResult, Signal, RiskVerdict, ParsedURL
├── url_parser.py         # URL decomposition via urllib.parse
├── scoring.py            # Weighted signal aggregation + severity-floor → RiskVerdict
├── defang.py             # URL defang / refang (offline string transform)
├── allowlist.py          # Tranco allowlist suppression for domain-based signals
├── cache.py              # SQLite OSINT result cache (~/.barb/cache.db, TTL)
├── data_update.py        # `update-data` — opt-in HTTPS allowlist refresh
├── version_check.py      # GitHub release check
├── analyzers/            # 12 offline heuristics (no network)
│   ├── protocol.py       # AnalyzerProtocol (typing.Protocol)
│   ├── base.py           # Shared analyzer helpers
│   ├── entropy.py        # Shannon entropy of domain/path
│   ├── homoglyph.py      # Unicode confusable + mixed-script detection
│   ├── tld.py            # Suspicious TLD check
│   ├── subdomain.py      # Subdomain depth & squatting patterns
│   ├── brand.py          # Brand impersonation detection
│   ├── shortener.py      # Known URL shortener detection
│   ├── encoding.py       # Percent-encoding / punycode abuse
│   ├── ip_url.py         # IP-based URL + @-obfuscation detection
│   ├── typosquat.py      # ASCII lookalikes (Levenshtein 1–2, digit↔letter)
│   ├── keyword.py        # Phishing keywords in path/query (aggregated LOW)
│   ├── lexical.py        # URL length / hyphen count / host digit ratio
│   └── file_ext.py       # Suspicious file extensions in the URL path
├── enrichers/            # opt-in OSINT (--osint); network, fail-open, never fetches URL
│   ├── protocol.py       # EnricherProtocol
│   ├── dns.py            # DNS resolution (stdlib socket): sinkhole/loopback/NXDOMAIN
│   ├── rdap.py           # RDAP domain registration age (IANA bootstrap, stdlib urllib)
│   ├── crtsh.py          # crt.sh certificate-transparency recency
│   └── asn.py            # ASN context (Team Cymru WHOIS) — INFO only, no score impact
├── data/
│   ├── homoglyphs.json   # Unicode confusable character mapping
│   ├── brands.json       # Brand domains + official-domain allow-lists
│   ├── shorteners.json   # Known URL shortener services
│   ├── suspicious_tlds.json  # High-risk TLDs
│   └── allowlist.json    # Curated Tranco allowlist (FP suppression baseline)
├── explain/
│   ├── protocol.py       # ExplainerProtocol
│   ├── template.py       # Template-based fallback (no LLM)
│   ├── llm.py            # Anthropic + OpenAI + Ollama providers
│   └── prompt.py         # Prompt templates for LLM
└── output/
    ├── formatter.py      # Rich + console output
    └── export.py         # JSON, NDJSON, CSV, STIX 2.1 export

eval/                     # dev-only detection-quality harness (not in the wheel)
├── run_eval.py           # precision/recall/F1 vs a labeled CSV; CI regression gate
│                         #   delegates corpus/binarization/metrics to shipwright_kit.eval
├── fetch_corpus.py       # build a real corpus (OpenPhish + Tranco → gitignored)
├── fixtures/             # committed synthetic sample corpus
└── corpus/               # local real corpus (gitignored)
```

### Config Priority Hierarchy

1. CLI flags (`--threshold`, `--output`, `--config`)
2. Environment variables (`BARB_LLM_KEY` → overrides `explain.api_key`)
3. User config (`~/.barb/config.yaml`)
4. Package defaults (Pydantic model defaults)

barb keeps its own `AppConfig` Pydantic schema (scoring weights/thresholds,
explain, output, update-check, OSINT timeouts) and its `BARB_LLM_KEY` override,
but as of v1.6.0 the **resolve → load → validate** skeleton and the secure
app-directory creation (`~/.barb`, 0o700) are delegated to
`shipwright_kit.config` so the boilerplate is shared across the Shipwright
tools rather than copied.

### Dependencies

Core runtime (always installed): `typer`, `rich`, `pydantic`, `pyyaml`,
`python-dotenv`, and — since v1.6.0 — **`shipwright-kit>=0.6.0,<0.7.0`** (the
shared Shipwright library, resolved from PyPI; imported at runtime by
`barb/config.py` and by the eval harness). Cloud LLM providers are an optional
extra: `pip install barb-phish[llm]` adds `anthropic` and `openai`. Dev tooling
(`pytest`, `ruff`, `hypothesis`) lives in a PEP-735 `[dependency-groups] dev`
group, installed with `uv sync --dev`.

### Security Model

1. **Never-fetch wall:** barb never issues any HTTP request to the *analyzed
   URL* — the offline analyzers are pure string heuristics. The opt-in
   `--osint` enrichers query infrastructure *about* the domain (DNS, RDAP,
   crt.sh, ASN) and never the URL itself, are off by default, and fail open.
2. **URL length cap:** 2048 characters
3. **File input cap:** 10 MB
4. **No eval/exec** — no dynamic code execution
5. **Secure storage:** Config dir `~/.barb/` with 0o700, config and
   user-override data files written 0o600 (atomic `os.replace`)
6. **Lean dependencies:** Typer, Rich, Pydantic, PyYAML, python-dotenv,
   shipwright-kit (core); cloud LLM providers are an optional `[llm]` extra
7. **Bundled static data** — no automatic runtime network fetches for data
   files; the `update-data` refresh is opt-in and HTTPS-only
8. **Input sanitization** — strip null bytes and control characters; defanged
   inputs are refanged with an offline string transform (still never fetched)

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
- CD: PyPI publish on version tag (see "Publication" below)

### v1.0 backlog (from MeetUp decisions)

The original v1.0 MeetUp deferred a backlog: Ollama local-LLM support, domain
age via WHOIS, STIX 2.1 export, vex pipe integration, a SQLite cache, a plugin
system, and a re-vote on the `send_url` default. The "Version History" section
below records which of these actually shipped (Ollama, WHOIS-via-RDAP, STIX,
SQLite cache, vex pipe-only) and which were rejected (plugin system —
single-purpose tool, analyzers are already Protocol-extensible).

---

## Feature Development / Version History

Every release is grounded in `CHANGELOG.md`. barb follows Semantic Versioning;
each version is shipped to PyPI as `barb-phish` and (from v1.5.0 on) gets a
parallel GitHub Release.

### v1.0.0 — Initial release (2026-03-18)

The heuristic phishing-URL analyzer as designed: **8 offline analyzers**
(entropy, homoglyph, TLD, subdomain, brand, shortener, encoding, IP-URL), the
5-tier verdict (`SAFE` / `LOW_RISK` / `SUSPICIOUS` / `HIGH_RISK` / `PHISHING`),
`--explain` with a template default and optional Anthropic/OpenAI providers
(`[llm]` extra), Rich / console / JSON / CSV output, sequential URL analysis,
TTY defanging, and the exit-code contract (0 safe/low, 1
suspicious/high, 2 phishing, 3 error). CI (pytest matrix + ruff) and tag-driven
PyPI publishing (`barb-phish`) shipped from day one.

### v1.1.0 — OSINT enrichment (2026-04-02)

The first deferred backlog item landed: **opt-in network enrichment** behind a
`--osint` flag, fail-open (an enricher failure never blocks analysis). Two
enrichers, both stdlib-only with no API key:

- **DNS resolution** (`socket.getaddrinfo`) — sinkhole/loopback and NXDOMAIN
  signals.
- **RDAP** (IANA bootstrap, `urllib`) — domain registration age and
  privacy-redaction signals. RDAP (RFC 7480–7484) replaced the planned
  `python-whois` dependency, so no `[osint]` extra was needed.

New `osint` config keys (`dns_timeout`, `rdap_timeout`, `cache_ttl_hours`).

### v1.2.0 — Offline heuristic upgrade + scoring tuning (2026-05-30)

Three new offline analyzers and a scoring overhaul:

- **`typosquat`** — ASCII brand lookalikes via Levenshtein distance 1–2 and
  digit↔letter substitution (`paypa1.com`, `g00gle.com`), skipping official
  brand domains.
- **`keyword`** — one aggregated LOW signal for phishing keywords in the
  path/query (`login`, `verify`, `secure`, `webscr`, `bank`, …).
- **`lexical`** — LOW signals for URL length, hyphen count, and host digit
  ratio.
- Homoglyph **mixed-script** detection (Latin + Cyrillic in one label); pure
  non-ASCII IDN labels now emit an informational LOW signal instead of
  inflating the score.
- Curated `data/allowlist.json` (71 entries) + **allowlist suppression** —
  domain-based signals are suppressed for known-good registrable domains while
  path/userinfo signals still fire (a trusted domain is not a safe URL).
- **SQLite OSINT cache** (`~/.barb/cache.db`) with configurable TTL and a
  `--no-cache` flag.
- Scoring: `@`-obfuscation on a domain host (`paypal.com@evil.com`) is now
  **CRITICAL**; a **severity-floor** rule (any CRITICAL floors the verdict at
  `HIGH_RISK`, any HIGH at `SUSPICIOUS` — only escalates, never lowers).

### v1.3.0 — "Prove & Integrate" (2026-05-31)

Detection quality became measurable and machine-output broadened:

- **`file_ext`** analyzer (the **12th** offline heuristic) — double-extension
  masquerade (`invoice.pdf.exe`) → HIGH, single executable/script extension →
  LOW, archive extension → INFO.
- **NDJSON** (`-o ndjson`) and **STIX 2.1** (`-o stix`) output formats. The
  STIX bundle emits `indicator` objects for URLs scored SUSPICIOUS or higher,
  with deterministic IDs and verdict-mapped confidence.
- **Offline evaluation harness** (`eval/`, a dev tool) measuring
  precision/recall/F1 against a labeled CSV, wired into CI as a
  detection-quality regression gate (`--min-precision` / `--min-recall`).
- CLI hardening: empty/malformed URLs and unknown `--output` values are now
  rejected with a clear error and exit code 3; a top-level `--version` flag was
  added; Rich output hides INFO-severity signals when the verdict is SAFE.

### v1.4.0 — "Enrichment & Currency" (2026-06-01)

The `--osint` enricher set grew from two to **four**, all opt-in, fail-open,
stdlib-only, and never fetching the analyzed URL:

- **crt.sh** certificate-transparency enricher — recently-issued-cert recency
  signal (MEDIUM < 7 d, LOW < 30 d, INFO if no CT records); sends only the
  hostname.
- **ASN enrichment** (Team Cymru WHOIS over stdlib socket) — an INFO-only
  context signal carrying the resolved IP's AS number, name, country and BGP
  prefix; analyst pivot context, zero score impact.
- **Ollama explain provider** (`provider: ollama`) — local-LLM summaries with
  no data leaving the host and no API key; falls back to the template explainer
  if Ollama is unreachable.
- **`update-data`** command — opt-in HTTPS refresh of the Tranco-based
  allowlist into a user-override file (`~/.barb/data/allowlist.json`); never
  automatic, non-HTTPS rejected, atomic write with `0o600`, bundled curated
  list stays the default.
- Full user manual (`docs/MANUAL.md`) and README badges.

At this point barb is at its current shape: **12 offline analyzers**, `--osint`
= DNS + RDAP + crt.sh + ASN.

### v1.4.1 — Detection-quality patch + honesty (2026-06-01)

A real-corpus run (OpenPhish + Tranco, via the new `eval/fetch_corpus.py`)
exposed brand/typosquat **false positives on legitimate domains** — e.g.
`dns.google` scoring PHISHING because `"com"` matched brand `"zoom"` and the
`"ing"` bank brand fired on `booking.com`. On an 800-URL corpus (300 phishing /
500 benign, alert tier SUSPICIOUS) the fixes moved:

| Metric    | Before | After  |
|-----------|--------|--------|
| Precision | 0.4597 | 1.0000 |
| FP        | 67     | 0      |
| Recall    | 0.1900 | 0.0733 |

The three fixes: typosquat de-stacking + short-label/dist-2 length guards;
brand own-registrable-domain skip + short-brand whole-token guard + expanded
official-domain lists (Google CDN/regional domains, Amazon, Apple, …); and five
measured abuse-heavy TLDs added (`.cfd`, `.help`, `.sbs`, `.lat`, `.casa`). The
35 "lost" true positives were false positives in disguise — correct catches for
the wrong reason. A "Detection quality (measured)" section was added to the
README and manual with the honest pre-filter framing.

### v1.5.0 — Documentation + built-in manual (2026-06-01)

- A comprehensive **vex-style `docs/` set** (`getting-started.md`,
  `commands.md`, `analyzers.md`, `osint.md`, `output-formats.md`,
  `configuration.md`, `pipeline.md`, plus a `docs/README.md` index).
- A built-in **`barb manual`** command — a terminal usage guide with six topics
  (`analyzers`, `osint`, `output`, `config`, `pipeline`, `examples`) plus an
  overview mode. The new command is why this is a minor (not patch) bump.
- `publish.yml` gained a **GitHub Release** job (`softprops/action-gh-release`)
  that runs parallel to the PyPI publish, both gated on the test job — one tag
  push ships both.

### v1.5.1 — Accept defanged IOCs on input (2026-06-01)

SOC analysts paste defanged indicators straight from reports. barb previously
rejected `hxxp://paypal[.]com@evil[.]tk` with "Invalid IPv6 URL"; it now
**refangs every input URL before parsing** — `hxxp(s)://`, `[.]`/`(.)`/`[dot]`,
`[at]`, `[://]`, fullwidth Unicode, zero-width characters. This is a pure
offline string transform (it never fetches the URL), is idempotent, and
preserves IPv6 (`[::1]`). The refang patterns were ported from the sibling
`sift` tool.

### v1.6.0 — Shipwright onboarding (2026-06-05)

barb began consuming the shared **shipwright-kit** library (the common
Shipwright engine, published to PyPI and consumed by vex, barb, and sift):

- **Eval delegates** to `shipwright_kit.eval` — corpus loading, binarization,
  the confusion tally and the metric math now come from the shared harness.
  barb keeps its own Rich rendering and per-tier breakdown. Eval numbers are
  byte-identical.
- **The eval `--json` output now carries a `schema_version` field** (the N6
  schema-contract), and a guard test pins it, so a change to the shared eval
  result shape can't silently break consumers.
- **Config delegates** to `shipwright_kit.config` (the resolve→load→validate
  skeleton + secure app-dir), while barb keeps its `AppConfig` schema and the
  `BARB_LLM_KEY` override.
- The dependency is **`shipwright-kit>=0.6.0,<0.7.0` resolved from PyPI**
  (previously a git URL), so `pip install barb-phish` resolves cleanly.

**Two packaging bugs were caught and fixed at publish time:**

1. `shipwright-kit` was declared only in `[dependency-groups] dev`, but
   `barb/config.py` imports it **at runtime** — so a plain `pip install
   barb-phish` would have raised `ImportError`. It was moved to
   `[project.dependencies]`, and a clean-room install verified the fix.
2. The `publish.yml` gate ran `pip install .[dev]` followed by a bare `ruff` —
   but dev tools live in a PEP-735 `[dependency-groups]` block, and pip's
   `[dev]` *extra* does not install dependency-groups, so the step failed with
   `ruff: command not found` (silently blocking releases since the dep-groups
   migration). The gate was switched to `uv sync --dev` + `uv run`.

**Why share an engine.** Pulling eval and config into shipwright-kit means a
fix to the corpus loader, the metric math, or the config resolver is made
**once and propagates to all three tools** (vex / barb / sift) instead of being
copied and drifting per project. The `schema_version` contract makes that
shared shape an explicit, test-guarded API rather than an implicit one.

### v1.6.1 — `__version__` fix + attribution (2026-06-07)

A release-please run on top of v1.6.0:

- **`__version__` literal fix** — `barb/__init__.py` was reporting `1.5.1` while the installed dist was `1.6.0`; corrected to `1.6.1` and enforced by shipwright's `python-ci.yml@v0.7.0` version-consistency guard.
- The `release-please` config now includes a `generic` updater covering `barb/__init__.py` and an `x-release-please-version` annotation so future bumps keep dist and import versions in sync (needed because the dist name `barb-phish` ≠ import package `barb`).
- Attribution metadata (`__author__`, `__repo__`) added to `barb/__init__.py`.
- `--osint` honesty docs (recall investigation results) finalized.

### On-main pending v1.7.0 (HEAD as of 2026-06-12)

Three batches of work are on `main`, Skeptic-approved, and will roll into the `release-please` 1.7.0 PR.

#### B1 — Abuse-TLD list: `.shop`, `.ink`, `.vip` added

Three generic gTLDs were added to `data/suspicious_tlds.json` after corpus verification (300 OpenPhish / 500 Tranco, snapshot 2026-06-11). All three met the inclusion threshold: corpus `phishing ≥ 2 / benign = 0` plus external abuse-corroboration. Country-code TLD candidates (`.id`, `.et`, `.bi`, `.py`, `.nf`, `.bn`) were **held** — 2–4 phishing hits on a country-code TLD is a sample artifact, not a precision guarantee. Measured impact on the 800-URL corpus: precision 1.0000 → 1.0000 (FP = 0), recall 0.1567 → 0.1633. No two-tier severity change (data did not support HIGH). This is a data-file-only change; no analyzer logic was altered.

#### B2 — Offline allowlist-staleness warning

barb now prints a one-line stderr hint when the effective Tranco allowlist (user override at `~/.barb/data/allowlist.json`, or the bundled curated list) is older than `allowlist_check.max_age_days` (default 90):

```
  allowlist is N days old — run `barb update-data` to refresh
```

The check reads only the file modification time — no network call, no blocking. It is emitted alongside the banner (before per-URL output) and routes to stderr, so machine output on stdout is unaffected. It can be silenced via `allowlist_check.enabled: false` in `~/.barb/config.yaml`. Source: `barb/allowlist_staleness.py`.

#### B3 — Aggregated batch summary + `--summary-only`

For N>1 URLs, rich and console output now open with an **aggregate summary block** before per-URL results. The block includes a verdict histogram, the top signals seen across the batch, and the share of results at or above `--threshold`.

The new `--summary-only` flag (confirmed in `barb analyze --help`) suppresses the per-URL detail and shows only the aggregate block. It has no effect on JSON, NDJSON, CSV, or STIX output — machine formats are completely unchanged.

### Identity — what barb is (and is not)

A MeetUp on 2026-06-01 fixed barb's identity: **barb is a high-precision URL
pre-filter, not a standalone phishing catch-all.** Its measured real-corpus
recall of roughly **7%** (precision 1.00, FP-rate 0.00 on the 800-URL offline
corpus) is **by design**, a direct consequence of the never-fetch wall: barb
only ever inspects URL *structure* and opt-in *infrastructure-about-the-domain*
signals. Phishing that uses clean URLs on legitimate hosting carries no
URL-structural tell, so catching it requires fetching and inspecting content or
reputation — that is the job of the downstream tools (`vex`, `sift`) and the
pipeline, not of barb. The team rejected lowering thresholds to chase recall
(it reintroduces false positives) and publishes the honest precision/recall
numbers in the docs. The one wall-compliant recall lever left to investigate is
the marginal recall of `--osint` (RDAP age + crt.sh recency) on a live corpus.

---

## Design Decisions

### Decision 1: Single `analyze` subcommand (not triage/investigate split)
**Vote:** Unanimous (7/7)
**Rationale:** Unlike vex where triage and investigate have fundamentally different API call depths, every URL in this tool receives the same heuristic battery. barb analyzes URLs sequentially — offline heuristics are microsecond-fast, so parallelism was never needed. One subcommand keeps the interface clean.

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

## Publication

- **GitHub:** https://github.com/duathron/barb (tags v1.0.0 → v1.6.0; from
  v1.5.0 onward `publish.yml` auto-creates a parallel GitHub Release from the
  CHANGELOG section).
- **PyPI:** published as **`barb-phish`** (install: `pip install barb-phish`;
  CLI command and import package: `barb`).
- **Publishing flow:** a version tag triggers `publish.yml`, which is gated on
  the test job (ruff + pytest via `uv`) and publishes to PyPI through an **OIDC
  Trusted Publisher**. The publish job runs under a `pypi` GitHub **Environment**
  configured with a **required human reviewer**, so no release reaches PyPI
  without an explicit approval and a green build.
- **License:** MIT.

---

## Current Status

**Phase:** **v1.6.1 shipped** (2026-06-07) — live on PyPI as `barb-phish 1.6.1`. **v1.7.0 pending** (release-please PR open) — rolls in B1/B2/B3 from main.

- 12 offline analyzers; `--osint` enrichment over DNS + RDAP + crt.sh + ASN
  (opt-in, fail-open); `--explain` with template / Anthropic / OpenAI / Ollama
  providers; Rich / console / JSON / NDJSON / CSV / STIX 2.1 output.
- Consumes the shared **shipwright-kit** library from PyPI
  (`>=0.6.0,<0.7.0`): eval delegates to `shipwright_kit.eval` (with the
  `schema_version` N6 contract and a guard test), config to
  `shipwright_kit.config`.
- **On main (pending 1.7.0):** B1 abuse-TLD additions (`.shop`/`.ink`/`.vip`, precision 1.0 held); B2 offline allowlist-staleness warning (stderr, file-mtime, opt-outable); B3 aggregated batch summary + `--summary-only` (machine formats unchanged). 395 tests, Skeptic clean-APPROVE.
- **Identity:** high-precision URL pre-filter — real-corpus precision 1.00 /
  recall ~0.07 / FP-rate 0.00, recall capped by design (the never-fetch wall;
  content/reputation recall is the downstream vex/sift job).
- **`--osint` recall measured (2026-06-07):** adds zero live-phishing recall (Δ = 0 across 123 resolving domains); retro-triage value only (DNS NXDOMAIN on taken-down domains). Documented honestly in `docs/osint.md`.

---

*Document maintained by Project Documentation Agent. English only per documentation policy.*
