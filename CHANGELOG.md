# Changelog

All notable changes to **barb** are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.2.0] - 2026-05-30

### Added
- `typosquat` analyzer — detects ASCII brand lookalikes via Levenshtein distance (1–2) and digit↔letter substitution (e.g. `paypa1.com`, `g00gle.com`), skipping official brand domains.
- `keyword` analyzer — one aggregated LOW signal for phishing keywords in the URL path/query (`login`, `verify`, `secure`, `webscr`, `bank`, …).
- `lexical` analyzer — LOW signals for URL length, hyphen count, and digit ratio of the host.
- Mixed-script label detection in the homoglyph analyzer (e.g. Latin + Cyrillic in one label).
- Informational LOW signal for internationalized (non-ASCII) domain labels.
- Curated `data/allowlist.json` (71 entries) + allowlist suppression: domain-based signals are suppressed for known-good registrable domains while path/userinfo signals still fire.
- SQLite OSINT result cache (`~/.barb/cache.db`) with configurable TTL (`osint.cache_ttl_hours`, default 6h) and a `--no-cache` flag.

### Changed
- `@`-obfuscation on a domain host (`paypal.com@evil.com`) is now flagged **CRITICAL** (previously unflagged).
- Verdict severity-floor: any CRITICAL signal floors the verdict at `HIGH_RISK`, any HIGH at `SUSPICIOUS` (floor only escalates, never lowers a score-based verdict).
- Homoglyph per-character CRITICAL is now emitted only on mixed-script labels; pure non-ASCII IDN labels no longer inflate the risk score.
- `risk_score` is rounded to 2 decimal places.

### Fixed
- Batch input (`--file` and stdin) now skips blank lines and `#` comment lines instead of analyzing them as URLs.
- `--no-defang` is now honored in JSON output (`defanged_url` equals the original URL).
- `barb version` now reports the correct version.

### Security
- New typosquat, mixed-script, and `@`-obfuscation handling close ASCII-lookalike, IDN-spoofing, and userinfo-masking detection gaps.

## [1.1.0] - 2026-04-02

### Added
- Opt-in OSINT enrichment via `--osint` (network-dependent, fail-open):
  - DNS resolution enricher (`socket.getaddrinfo`, stdlib) — sinkhole/loopback and NXDOMAIN signals.
  - RDAP enricher (IANA bootstrap, stdlib `urllib`, no API key) — domain registration age and privacy-redaction signals.
- `osint` configuration: `dns_timeout`, `rdap_timeout`, `cache_ttl_hours`.

## [1.0.0] - 2026-03-18

### Added
- Initial release of barb — heuristic phishing URL analyzer for SOC/DFIR workflows.
- 8 offline heuristic analyzers: entropy, homoglyph, TLD, subdomain, brand, shortener, encoding, IP-URL.
- 5-tier verdict: `SAFE` / `LOW_RISK` / `SUSPICIOUS` / `HIGH_RISK` / `PHISHING`.
- `--explain` with template default and optional LLM providers (Anthropic, OpenAI as `[llm]` extra).
- Output formats: Rich, console, JSON, CSV. Batch processing with `ThreadPoolExecutor`.
- URL defanging for TTY output. Exit codes: 0 safe/low, 1 suspicious/high, 2 phishing, 3 error.
- CI (pytest matrix + ruff) and PyPI publishing via OIDC Trusted Publisher.

[Unreleased]: https://github.com/duathron/barb/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/duathron/barb/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/duathron/barb/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/duathron/barb/releases/tag/v1.0.0
