# Changelog

All notable changes to **barb** are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.6.1](https://github.com/duathron/barb/compare/v1.6.0...v1.6.1) (2026-06-07)


### Documentation

* **changelog:** note attribution metadata change under Unreleased ([860dcac](https://github.com/duathron/barb/commit/860dcac3a425c31295943577c8bffc13683df049))
* correct --osint framing — context/retro-triage, not a recall booster ([cf840ac](https://github.com/duathron/barb/commit/cf840ac433312f147f7a422cd55e34b65acbc72b))
* **meta:** attribution — GitHub + LinkedIn; drop personal email from metadata ([18a6b57](https://github.com/duathron/barb/commit/18a6b579dbf0bb33ab462a0705010819ef20221b))
* update project_documentation.md through v1.6.0 ([129b5da](https://github.com/duathron/barb/commit/129b5daa39f0d4eccbcc4ab8955291f04a88e7c8))

## [Unreleased]

### Changed
- Project metadata: added a LinkedIn link to the package URLs (shown in the PyPI sidebar) and a README **Author** section; removed the personal email from `authors` — contact is via GitHub issues / LinkedIn.

## [1.6.0] - 2026-06-05

Minor release: Shipwright eval/config now consumed from PyPI, plus the eval schema-version contract.

### Added
- Eval `--json` output now carries a `schema_version` field (and a guard test pins it), so a change to the shared eval result shape can't silently break consumers (N6 schema-contract).

### Changed
- Detection-quality eval delegates corpus loading, binarization, confusion tally and metric math to `shipwright_kit.eval`; config loading delegates to `shipwright_kit.config` — eliminating duplicated logic. Eval numbers and config behaviour are unchanged.
- Dependency `shipwright-kit` is now resolved from **PyPI** (`>=0.6.0,<0.7.0`) instead of a git URL, so `pip install barb-phish` resolves cleanly.

### Fixed
- Defensive parsing of external OSINT enricher responses (RDAP/crt.sh) so malformed/edge-case payloads no longer raise.

## [1.5.1] - 2026-06-01

### Fixed

- barb now accepts defanged IOCs on input (`hxxp[://]`, `hxxp://`, `[.]`, `(.)`, `[dot]`, `[at]`, fullwidth Unicode, zero-width) — previously rejected with "Invalid IPv6 URL"; input is refanged before parsing (offline string transform, never fetches the URL).

## [1.5.0] - 2026-06-01

### Added
- Built-in `barb manual` command — terminal usage guide with six topics (`analyzers`, `osint`, `output`, `config`, `pipeline`, `examples`) and an overview mode; mirrors the vex-style `vex manual` structure.
- Comprehensive `docs/` set: `getting-started.md`, `commands.md`, `analyzers.md`, `osint.md`, `output-formats.md`, `configuration.md`, `pipeline.md`, and `docs/README.md` index page.

## [1.4.1] - 2026-06-01

### Added
- Real-corpus evaluation tooling: `eval/fetch_corpus.py` (OpenPhish + Tranco → gitignored local corpus) and a `--osint` flag on `eval/run_eval.py`.
- "Detection quality (measured)" section in the README and `docs/MANUAL.md` — real-corpus precision/recall with the honest "high-precision URL pre-filter, not a standalone catch-all" framing.

### Fixed — brand/typosquat false positives on legitimate domains

Real-corpus numbers (800 URLs: 300 phishing + 500 benign, alert tier = SUSPICIOUS):

| Metric    | Before | After  | Delta  |
|-----------|--------|--------|--------|
| Precision | 0.4597 | 1.0000 | +0.540 |
| Recall    | 0.1900 | 0.0733 | -0.117 |
| FP-rate   | 0.1340 | 0.0000 | -0.134 |
| TP        | 57     | 22     | -35    |
| FP        | 67     | 0      | -67    |

Precision gain and FP elimination are the primary goals of this branch.
The baseline TP count was inflated by spurious signals (e.g. registrable
label `"com"` matching brand `"zoom"` at distance 2 for `roblox.com.et`,
and the `"ing"` bank brand firing on `booking.com`, `bing.com`, etc.).
The 35 lost "TPs" were false positives in disguise — correct catches for
the wrong reason.  Genuine detections gained from the TLD additions
(phishing moved from SAFE → LOW_RISK, not reaching the SUSPICIOUS alert
tier).

**Fix 1 — typosquat: de-stack + short-label guard + dist-2 length guard**
- Emit at most one typosquat signal per host (the best/lowest-distance
  brand match), eliminating stacked HIGH signals (e.g. `dns.google`
  getting 3× HIGH for `dhl`/`ups`/`ing`).
- Skip typosquat entirely when the registrable label is fewer than 5 chars
  (`hp`, `un`, `dns`) — too short to be a meaningful typosquat target.
- Only accept Levenshtein distance-2 matches when the label is ≥ 8 chars;
  short labels at dist=2 produce too many legitimate collisions
  (`webex`→`fedex`, `spotify`→`shopify`, `nease`→`chase`).
- Fixed a logic bug where the dist-2 guard's `continue` skipped path (b)
  (digit-normalization) for the same brand, causing `g00gle.com` to be
  missed.

**Fix 2 — brand: own-registrable-domain skip + short-brand whole-token guard + official domain expansion**
- Brand analyzer no longer fires when the matched brand's official domain
  list includes the host's own registrable domain (e.g. `dns.google` →
  registrable `google.com` is Google's own domain → skip brand signal).
- Short brands (< 5 chars, specifically `ing`) now require a whole-token
  match (split on `.` and `-`) instead of a substring match, preventing
  `booking.com`, `bing.com`, `springer.com`, `duolingo.com` etc. from
  triggering the ING bank brand signal.
- Extended `brands.json` official domain lists for Google (11 CDN/regional
  domains), Amazon (10 regional/service domains), Apple (3), Microsoft (2),
  Adobe (3), Netflix (2), Facebook (2), Instagram (1), Twitter (1),
  LinkedIn (1), Shopify (2), Zoom (1) to eliminate brand FPs for legitimate
  infrastructure domains.

**Fix 3 — suspicious-TLD list: 5 new abuse-heavy TLDs**
Additions measured against the corpus (phishing count / benign count):
- `.cfd` (+28 phishing / 0 benign) — kept
- `.help` (+8 phishing / 0 benign) — kept
- `.sbs` (+3 phishing / 0 benign) — kept
- `.lat` (+2 phishing / 0 benign) — kept
- `.casa` (+1 phishing / 0 benign) — kept

Candidates with 0 corpus hits (`lol`, `quest`, `mom`) and mainstream-legit
TLDs (`app`, `dev`, `io`, `com`) were not added.
These additions move phishing URLs from SAFE → LOW_RISK (MEDIUM signal);
they do not reach the SUSPICIOUS alert tier unless combined with other signals.

## [1.4.0] - 2026-06-01

### Added
- crt.sh certificate-transparency enricher (opt-in `--osint`) — flags recently issued TLS certificates (MEDIUM < 7 d, LOW < 30 d, INFO if no CT records); sends only the hostname; fail-open.
- ASN enrichment (opt-in `--osint`) — INFO context signal with the resolved IP's AS number, name, country and BGP prefix (Team Cymru WHOIS, stdlib socket); analyst context only, no score impact.
- Ollama explain provider (`provider: ollama`) — local-LLM analysis summaries via a local Ollama server; privacy-positive (no data leaves the host), no API key; falls back to the template explainer if Ollama is unreachable.
- `update-data` command — opt-in refresh of the Tranco-based allowlist over HTTPS into a user-override file (`~/.barb/data/allowlist.json`); never automatic; bundled curated list remains the default. Supports `--top-n` (default 5000) and `--source` flags; non-https URLs rejected immediately; atomic write (`os.replace`) with `0o600` file permissions; stdlib `urllib` only; merges bundled curated entries so brand domains are never lost.
- Full user manual at `docs/MANUAL.md`; README shields.io badges.

### Changed
- `--osint` help text now lists all four enrichers (DNS, RDAP, crt.sh, ASN).
- Rich/console output under a SAFE verdict now shows `osint:*` enrichment signals (e.g. the ASN INFO context) since they are explicitly requested via `--osint`; non-osint INFO signals stay hidden.
- `update-data` validates the source is HTTPS before printing any progress line.

## [1.3.0] - 2026-05-31

### Added
- `file_ext` analyzer (12th offline heuristic) — flags suspicious file extensions in the URL path: double-extension masquerade (e.g. `invoice.pdf.exe`) → HIGH; single executable/script extension (e.g. `.exe`, `.ps1`, `.sh`) → LOW; archive extension (e.g. `.zip`, `.tar.gz`) → INFO.
- NDJSON output format (`-o ndjson`) — one compact JSON object per line, suitable for streaming pipelines and log aggregators.
- STIX 2.1 export (`-o stix`) — emits a STIX bundle containing `indicator` objects for URLs with verdict SUSPICIOUS or higher; uses deterministic IDs and maps verdict to STIX confidence.
- Offline evaluation harness (`eval/`, dev tool) — measures precision, recall, and F1 against a labeled URL corpus; wired into CI as a detection-quality regression gate.
- Top-level `--version` flag (`barb --version`) in addition to the existing `barb version` subcommand.

### Changed
- Rich terminal output now hides INFO-severity signals when the overall verdict is SAFE, reducing noise in clean results. Machine formats (JSON, NDJSON, CSV, STIX) still include all signals.

### Fixed
- Empty or malformed URLs (empty host, whitespace in host) are now rejected with a clear error message and exit code 3, instead of being silently scored SAFE.
- Unknown `--output` values are now rejected with a clear error message and exit code 3, instead of silently falling back to rich output.
- A stderr note is printed when `--explain` is combined with `-o stix`, since `--explain` has no effect on that machine format.

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

[Unreleased]: https://github.com/duathron/barb/compare/v1.5.1...HEAD
[1.5.1]: https://github.com/duathron/barb/compare/v1.5.0...v1.5.1
[1.5.0]: https://github.com/duathron/barb/compare/v1.4.1...v1.5.0
[1.4.1]: https://github.com/duathron/barb/compare/v1.4.0...v1.4.1
[1.4.0]: https://github.com/duathron/barb/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/duathron/barb/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/duathron/barb/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/duathron/barb/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/duathron/barb/releases/tag/v1.0.0
