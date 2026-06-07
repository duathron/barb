# Analyzers

[← Docs index](README.md)

All 12 analyzers run offline on every `barb analyze` invocation. No network
access, no API key, no external calls.

## The 12 offline analyzers

| Analyzer | What it detects | Typical severity | Weight | Example |
|----------|-----------------|-----------------|--------|---------|
| **entropy** | High Shannon entropy in host or path — indicates generated/random labels | MEDIUM | 1.0 | `x7k2m9p.evil.com` |
| **homoglyph** | Unicode confusable characters and mixed-script labels (Latin + Cyrillic in the same label); pure non-ASCII IDN emits a LOW informational signal | HIGH / LOW | 1.5 | `pаypal.com` (Cyrillic `а`) |
| **tld** | Suspicious top-level domains associated with phishing | MEDIUM | 1.0 | `paypal-login.tk` |
| **subdomain** | Excessive subdomain depth or domain-squatting patterns | MEDIUM | 1.0 | `secure.paypal.com.evil.com` |
| **brand** | Brand name appears in a domain that is not the brand's own registrar | MEDIUM–HIGH | 1.2 | `paypal-secure.evil.com` |
| **shortener** | Known URL shortener services that obscure the real destination | MEDIUM | 0.8 | `bit.ly/abc123` |
| **encoding** | Percent-encoding or punycode abuse to disguise the actual host or path | MEDIUM–HIGH | 1.0 | `%70%61%79pal.com` |
| **ip\_url** | IP address used as host; `@`-obfuscation where a domain appears before `@` and the real host follows → CRITICAL | HIGH / CRITICAL | 1.0 | `http://192.168.1.1/login`, `http://paypal.com@evil.com` |
| **typosquat** | ASCII brand lookalikes via Levenshtein distance 1–2 and digit-for-letter swaps; official brand domains are skipped; de-stacked; short-label guarded | MEDIUM–HIGH | 1.3 | `paypa1.com`, `g00gle.com` |
| **keyword** | Phishing-pattern keywords in path or query (login, verify, secure, webscr, bank, …); aggregated into one LOW signal | LOW | 0.6 | `/login/verify-account` |
| **lexical** | URL length, hyphen count, and digit ratio; emits LOW signals for suspicious structural patterns | LOW | 0.5 | `my-secure-bank-update-2024.com` |
| **file\_ext** | Suspicious file extensions in the URL path: double-extension masquerade → HIGH; single executable or script → LOW; archive → INFO | INFO / LOW / HIGH | 1.0 | `invoice.pdf.exe`, `setup.ps1` |

Source of truth: `barb/config.py` (weights), `barb/analyzers/` (detection logic).

---

## Scoring model

### Signal severity points

Each signal has a severity level. The points value maps severity to a numeric
weight used in the score formula. Source of truth: `barb/models.py`
(`SignalSeverity.points`).

| Severity | Points |
|----------|--------|
| INFO | 0 |
| LOW | 1 |
| MEDIUM | 2 |
| HIGH | 3 |
| CRITICAL | 5 |

### Score formula

```
risk_score = Σ ( severity.points × signal.weight × analyzer_weight )
```

Rounded to 2 decimal places. `signal.weight` is the per-signal weight (usually
`1.0` unless an analyzer adjusts it internally). `analyzer_weight` is the
per-analyzer weight from `scoring.weights` in config (defaults above). Source of
truth: `barb/scoring.py::compute_risk_score`.

**Example:** a single CRITICAL signal from `ip_url` (analyzer weight 1.0,
signal weight 1.0):
`5 × 1.0 × 1.0 = 5.0`. Add a MEDIUM from `tld` (1.0 × 1.0 × 1.0 = 2.0) and a
LOW from `keyword` (1 × 1.0 × 0.6 = 0.6): total = **7.6** → HIGH\_RISK tier.

### Verdict thresholds

Score → verdict mapping. Source of truth: `barb/config.py`
(`ScoringThresholds`).

| Score | Verdict |
|-------|---------|
| < 1 | 🟢 SAFE |
| ≥ 1 | 🔵 LOW\_RISK |
| ≥ 4 | 🟡 SUSPICIOUS |
| ≥ 8 | 🟠 HIGH\_RISK |
| ≥ 13 | 🔴 PHISHING |

### Severity floor

The severity floor ensures that high-impact individual signals are never buried
under a low cumulative score. Source of truth: `barb/scoring.py::determine_verdict`.

| Highest signal severity in the run | Minimum verdict |
|------------------------------------|-----------------|
| CRITICAL | HIGH\_RISK |
| HIGH | SUSPICIOUS |
| MEDIUM / LOW / INFO | (no floor applied) |

The floor **never lowers** a verdict that the score alone already placed higher.
The final verdict is `max(score_verdict, floor_verdict)`.

---

## Allowlist suppression

barb ships a bundled curated list of known-good domains (popular brands and
services). When the analyzed host matches a known-good domain, **domain-based**
signals are suppressed — only path and query signals still fire.

Running `barb update-data` writes an additional user-override allowlist to
`~/.barb/data/allowlist.json`, merged with the bundled list. Users who never run
`update-data` see only the bundled list and experience no change in detection
behavior.

> [!NOTE]
> Allowlist suppression applies to domain-based signals only. A known-good domain
> hosting a suspicious path (e.g. `paypal.com/verify?token=…`) will still fire
> `keyword` and `file_ext` signals if the path triggers them.

---

## Detection quality (measured)

### Methodology

The eval harness in `eval/` scores barb against a labeled URL corpus. The corpus
is built from two feeds:

- **Phishing:** 300 URLs from the OpenPhish community feed (`eval/fetch_corpus.py`
  fetches and labels them).
- **Benign:** 500 URLs from the Tranco top-500 list (most-popular domains,
  expected clean).

Alert tier: verdict ≥ SUSPICIOUS counts as a positive detection.

### Results — v1.4.1 (offline core, snapshot 2026-06-01)

| Metric | Value | Detail |
|--------|-------|--------|
| Precision | **1.00** | 0 false positives out of 500 benign URLs |
| Recall | **0.07** | 22 of 300 phishing URLs caught |
| False-positive rate | **0.00** | 0 of 500 benign URLs flagged |

### Interpretation

> [!IMPORTANT]
> barb is a **high-precision URL-structure pre-filter**. When it flags SUSPICIOUS
> or higher, that verdict is reliable (precision 1.00 on this corpus). It is **not
> a standalone phishing catch-all**.
>
> Low recall is by design. barb inspects URL structure only and never fetches the
> URL, so phishing campaigns that use clean-looking URLs on abused legitimate
> hosting (`github.io`, `pages.dev`, plain `.com`, short paths) fall below the
> detection threshold. That is an inherent limit of URL-only heuristics, not a bug.
>
> Close the recall gap with the downstream pipeline:
> - `--osint` for fresh-domain signals (RDAP registration age, crt.sh certificate
>   recency).
> - **vex** for VirusTotal / AbuseIPDB reputation lookup on barb's flagged URLs.
> - **sift** for alert correlation across the full event stream.

### With `--osint` (measured, barb 1.6.0)

`--osint` does **not** improve recall on **live** phishing. Measured on a fresh
corpus (OpenPhish + Tranco, snapshot 2026-06-07), recall across the 123 *resolving*
phishing domains was **0.154 with and without `--osint` (Δ = 0)** — RDAP, crt.sh,
and ASN caught zero live domains the offline core missed. The only recall `--osint`
adds is flagging **non-resolving (taken-down) domains** via DNS NXDOMAIN — genuine
**retro-triage** value for IOC-list sweeps, not live detection, and it costs a
false positive (1 benign domain here). Use `--osint` for takedown confirmation and
analyst context, not as a live-recall booster. See
[osint.md — Recall](osint.md#recall-what---osint-does-and-does-not-add-measured)
for the live/dead split and full reasoning.

### CI regression gate vs. field measurement

The repo contains a synthetic fixture (`eval/fixtures/`) that drives a
pytest-based regression gate. That fixture reports precision 1.00 / recall 0.76 —
numbers intentionally higher than the real corpus because the fixture is
constructed from known-bad URL patterns that exercise every analyzer. It catches
score regressions between releases; it is **not** a field performance claim.

### Reproduce the numbers

```bash
# Build the corpus (fetches OpenPhish + Tranco, writes eval/corpus/real.csv)
python -m eval.fetch_corpus

# Score barb against it and print precision/recall/F1
python -m eval.run_eval --corpus eval/corpus/real.csv
```

Both scripts are in the repo root. No extra dependencies beyond `barb-phish[dev]`.
