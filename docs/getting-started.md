# Getting started

[← Docs index](README.md)

This page gets you from nothing to a first verdict.

## Install

`barb` is published on PyPI as `barb-phish`. The command stays `barb`.

```bash
pip install barb-phish
```

To enable AI-powered explanations (`--explain` with a cloud provider), install
the LLM extra:

```bash
pip install barb-phish[llm]    # Anthropic + OpenAI client libraries
```

The default `template` explainer is built in and needs no extra. See
[Configuration → explain providers](configuration.md#explain-providers) for the
full provider list including local Ollama.

## Your first analysis

```bash
barb analyze "http://paypal.com@evil-login.tk/verify"
```

Output:

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

## How to read the output

- **URL** — the analyzed URL, defanged for safe display (`hxxp[://]` instead of
  `http://`, brackets around dots). This is display-only; the original URL is used
  for analysis and appears as-is in JSON/NDJSON/CSV/STIX output.

- **Verdict** — one of five levels, each with a colored indicator:

  | Verdict | Meaning |
  |---------|---------|
  | 🟢 SAFE | No suspicious signals at or above the score threshold. |
  | 🔵 LOW\_RISK | Minor signals — worth logging, unlikely immediate threat. |
  | 🟡 SUSPICIOUS | Multiple moderate signals or one HIGH signal — warrants investigation. |
  | 🟠 HIGH\_RISK | Strong signals, severity-floor escalation, or both — likely malicious. |
  | 🔴 PHISHING | Clear, high-confidence phishing indicators. |

- **Risk Score** — a weighted sum of all signal severities. The formula and
  thresholds are in [Analyzers → scoring model](analyzers.md#scoring-model).

- **Signals table** — each row is one finding from one analyzer. Columns are
  **Severity** (INFO / LOW / MEDIUM / HIGH / CRITICAL), **Analyzer** (which of the
  12 offline analyzers produced it), and **Finding** (the human-readable detail).

## Offline by default

The offline core never makes network calls. All 12 analyzers run against URL
structure only — no DNS, no HTTP, no API. You need no API key to run `barb analyze`.

> [!WARNING]
> **Never makes HTTP requests to the analyzed URL. Offline core makes no network
> calls and never fetches the URL.**

## Opt-in OSINT enrichment

Pass `--osint` to layer in four infrastructure checks about the domain. They query
metadata — registration age, certificate history, hosting ASN — but never contact
the analyzed URL.

```bash
barb analyze "https://suspicious-site.tk/paypal-login" --osint
```

All four enrichers are fail-open: a timeout or connection error drops that
enricher's signals and analysis continues offline. No API key is required.

See [OSINT enrichment](osint.md) for the full enricher reference.

## Suppress the banner

The colored banner (`╭─ barb ─╮`) prints on every `rich`/`console` run. Suppress
it with `--quiet` / `-q`:

```bash
barb analyze "https://suspicious-site.tk/paypal-login" -q
```

Use `-q` in scripts and pipelines where the banner would pollute output.

## Exit codes at a glance

The exit code is the **worst verdict** across all URLs in a single run — useful
for branching in shell scripts.

| Exit code | Condition |
|-----------|-----------|
| `0` | All reported URLs are SAFE or LOW\_RISK |
| `1` | At least one URL is SUSPICIOUS or HIGH\_RISK |
| `2` | At least one URL is PHISHING |
| `3` | Error — bad input, missing file, non-HTTPS `--source`, or no URLs |

```bash
barb analyze "$URL" -q
if [ $? -eq 2 ]; then
    echo "PHISHING — block $URL"
fi
```

## Built-in help

A terminal usage guide is built into barb. No browser required.

```bash
barb manual              # overview: version, topics, quick start
barb manual analyzers    # the 12 analyzers, scoring, thresholds
barb manual osint        # OSINT enrichers, cache, privacy
barb manual output       # all six output formats and defang rules
barb manual config       # config file, priority chain, BARB_LLM_KEY
barb manual pipeline     # barb → vex integration
barb manual examples     # real one-line invocations
```

## Next steps

- [Commands](commands.md) — full flag reference for all subcommands.
- [Analyzers](analyzers.md) — what the 12 analyzers detect and how scoring works.
- [OSINT enrichment](osint.md) — the four enrichers and their privacy footprint.
- [Output formats](output-formats.md) — JSON, NDJSON, CSV, STIX 2.1.
- [Pipeline](pipeline.md) — feed barb JSON into vex and sift.
