# barb — Documentation

`barb` is a command-line tool that takes a URL — one, a list, or a stream — and
runs it through 12 offline heuristic analyzers to produce a phishing verdict you
can act on. It emits a scored result in whichever format your workflow needs: a
colored terminal table, JSON, NDJSON, CSV, or a STIX 2.1 bundle. An optional
`--osint` flag layers in DNS, RDAP, Certificate Transparency, and ASN signals
about the domain — without ever touching the analyzed URL itself.

It is built for SOC triage, DFIR investigation, and CI pipelines. `analyze`
answers "is this URL suspicious, and why?" using only URL structure — no API keys,
no runtime downloads, no network calls to the target. Feed the JSON into **vex**
for VirusTotal reputation enrichment, then into **sift** for alert correlation.

**Installed version this manual describes: `barb 1.4.1`.**

## Who this is for

- **SOC analysts** doing fast URL triage before clicking or escalating.
- **DFIR responders** who need bulk verdict processing and exportable evidence (STIX, JSON).
- **Automation authors** wiring `barb` into pipelines via exit codes and machine output.

## Pages

| Page | What it covers |
|------|----------------|
| [Getting started](getting-started.md) | Install, first `barb analyze`, how to read the verdict/score/signals, offline-by-default vs opt-in `--osint`, exit codes at a glance. |
| [Commands](commands.md) | Every command and every flag, taken from `--help`, with one example each. |
| [Analyzers](analyzers.md) | The 12 offline analyzers, the scoring model (formula + severity points + thresholds + severity-floor), allowlist suppression, and measured detection quality. |
| [OSINT enrichment](osint.md) | The four opt-in enrichers (DNS, RDAP, crt.sh, ASN), the cache, fail-open behavior, and the privacy footprint. |
| [Output formats](output-formats.md) | All six output formats with a real example each. Defang rules. Threshold and exit-code interaction. |
| [Configuration](configuration.md) | Priority hierarchy, the full `~/.barb/config.yaml` with all fields and defaults, `BARB_LLM_KEY`, `~/.barb/` files and permissions, weight/threshold tuning. |
| [Pipeline](pipeline.md) | barb → vex → sift, the precise handoff contract, and why barb stays pipe-only. |

## Verdict and exit-code key

| Verdict | Score range | Exit code |
|---------|-------------|-----------|
| 🟢 SAFE | < 1 | 0 |
| 🔵 LOW\_RISK | ≥ 1 | 0 |
| 🟡 SUSPICIOUS | ≥ 4 | 1 |
| 🟠 HIGH\_RISK | ≥ 8 | 1 |
| 🔴 PHISHING | ≥ 13 | 2 |
| (error — bad input / missing file / no URLs) | — | 3 |

> [!NOTE]
> The exit code reflects the **worst verdict** across all URLs in a single
> invocation. A severity-floor rule can escalate the verdict independently of the
> score: any CRITICAL signal forces at least HIGH\_RISK; any HIGH signal forces at
> least SUSPICIOUS. Source of truth: `barb/scoring.py` + `barb/models.py`.

> [!WARNING]
> **Never makes HTTP requests to the analyzed URL. Offline core makes no network
> calls and never fetches the URL.**
