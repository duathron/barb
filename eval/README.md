# barb eval — offline detection-quality harness

A dev-only tool that measures barb's precision, recall, and F1 against a
labeled CSV corpus.  It is **not** part of the shipped `barb-phish` package.

## What it does

For each `(url, label)` row in the corpus it:

1. Calls `barb._analyze_single(url, config, osint=False)` — 100% offline.
2. Maps the resulting verdict to a binary positive/negative prediction using
   the configurable *alert tier* (default: `SUSPICIOUS`).
3. Computes TP / FP / TN / FN and derives precision, recall, F1, accuracy,
   and false-positive rate.
4. Produces a per-verdict-tier breakdown (5 × 2 table) showing where benign
   and phishing URLs land across all five verdict tiers.

## Running

```sh
# Default: bundled synthetic fixture, Rich table output
python -m eval.run_eval

# JSON output (for CI tracking)
python -m eval.run_eval --json

# Custom corpus + higher alert tier
python -m eval.run_eval --corpus eval/corpus/real.csv --alert-tier HIGH_RISK

# Help
python -m eval.run_eval --help
```

## Corpus CSV format

```
url,label
https://www.google.com,benign
http://paypa1-secure.verify.tk/signin,phishing
# Lines starting with # are comments and are skipped
```

| Column  | Required | Values                         |
|---------|----------|--------------------------------|
| `url`   | yes      | any URL string                 |
| `label` | yes      | `phishing` or `benign` (case-insensitive) |

Blank lines and `#` comment lines are silently skipped.

## Bundled fixture

`eval/fixtures/sample_corpus.csv` (~35 rows) contains:

- **Benign**: real well-known safe domains (Google, GitHub, Wikipedia, major
  banks, etc.) — these establish the false-positive baseline.
- **Phishing**: hand-crafted *synthetic* lookalike patterns that exercise all
  heuristic analyzers (IP-host URLs using RFC 5737 test IPs, userinfo tricks,
  high-entropy hosts, excessive subdomains, punycode/homoglyph lookalikes,
  encoding tricks, brand typosquats, suspicious TLDs).

**No real malicious URLs are committed to the repository.**

## Plugging in a real corpus

Download a real labeled corpus into the gitignored `eval/corpus/` directory
(that path is in `.gitignore` — it will never be committed):

```sh
mkdir -p eval/corpus

# OpenPhish community feed (phishing only — combine with Tranco benign list)
curl -o eval/corpus/openphish.txt https://openphish.com/feed.txt
# Convert to CSV: add header + label column, then run barb eval

# Tranco top-1M list (benign)
curl -L -o eval/corpus/tranco.csv https://tranco-list.eu/download/latest/full

# Once you have a combined labeled CSV:
python -m eval.run_eval --corpus eval/corpus/real.csv
```

The harness is offline-only: it never fetches the analyzed URL.  DNS/RDAP
OSINT enrichers are explicitly disabled (`osint=False`).

## Options

| Flag            | Default      | Description                                              |
|-----------------|--------------|----------------------------------------------------------|
| `--corpus PATH` | bundled fixture | Path to labeled CSV                                 |
| `--alert-tier`  | `SUSPICIOUS` | Tier at/above which a URL counts as a positive prediction |
| `--json`        | off          | Emit JSON instead of Rich table (useful for CI)          |

Alert tier choices: `SAFE`, `LOW_RISK`, `SUSPICIOUS`, `HIGH_RISK`, `PHISHING`.

## Running the test suite

```sh
.venv/bin/python -m pytest tests/test_eval_harness.py -v
```

The tests run entirely offline against the bundled fixture.
