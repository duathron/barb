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

## Real corpus (opt-in, local)

`eval/corpus/` is gitignored — nothing in that directory is ever committed.

### Step 1 — build the corpus (one-time, needs network)

```sh
python -m eval.fetch_corpus
# or with options:
python -m eval.fetch_corpus --out eval/corpus/real.csv --benign-n 500
python -m eval.fetch_corpus --help
```

This fetches the [OpenPhish community feed](https://openphish.com/feed.txt)
(phishing URLs) and the [Tranco top-1M list](https://tranco-list.eu/) (benign
domains), then writes a labeled CSV to `eval/corpus/real.csv`.

**Safety notes:**
- Both downloads are HTTPS-only (HTTP is rejected before any network call).
- The output file contains LIVE phishing URLs stored as **data strings** — do
  not open or visit any URL from this file.
- The file is gitignored and will never be committed to the repository.

### Step 2 — run the eval (offline headline number)

```sh
python -m eval.run_eval --corpus eval/corpus/real.csv
python -m eval.run_eval --corpus eval/corpus/real.csv --json
```

This runs barb's heuristic-only analysis — 100% offline, no OSINT.

### Step 3 — run with OSINT enrichers (optional, live network, slower)

```sh
python -m eval.run_eval --corpus eval/corpus/real.csv --osint
```

Enables DNS/RDAP/crt.sh/ASN enrichers during evaluation.  Best-effort — live
domains, slower, some lookups may fail or be rate-limited.  Useful for
measuring the uplift from enrichers over heuristics alone.

**CI always uses the synthetic fixture without `--osint`** — the default
offline path is never changed by adding a real corpus.

## Options

| Flag                  | Default          | Description                                                     |
|-----------------------|------------------|-----------------------------------------------------------------|
| `--corpus PATH`       | bundled fixture  | Path to labeled CSV                                             |
| `--alert-tier`        | `SUSPICIOUS`     | Tier at/above which a URL counts as a positive prediction       |
| `--json`              | off              | Emit JSON instead of Rich table (useful for CI)                 |
| `--osint`             | off              | Enable OSINT enrichers (live network, opt-in, slower)           |
| `--min-precision F`   | none             | Fail (exit 1) if precision is below this floor                  |
| `--min-recall F`      | none             | Fail (exit 1) if recall is below this floor                     |

Alert tier choices: `SAFE`, `LOW_RISK`, `SUSPICIOUS`, `HIGH_RISK`, `PHISHING`.

## Running the test suite

```sh
.venv/bin/python -m pytest tests/test_eval_harness.py -v
```

The tests run entirely offline against the bundled fixture.
