# Configuration

[← Docs index](README.md)

`barb` resolves every setting through a fixed priority chain and stores user state
under `~/.barb/`.

## Priority chain

For any given value, the **first** source that provides it wins:

```
CLI flags  >  environment variables  >  ~/.barb/config.yaml  >  built-in defaults
```

For example, the LLM key resolves as `--explain` provider key → `BARB_LLM_KEY`
env var → `explain.api_key` in config → `null` (template provider used, no key
needed). Source of truth: `barb/config.py::load_config`.

---

## Environment variable

| Variable | Sets | Config equivalent |
|----------|------|-------------------|
| `BARB_LLM_KEY` | LLM API key for `anthropic` or `openai` explain providers | `explain.api_key` |

`BARB_LLM_KEY` takes precedence over `explain.api_key` in the config file. No
other environment variables are read by barb's configuration system.

---

## Config file: `~/.barb/config.yaml`

Create this file to persist any setting. If it does not exist, barb runs with
all built-in defaults. Edit by hand — there is no `config --set-*` command; use
`barb config --show` to inspect the active merged configuration.

### Full config with all fields and defaults

```yaml
scoring:
  weights:
    entropy: 1.0
    homoglyph: 1.5
    tld: 1.0
    subdomain: 1.0
    brand: 1.2
    shortener: 0.8
    encoding: 1.0
    ip_url: 1.0
    typosquat: 1.3
    keyword: 0.6
    lexical: 0.5
    file_ext: 1.0
  thresholds:
    low_risk: 1
    suspicious: 4
    high_risk: 8
    phishing: 13

explain:
  provider: template      # template | anthropic | openai | ollama
  model: null             # e.g. "gpt-4o", "llama3.1" — null = provider default
  api_key: null           # overridden by BARB_LLM_KEY env var
  send_url: true          # include defanged URL in the LLM prompt
  ollama_host: http://localhost:11434

output:
  default_format: rich    # rich | console | json | ndjson | csv | stix
  quiet: false
  defang: true            # defang URLs in terminal output (rich/console)

update_check:
  enabled: true
  check_interval_hours: 24

allowlist_check:
  enabled: true            # set false to silence the staleness hint entirely
  max_age_days: 90         # warn when the effective allowlist is older than this

osint:
  dns_timeout: 2.0        # seconds
  rdap_timeout: 5.0       # seconds
  crtsh_timeout: 8.0      # seconds
  asn_timeout: 3.0        # seconds
  cache_ttl_hours: 6      # SQLite cache TTL (~/.barb/cache.db)
```

Source of truth: `barb/config.py` (`AppConfig` and all nested models).

---

### `scoring.weights`

Per-analyzer multipliers applied to signal scores. Raise a weight to make that
analyzer's signals count more; lower it to reduce false positives from noisy
analyzers.

| Key | Default | Analyzer |
|-----|---------|----------|
| `entropy` | 1.0 | Shannon entropy |
| `homoglyph` | 1.5 | Unicode confusables / mixed-script |
| `tld` | 1.0 | Suspicious TLD |
| `subdomain` | 1.0 | Subdomain depth / squatting |
| `brand` | 1.2 | Brand in non-brand domain |
| `shortener` | 0.8 | URL shortener |
| `encoding` | 1.0 | Percent/punycode abuse |
| `ip_url` | 1.0 | IP host / `@`-obfuscation |
| `typosquat` | 1.3 | Levenshtein lookalike |
| `keyword` | 0.6 | Phishing keywords |
| `lexical` | 0.5 | Length / hyphen / digit ratio |
| `file_ext` | 1.0 | Suspicious file extensions |

### `scoring.thresholds`

Score values at which the verdict tier changes.

| Key | Default | Verdict tier |
|-----|---------|-------------|
| `low_risk` | 1 | ≥ 1 → LOW\_RISK |
| `suspicious` | 4 | ≥ 4 → SUSPICIOUS |
| `high_risk` | 8 | ≥ 8 → HIGH\_RISK |
| `phishing` | 13 | ≥ 13 → PHISHING |

> [!NOTE]
> Raising `suspicious` or `high_risk` thresholds reduces false positives but may
> let genuine threats through at lower verdict tiers. The severity-floor rule
> (CRITICAL → HIGH\_RISK, HIGH → SUSPICIOUS) is independent of these thresholds
> and cannot be disabled via config.

### `explain`

| Key | Default | Meaning |
|-----|---------|---------|
| `provider` | `template` | `template` \| `anthropic` \| `openai` \| `ollama` |
| `model` | `null` | Model override for the provider. `null` = provider default. |
| `api_key` | `null` | Cloud LLM key; overridden by `BARB_LLM_KEY`. |
| `send_url` | `true` | Include the defanged URL in the LLM prompt. Set `false` to send only signal labels and severities. |
| `ollama_host` | `http://localhost:11434` | Ollama server base URL. |

#### Explain providers

| Provider | Requires | Notes |
|----------|----------|-------|
| `template` | Nothing | Default. Offline, deterministic, zero network calls. |
| `anthropic` | `pip install barb-phish[llm]` + `BARB_LLM_KEY` | Calls Anthropic Claude API. Sends defanged URL and signals unless `send_url: false`. |
| `openai` | `pip install barb-phish[llm]` + `BARB_LLM_KEY` | Calls OpenAI API. Same data-send behavior as `anthropic`. |
| `ollama` | Local [Ollama](https://ollama.ai) server running | No API key, no data leaves the host. Falls back to `template` if Ollama is unreachable. |

> [!IMPORTANT]
> The `anthropic` and `openai` providers require `pip install barb-phish[llm]`
> and the `BARB_LLM_KEY` environment variable. The `template` provider (default)
> needs neither.

**Ollama example config:**

```yaml
explain:
  provider: ollama
  model: llama3.1
  ollama_host: http://localhost:11434
  send_url: false    # omit URL from prompt for maximum privacy
```

If Ollama is unreachable when `--explain` is used, barb prints a note to stderr
and falls back to the template explainer. The command always completes.

### `output`

| Key | Default | Meaning |
|-----|---------|---------|
| `default_format` | `rich` | Default output format when `-o` is not passed. |
| `quiet` | `false` | Suppress the banner by default. |
| `defang` | `true` | Defang URLs in `rich`/`console` output. |

### `update_check`

| Key | Default | Meaning |
|-----|---------|---------|
| `enabled` | `true` | Passive PyPI version check. |
| `check_interval_hours` | `24` | How often to check for a newer version. |

### `allowlist_check`

barb prints a one-line stderr hint when the effective Tranco allowlist is older than `max_age_days`. The check reads only the file modification time — it is offline, never blocks analysis, and produces no output when the allowlist is fresh.

| Key | Default | Meaning |
|-----|---------|---------|
| `enabled` | `true` | When `false`, the staleness hint is never shown. |
| `max_age_days` | `90` | Warn when the allowlist file is older than this many days. |

The *effective* allowlist is the user-override file (`~/.barb/data/allowlist.json`) when it exists; otherwise the bundled curated list. Run `barb update-data` to refresh the user-override allowlist and silence the hint.

```yaml
allowlist_check:
  enabled: false    # silence the hint permanently
```

> [!NOTE]
> This hint goes to stderr only. Machine output (json/ndjson/csv/stix) on stdout is unaffected.

### `osint`

| Key | Default | Meaning |
|-----|---------|---------|
| `dns_timeout` | `2.0` | Seconds before DNS lookup times out. |
| `rdap_timeout` | `5.0` | Seconds before RDAP query times out. |
| `crtsh_timeout` | `8.0` | Seconds before crt.sh query times out. |
| `asn_timeout` | `3.0` | Seconds before Team Cymru ASN lookup times out. |
| `cache_ttl_hours` | `6` | OSINT result cache lifetime in `~/.barb/cache.db`. |

---

## The `~/.barb/` directory

| Path | Purpose | Permissions |
|------|---------|-------------|
| `~/.barb/` (dir) | All user state | `0o700` (owner-only) |
| `~/.barb/config.yaml` | Saved configuration | `0o600` (owner read/write) |
| `~/.barb/cache.db` | SQLite OSINT result cache | Inside the `0o700` dir |
| `~/.barb/data/allowlist.json` | User-override Tranco allowlist (written by `update-data`) | `0o600` |
| `~/.barb/rdap_bootstrap.json` | IANA RDAP bootstrap cache (auto-managed, max 7-day refresh) | Inside the `0o700` dir |

> [!WARNING]
> `~/.barb/` is created with `0o700` and all files within it with `0o600`, so
> secrets and cached data are owner-readable only. Do not relax these permissions.

---

## Weight and threshold tuning

**Raising a weight** (e.g. `homoglyph: 2.0`) makes that analyzer's signals count
more toward the total score, pushing borderline URLs to a higher verdict tier.

**Lowering a weight** (e.g. `keyword: 0.3`) reduces the score contribution of
that analyzer — useful if you see frequent false positives from keyword matches on
internal tooling URLs.

**Raising a threshold** (e.g. `suspicious: 6`) requires a higher score before the
verdict escalates to that tier. This reduces false positives but also lets some
true positives remain at a lower tier.

**Lowering a threshold** (e.g. `high_risk: 6`) escalates verdicts more
aggressively. Useful in high-sensitivity environments where any medium-confidence
signal should be treated as high-risk.

> [!NOTE]
> The severity-floor rule (any CRITICAL signal → HIGH\_RISK, any HIGH signal →
> SUSPICIOUS) operates independently of thresholds and analyzer weights. It cannot
> be disabled via configuration.
