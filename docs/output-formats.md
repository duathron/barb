# Output formats

[← Docs index](README.md)

`barb` can emit analysis results in six shapes. Select with `-o` / `--output`.
Every JSON, NDJSON, CSV, and STIX block below was produced by running `barb`
against the real binary.

| Format | How to select | Defang behavior |
|--------|---------------|-----------------|
| `rich` (default) | `-o rich` | Defanged in terminal output |
| `console` | `-o console` | Defanged in terminal output |
| `json` | `-o json` | Original URL + `defanged_url` field |
| `ndjson` | `-o ndjson` | Original URL + `defanged_url` field |
| `csv` | `-o csv` | Original URL + `defanged_url` column |
| `stix` | `-o stix` | Original URL in STIX pattern |

> [!NOTE]
> Machine output goes to **stdout**; the banner, warnings, and progress messages
> go to **stderr**. `barb analyze … -o ndjson -q > out.ndjson` gives a clean
> machine file while notices remain visible in the terminal.

---

## Defang rules

`barb` rewrites URLs into non-clickable form for safe display (`hxxps[://]evil[.]com`).

| Format | Defang behavior |
|--------|-----------------|
| `rich` / `console` | **Always defanged** in the terminal display. `--no-defang` disables this. |
| `json` / `ndjson` / `csv` / `stix` | Real original URL is preserved. Both `url` (original) and `defanged_url` fields are carried in the output. |

Machine formats keep real, parseable URLs by default. Use `--no-defang` only with
`rich`/`console` when you need the original URL on-screen.

---

## rich (default)

The default format. Colored, human-oriented: a verdict box (URL, verdict label,
risk score) followed by a signals table with severity, analyzer name, and finding.
The ASCII banner prints unless suppressed with `--quiet` / `-q`.

```bash
barb analyze "http://paypal.com@evil-login.tk/verify" -q
```

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

Use `rich` for interactive terminal work. It is not suitable for scripting or
downstream parsing.

---

## console (`-o console`)

Plain-text equivalent of `rich` — same content, lighter formatting. URLs are
still defanged. Useful when the terminal does not support Rich markup or when you
want a grep-friendly view.

```bash
barb analyze "https://suspicious-site.tk/paypal-login" -o console -q
```

```
URL:      hxxps[://]suspicious-site[.]tk/paypal-login
Verdict:  LOW_RISK
Score:    2.6
Signals:
  [MEDIUM  ] tld          TLD '.tk' is commonly associated with phishing
  [LOW     ] keyword      Matched keywords: login
```

---

## json (`-o json`)

Pretty-printed JSON array (2-space indent), one object per URL. The complete
`AnalysisResult` structure including the `parsed_url` decomposition.

```bash
barb analyze "http://paypal.com@evil-login.tk/verify" "https://bit.ly/3abc123" -o json -q
```

```json
[
  {
    "url": "http://paypal.com@evil-login.tk/verify",
    "defanged_url": "hxxp[://]paypal[.]com@evil-login[.]tk/verify",
    "parsed_url": {
      "original": "http://paypal.com@evil-login.tk/verify",
      "scheme": "http",
      "userinfo": "paypal.com",
      "host": "evil-login.tk",
      "port": null,
      "path": "/verify",
      "query": null,
      "fragment": null,
      "is_ip": false,
      "is_punycode": false
    },
    "signals": [
      {
        "analyzer": "tld",
        "severity": "MEDIUM",
        "label": "Suspicious TLD",
        "detail": "TLD '.tk' is commonly associated with phishing",
        "weight": 1.0
      },
      {
        "analyzer": "ip_url",
        "severity": "CRITICAL",
        "label": "Userinfo in URL",
        "detail": "URL contains userinfo 'paypal.com' before '@'; the real host is 'evil-login.tk'",
        "weight": 1.0
      },
      {
        "analyzer": "keyword",
        "severity": "LOW",
        "label": "Phishing keywords in URL path",
        "detail": "Matched keywords: verify",
        "weight": 1.0
      }
    ],
    "risk_score": 7.6,
    "verdict": "HIGH_RISK",
    "explanation": null,
    "analyzed_at": "2026-06-01T16:24:24.488073Z"
  },
  {
    "url": "https://bit.ly/3abc123",
    "defanged_url": "hxxps[://]bit[.]ly/3abc123",
    "parsed_url": {
      "original": "https://bit.ly/3abc123",
      "scheme": "https",
      "userinfo": null,
      "host": "bit.ly",
      "port": null,
      "path": "/3abc123",
      "query": null,
      "fragment": null,
      "is_ip": false,
      "is_punycode": false
    },
    "signals": [
      {
        "analyzer": "shortener",
        "severity": "MEDIUM",
        "label": "URL shortener detected",
        "detail": "Domain 'bit.ly' is a known URL shortener",
        "weight": 1.0
      }
    ],
    "risk_score": 1.6,
    "verdict": "LOW_RISK",
    "explanation": null,
    "analyzed_at": "2026-06-01T16:24:24.488365Z"
  }
]
```

Use `-o json` when piping into `jq`, `vex`, or any downstream tool that expects
structured input. See [Pipeline](pipeline.md) for the barb → vex handoff.

---

## ndjson (`-o ndjson`)

One compact JSON object **per line** (no indentation, no outer array). Identical
fields to `json`, but formatted for streaming into log pipelines, `tail -f`, and
log aggregators.

```bash
barb analyze "http://paypal.com@evil-login.tk/verify" -o ndjson -q
```

```
{"url":"http://paypal.com@evil-login.tk/verify","defanged_url":"hxxp[://]paypal[.]com@evil-login[.]tk/verify","parsed_url":{"original":"http://paypal.com@evil-login.tk/verify","scheme":"http","userinfo":"paypal.com","host":"evil-login.tk","port":null,"path":"/verify","query":null,"fragment":null,"is_ip":false,"is_punycode":false},"signals":[{"analyzer":"tld","severity":"MEDIUM","label":"Suspicious TLD","detail":"TLD '.tk' is commonly associated with phishing","weight":1.0},{"analyzer":"ip_url","severity":"CRITICAL","label":"Userinfo in URL","detail":"URL contains userinfo 'paypal.com' before '@'; the real host is 'evil-login.tk'","weight":1.0},{"analyzer":"keyword","severity":"LOW","label":"Phishing keywords in URL path","detail":"Matched keywords: verify","weight":1.0}],"risk_score":7.6,"verdict":"HIGH_RISK","explanation":null,"analyzed_at":"2026-06-01T16:24:27.422081Z"}
```

In a batch run, each URL produces one line. Stderr stays clean with `-q`.

Streaming example:

```bash
tail -f access.log | grep -oP 'https?://\S+' | barb analyze -o ndjson -q
```

---

## csv (`-o csv`)

A flattened, spreadsheet-friendly view. Signals are joined into a pipe-separated
`signals_summary` column (`SEVERITY:analyzer:label|…`).

```bash
barb analyze "http://paypal.com@evil-login.tk/verify" -o csv -q
```

```
url,defanged_url,verdict,risk_score,signal_count,signals_summary,explanation,analyzed_at
http://paypal.com@evil-login.tk/verify,hxxp[://]paypal[.]com@evil-login[.]tk/verify,HIGH_RISK,7.6,3,MEDIUM:tld:Suspicious TLD|CRITICAL:ip_url:Userinfo in URL|LOW:keyword:Phishing keywords in URL path,,2026-06-01T16:24:34.456308+00:00
```

Fixed column set: `url`, `defanged_url`, `verdict`, `risk_score`, `signal_count`,
`signals_summary`, `explanation`, `analyzed_at`.

Use `-o csv` for spreadsheet import or grep workflows.

---

## stix (`-o stix`)

Emits a STIX 2.1 `bundle` with one `indicator` SDO per URL that has a verdict of
SUSPICIOUS, HIGH\_RISK, or PHISHING. SAFE and LOW\_RISK URLs produce no STIX
objects — the bundle is still valid. IDs are deterministic UUID-5; confidence maps
from verdict (SUSPICIOUS → 50, HIGH\_RISK → 75, PHISHING → 95).

```bash
barb analyze "http://paypal.com@evil-login.tk/verify" -o stix -q
```

```json
{
  "type": "bundle",
  "id": "bundle--dba5ecc9-4337-472c-a37f-5b25c44b4a3e",
  "objects": [
    {
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--4284e981-79a9-5f8d-a25f-5348c73b0817",
      "created": "2026-06-01T16:24:37.051985+00:00",
      "modified": "2026-06-01T16:24:37.051985+00:00",
      "name": "Phishing indicator: HIGH_RISK (http://paypal.com@evil-login.tk/verify)",
      "description": "Verdict: HIGH_RISK, Risk score: 7.6. Signals: MEDIUM:tld:Suspicious TLD; CRITICAL:ip_url:Userinfo in URL; LOW:keyword:Phishing keywords in URL path",
      "pattern": "[url:value = 'http://paypal.com@evil-login.tk/verify']",
      "pattern_type": "stix",
      "pattern_version": "2.1",
      "valid_from": "2026-06-01T16:24:37.051985+00:00",
      "indicator_types": [
        "malicious-activity"
      ],
      "confidence": 75
    }
  ]
}
```

Use `-o stix` for SIEM or TIP ingest.

> [!NOTE]
> The STIX bundle `id` and timestamps vary per run. The `indicator` id is
> deterministic (UUID-5 from the URL string) — the same URL produces the same
> indicator id on every run, which supports deduplication in downstream tools.

---

## Threshold and exit-code interaction

`--threshold INT` filters which URLs appear in output: only URLs with
`risk_score >= threshold` are printed. The exit code is based on the worst verdict
among the URLs that **were** reported (at or above the threshold), not all URLs
analyzed.

```bash
# Only report URLs with risk_score >= 4; exit code reflects worst of those
barb analyze -f urls.txt -o json --threshold 4 -q
```

| Exit code | Condition |
|-----------|-----------|
| `0` | All reported URLs are SAFE or LOW\_RISK |
| `1` | At least one reported URL is SUSPICIOUS or HIGH\_RISK |
| `2` | At least one reported URL is PHISHING |
| `3` | Error — bad input, missing file, non-HTTPS `--source`, or no URLs |
