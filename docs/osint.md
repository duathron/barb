# OSINT enrichment

[← Docs index](README.md)

barb's offline core makes zero network calls. Pass `--osint` to layer in four
infrastructure checks about the domain — registration age, certificate history,
DNS resolution, and hosting ASN. These queries target infrastructure metadata
about the domain, never the analyzed URL itself.

> [!WARNING]
> **`--osint` is opt-in and fail-open; no API key required.** All four enrichers
> use Python stdlib only (`socket`, `urllib`). A timeout or connection error drops
> that enricher's signals and analysis continues with the offline results.

---

## The four enrichers

| Enricher | Protocol / endpoint | What it checks | Signals | Timeout |
|----------|--------------------|--------------------|---------|---------|
| **DNS** | `socket.getaddrinfo` via your system resolver (port 53, stdlib) | Resolves the host to one or more IPs | HIGH on loopback (127.0.0.0/8) or known sinkhole IP; MEDIUM on private IP (RFC 1918) or NXDOMAIN | 2 s |
| **RDAP** | IANA RDAP bootstrap (`https://data.iana.org/rdap/dns.json`) → TLD registry RDAP server; `urllib` stdlib; no API key | Domain registration age and registrant redaction | HIGH if domain < 30 days old; MEDIUM if < 90 days; LOW if registrant privacy-redacted | 5 s |
| **crt.sh** | `https://crt.sh/` (Sectigo CT log aggregator); `urllib` stdlib; sends hostname only; no API key | Most recent TLS certificate issuance date in Certificate Transparency logs | MEDIUM if newest cert < 7 days old; LOW if < 30 days; INFO if no CT records found | 8 s |
| **ASN** | Team Cymru WHOIS (`whois.cymru.com:43`); stdlib socket; no API key; sends only the resolved IP | Hosting AS number, name, country, and BGP prefix | INFO — analyst context only; **zero score impact** | 3 s |

Source of truth: `barb/osint/` (enricher implementations), `barb/config.py`
(`OsintConfig` — timeout defaults).

---

## When to use `--osint`

`--osint` is **not** a "find more phishing" switch. It adds **no live-phishing
recall** — measured Δ = 0 across resolving phishing domains (see
[Recall](#recall-what---osint-does-and-does-not-add-measured)). Turn it on for
**infrastructure context and takedown status on a domain you are already
investigating**, not to catch more URLs. Concretely it buys:

1. **Takedown / retro-triage** — the DNS enricher flags domains that no longer
   resolve (NXDOMAIN). Sweeping an old IOC list, this tells you which phishing
   infrastructure is already dead or sinkholed. (This is the only effect that
   shows up as "recall" — and it's list hygiene, not live detection.)
2. **Sinkhole / loopback catch** — DNS emits HIGH when a domain resolves to a
   known sinkhole or a loopback address (infrastructure already flagged bad).
3. **Per-URL analyst context** (intel for a human decision, not a score change):
   - **ASN** — hosting attribution: AS number, name, country, BGP prefix (pivot
     on the hosting provider). INFO, zero score impact.
   - **RDAP** — domain age and a registrant-privacy flag ("registered 3 days ago"
     is a datapoint worth having).
   - **crt.sh** — certificate recency / CT-log presence.
   - **DNS** — where the host actually resolves.

> [!NOTE]
> The recall result is **threat-profile-dependent**. RDAP domain-age *would*
> contribute against campaigns built on freshly-registered domains — those exist.
> The corpus measured here (OpenPhish) skews to phishing on **compromised / old
> hosting and free platforms** (`github.io`, `pages.dev`), where domains aren't
> new, so RDAP-age never fires. "No recall bonus" is proven for that profile,
> untested for a fresh-registration-heavy one.

**Costs:** network latency, a privacy footprint (your resolver, the TLD RDAP
registry, crt.sh/Sectigo, and Team Cymru each learn the domain you're
investigating — see [Privacy footprint](#privacy-footprint)), and occasional DNS
false positives (a transient or geo-blocked legitimate domain can look like
NXDOMAIN).

---

## Opt-in, fail-open, cached

### Opt-in

`--osint` must be passed explicitly. `barb analyze` never makes network calls
without it.

### Fail-open

Every enricher is wrapped in a `try/except`. A timeout, DNS error, parse failure,
or any other exception:

1. Drops that enricher's signals.
2. Logs a debug message.
3. Continues to the next enricher.

The overall analysis completes with whatever offline + available OSINT signals
were collected.

### Cache

OSINT results are stored per host in `~/.barb/cache.db` (SQLite). Default TTL:
**6 hours**. Repeat lookups within the TTL window make no network calls.

Bypass the cache with `--no-cache`:

```bash
barb analyze "https://suspicious-site.tk/paypal-login" --osint --no-cache
```

The cache path and TTL are configurable in `~/.barb/config.yaml` under the
`osint` key. See [Configuration → osint](configuration.md#osint).

---

## Usage

```bash
barb analyze "https://suspicious-site.tk/paypal-login" --osint -q
```

OSINT signals appear in the same signals table as offline signals, prefixed with
their analyzer name (`osint:dns`, `osint:rdap`, `osint:crtsh`, `osint:asn`). The
ASN enricher always emits an INFO signal — it carries no score points but gives
analyst context (AS number, name, country, prefix).

---

## Recall: what `--osint` does and does not add (measured)

Measured on a fresh corpus (OpenPhish phishing + Tranco benign, built via
`eval/fetch_corpus.py`, scored via `eval/run_eval.py --osint`), identical rows
offline vs. with `--osint`. Snapshot 2026-06-07, barb 1.6.0. Live feeds — a
reproducible snapshot, not a fixed guarantee.

The headline number (`--osint` lifts whole-corpus recall ~0.12 → ~0.31) is
**misleading on its own**, so it is split by whether the phishing domain still
resolves. Of 300 OpenPhish URLs, 123 still resolved (live) and 177 did not
(taken down / sinkholed → NXDOMAIN).

| Phishing subset | Offline recall | With `--osint` | Δ |
|-----------------|----------------|----------------|---|
| **Live (resolving), n=123** | 0.154 | **0.154** | **+0.00 — zero new domains** |
| Dead (NXDOMAIN), n=177 | 17/177 | 69/177 | +52, all from the DNS "does not resolve" signal |

> [!IMPORTANT]
> **`--osint` did not improve live-phishing recall at all** — Δ was exactly
> zero across 123 resolving domains; not one was newly caught. **RDAP, crt.sh,
> and ASN caught zero live phishing** the offline core missed.
>
> The entire apparent "lift" is the DNS enricher flagging **non-resolving
> (taken-down) domains**. That is genuine **retro-triage** value — sweeping an
> old IOC list to confirm infrastructure is gone — but it is **not** live-threat
> detection, and it is an artifact of corpus staleness (OpenPhish entries are
> largely dead by the time you fetch them).
>
> **Why the enrichers whiff on live phishing:** the resolving phishing in this
> corpus sits on **old / compromised hosting and free platforms** (`github.io`,
> `pages.dev`, hacked legitimate sites) — *not* freshly-registered attacker
> domains — so RDAP domain-age never fires. The signals barb's enrichers measure
> are structurally mismatched to where live phishing actually lives.
>
> **Cost:** `--osint` still adds false positives — 1 benign domain flagged here
> (`osint:dns` HIGH on a legitimate host). The recall "signal" (DNS) is the same
> mechanism as the FP, so precision is bound to DNS reliability at run time.

**Bottom line:** use `--osint` for **retro-triage of IOC lists** (confirming
takedowns) and for the analyst *context* it adds (RDAP age, ASN, CT history) —
**not** as a live-phishing recall booster, which it measurably is not. Real
recall on live phishing remains the downstream pipeline's job (vex reputation,
sift correlation, content inspection). RDAP's value against a corpus of genuinely
fresh attacker registrations is **untested here** — it is unmeasured, not proven.

### Reproduce

```bash
python -m eval.fetch_corpus                                  # OpenPhish + Tranco → eval/corpus/real.csv
python -m eval.run_eval --corpus eval/corpus/real.csv        # offline
python -m eval.run_eval --corpus eval/corpus/real.csv --osint  # + OSINT
# then split by resolution to separate taken-down (NXDOMAIN) from live domains
```

---

## Privacy footprint

The offline core makes **zero** outbound connections. When you pass `--osint`,
barb makes the following requests — **never to the analyzed host itself**.

| Connection | Endpoint | What it reveals | Notes |
|------------|----------|-----------------|-------|
| DNS resolution | Your system resolver (`/etc/resolv.conf`, port 53) | The domain being looked up | Same lookup any browser makes |
| RDAP bootstrap | `https://data.iana.org/rdap/dns.json` | That you use barb/RDAP | Fetched at most once per 7 days; cached at `~/.barb/rdap_bootstrap.json` |
| RDAP query | The TLD registry RDAP server (e.g. `rdap.verisign.com` for `.com`) | The domain being investigated | No API key; stdlib `urllib` only |
| crt.sh CT query | `https://crt.sh/` (Sectigo) | The domain being investigated | Reveals domain-of-interest to Sectigo; no API key; stdlib `urllib` only |
| ASN lookup | `whois.cymru.com:43` (Team Cymru) | The **resolved IP** of the domain | Sends only the IP — not the URL or hostname; stdlib socket only |

- The suspect host is **never contacted** — no HTTP GET/HEAD to the URL, no DNS
  beacon to attacker-controlled infrastructure beyond normal name resolution.
- No credentials are ever transmitted.
- All OSINT calls are fail-open: a timeout or error drops the enrichment signals
  and analysis continues offline.
- OSINT results are cached per host in `~/.barb/cache.db` (default TTL 6 h), so
  repeat lookups make no network calls. `--no-cache` forces fresh requests.
- URL length is capped at 2048 characters.
- `~/.barb/` is created with `0o700` permissions; individual files with `0o600`.

> [!WARNING]
> **All detection data is bundled static JSON — no runtime downloads.** The one
> explicit exception is the opt-in `update-data` command, which downloads the
> Tranco list over HTTPS only when the user runs it.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `--osint` is slow | crt.sh has an 8 s timeout; slow TLD registries can push RDAP close to 5 s | Expected on first lookup. Results are cached for 6 h. Use `--no-cache` only when fresh data is needed. |
| `--osint` returns no enrichment signals | A timeout or network error occurred | barb is fail-open — analysis completes with offline signals only. Check network connectivity. |
| ASN signal shows INFO with no score | Expected — the ASN enricher carries zero score impact by design | Use the ASN context for analyst pivoting, not for verdict escalation. |
