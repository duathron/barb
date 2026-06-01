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
