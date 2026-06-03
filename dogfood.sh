#!/usr/bin/env bash
# Dogfood gate for barb — offline heuristics (no key, the core). Optional OSINT
# network tier via BARB_DOGFOOD_OSINT=1. Framework QA policy: no release without a pass.
set -uo pipefail
crashed() { printf '%s' "$1" | grep -q 'Traceback (most recent call last)'; }
fail=0

echo "== offline (heuristics) =="
out="$(barb version 2>&1)" || { echo "FAIL: barb version"; fail=1; }
crashed "$out" && { echo "FAIL: version crashed"; fail=1; }
for u in "https://example.com" "http://paypa1-secure-login.example.com/verify" \
         "http://xn--80ak6aa92e.com" "report.dll" "/etc/passwd" "a sentence." "" \
         "$(printf 'a%.0s' {1..3000})"; do
  out="$(barb analyze "$u" 2>&1)" || true
  if crashed "$out"; then echo "DOGFOOD FAIL: analyze '$u' crashed"; printf '%s\n' "$out" | tail -5; fail=1; fi
done
if [ "$fail" -ne 0 ]; then echo "DOGFOOD: FAIL (offline)"; exit 1; fi

if [ "${BARB_DOGFOOD_OSINT:-0}" = "1" ]; then
  echo "== osint (network: DNS/RDAP/crt.sh) =="
  out="$(barb analyze "https://example.com" --osint 2>&1)" || true
  if crashed "$out"; then echo "DOGFOOD FAIL: --osint crashed"; printf '%s\n' "$out" | tail -8; fail=1; fi
  if [ "$fail" -ne 0 ]; then echo "DOGFOOD: FAIL (osint)"; exit 1; fi
  echo "DOGFOOD: PASS (offline + osint)"; exit 0
fi
echo "DOGFOOD: PASS (offline) — OSINT tier not run (set BARB_DOGFOOD_OSINT=1 for network checks)"
exit 0
