"""crt.sh certificate-transparency enricher.

Queries the crt.sh CT log aggregator for public TLS certificates issued for the
domain.  Only the hostname is sent — the analyzed URL itself is never fetched.

Signals
-------
MEDIUM — newest certificate issued < 7 days ago   (fresh cert correlates with phishing)
LOW    — newest certificate issued < 30 days ago
INFO   — no certificate transparency records found for the domain
"""

from __future__ import annotations

import json
import urllib.request
from datetime import datetime, timezone

from barb.models import ParsedURL, Signal, SignalSeverity

_CRTSH_URL = "https://crt.sh/?q={host}&output=json"


class CrtShEnricher:
    """Query crt.sh for certificate-transparency data about the domain."""

    @property
    def name(self) -> str:
        return "osint:crtsh"

    def __init__(self, timeout: float = 8.0) -> None:
        self._timeout = timeout

    def enrich(self, parsed_url: ParsedURL) -> list[Signal]:
        """Fetch CT records and return signals for recently issued certificates."""
        if parsed_url.is_ip:
            return []

        host = parsed_url.host.lower()
        if len(host.split(".")) < 2:
            return []

        url = _CRTSH_URL.format(host=urllib.request.quote(host, safe=""))

        try:
            req = urllib.request.Request(
                url,
                headers={"Accept": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                entries = json.loads(resp.read())
        except Exception:
            return []  # Network or parse error — fail-open

        # Guard: crt.sh must return a list; a non-list (e.g. error dict) would cause
        # AttributeError when iterating and calling .get() on string keys.
        if not isinstance(entries, list):
            return []

        if not entries:
            return [
                Signal(
                    analyzer=self.name,
                    severity=SignalSeverity.INFO,
                    label="No certificate transparency records",
                    detail=(
                        f"No public TLS certificates found in CT logs for {host!r}. "
                        "This may indicate a very new or non-public domain."
                    ),
                )
            ]

        # Find the most recently issued certificate
        now = datetime.now(timezone.utc)
        newest_date: datetime | None = None

        for entry in entries:
            # Guard: each entry must be a dict; skip non-dict entries (e.g. None)
            if not isinstance(entry, dict):
                continue
            raw = entry.get("not_before", "")
            if not raw:
                continue
            try:
                dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
                # crt.sh may return naive datetimes (no timezone suffix) — treat as UTC
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                if newest_date is None or dt > newest_date:
                    newest_date = dt
            except (ValueError, TypeError):
                continue

        if newest_date is None:
            return []

        age_days = (now - newest_date).days

        if age_days < 7:
            return [
                Signal(
                    analyzer=self.name,
                    severity=SignalSeverity.MEDIUM,
                    label="Recently issued TLS certificate",
                    detail=(
                        f"Newest certificate issued {age_days} day(s) ago "
                        f"({newest_date.date()}). Freshly-minted certs correlate with phishing campaigns."
                    ),
                )
            ]

        if age_days < 30:
            return [
                Signal(
                    analyzer=self.name,
                    severity=SignalSeverity.LOW,
                    label="Recently issued TLS certificate",
                    detail=(f"Newest certificate issued {age_days} day(s) ago ({newest_date.date()})."),
                )
            ]

        return []
