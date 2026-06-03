"""RDAP (Registration Data Access Protocol) enricher.

Queries the IANA RDAP bootstrap registry to find the authoritative RDAP server
for a domain's TLD, then fetches registration data (RFC 7480-7484, 9083).

No external packages or API keys required — stdlib urllib only.

Signals
-------
HIGH   — domain registered < 30 days ago
MEDIUM — domain registered < 90 days ago
LOW    — registrant contact information is privacy-protected / redacted
"""

from __future__ import annotations

import json
import stat
import threading
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from barb.models import ParsedURL, Signal, SignalSeverity

_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
_BOOTSTRAP_CACHE = Path.home() / ".barb" / "rdap_bootstrap.json"
_BOOTSTRAP_TTL = 7 * 24 * 3600  # 7 days in seconds
_BOOTSTRAP_LOCK = threading.Lock()


def _load_bootstrap(timeout: float) -> dict:
    """Load IANA RDAP bootstrap data, refreshing from network when stale."""
    with _BOOTSTRAP_LOCK:
        now = time.time()
        if _BOOTSTRAP_CACHE.exists():
            try:
                data = json.loads(_BOOTSTRAP_CACHE.read_text())
                if now - data.get("_fetched_at", 0) < _BOOTSTRAP_TTL:
                    return data
            except (json.JSONDecodeError, OSError):
                pass

        try:
            req = urllib.request.Request(
                _BOOTSTRAP_URL,
                headers={"Accept": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read())
            data["_fetched_at"] = now
            try:
                _BOOTSTRAP_CACHE.parent.mkdir(mode=stat.S_IRWXU, parents=True, exist_ok=True)
                _BOOTSTRAP_CACHE.write_text(json.dumps(data))
                _BOOTSTRAP_CACHE.chmod(stat.S_IRUSR | stat.S_IWUSR)
            except OSError:
                pass
            return data
        except Exception:
            return {}


def _find_server(tld: str, bootstrap: dict) -> Optional[str]:
    """Return the RDAP base URL for the given TLD, or None if unknown."""
    tld_lower = tld.lower()
    for entry in bootstrap.get("services", []):
        if not isinstance(entry, (list, tuple)) or len(entry) < 2:
            continue
        tlds, servers = entry[0], entry[1]
        # Guard: tlds and servers must be iterable collections
        if not isinstance(tlds, (list, tuple)) or not isinstance(servers, (list, tuple)):
            continue
        if tld_lower in (t.lower() for t in tlds if isinstance(t, str)) and servers:
            server = servers[0]
            if not isinstance(server, str):
                continue
            return server.rstrip("/") + "/"
    return None


class RDAPEnricher:
    """Query RDAP for domain registration age and privacy protection."""

    @property
    def name(self) -> str:
        return "osint:rdap"

    def __init__(self, timeout: float = 5.0) -> None:
        self._timeout = timeout

    def enrich(self, parsed_url: ParsedURL) -> list[Signal]:
        """Fetch RDAP data and return signals for suspicious registration patterns."""
        if parsed_url.is_ip:
            return []

        host = parsed_url.host.lower()
        parts = host.split(".")
        if len(parts) < 2:
            return []
        tld = parts[-1]

        bootstrap = _load_bootstrap(self._timeout)
        server = _find_server(tld, bootstrap)
        if not server:
            return []  # Unknown TLD — fail-open

        try:
            req = urllib.request.Request(
                f"{server}domain/{host}",
                headers={"Accept": "application/rdap+json"},
            )
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                data = json.loads(resp.read())
        except Exception:
            return []  # Network or parse error — fail-open

        # Guard: RDAP response must be a dict; a non-dict (e.g. list) would cause
        # AttributeError on .get() — fail-open.
        if not isinstance(data, dict):
            return []

        signals: list[Signal] = []

        # --- Registration date -----------------------------------------------
        for event in data.get("events", []):
            # Guard: each event must be a dict; skip malformed entries
            if not isinstance(event, dict):
                continue
            if event.get("eventAction") == "registration":
                raw_date = event.get("eventDate", "")
                try:
                    # Guard: raw_date must be a str; a non-str (e.g. int epoch) would
                    # cause AttributeError on .replace() — skip gracefully.
                    if not isinstance(raw_date, str):
                        raise TypeError("eventDate is not a string")
                    reg_date = datetime.fromisoformat(raw_date.replace("Z", "+00:00"))
                    age_days = (datetime.now(timezone.utc) - reg_date).days
                    if age_days < 30:
                        signals.append(
                            Signal(
                                analyzer=self.name,
                                severity=SignalSeverity.HIGH,
                                label="Recently registered domain",
                                detail=f"Domain registered {age_days} day(s) ago ({reg_date.date()})",
                            )
                        )
                    elif age_days < 90:
                        signals.append(
                            Signal(
                                analyzer=self.name,
                                severity=SignalSeverity.MEDIUM,
                                label="Recently registered domain",
                                detail=f"Domain registered {age_days} day(s) ago ({reg_date.date()})",
                            )
                        )
                except (ValueError, TypeError):
                    pass
                break  # Only care about the first registration event

        # --- Privacy protection ----------------------------------------------
        # Guard: each remark must be a dict with a list-of-strings description;
        # non-dict remarks and non-list/non-str descriptions are skipped to avoid
        # AttributeError (None.get), TypeError (int not iterable), and
        # wrong-behavior (str description iterates as characters).
        remark_notes: list[str] = []
        for remark in data.get("remarks", []):
            if not isinstance(remark, dict):
                continue
            description = remark.get("description", [])
            if not isinstance(description, list):
                continue
            for note in description:
                if isinstance(note, str):
                    remark_notes.append(note)
        remarks_text = " ".join(remark_notes).upper()
        if "REDACTED" in remarks_text or "PRIVACY" in remarks_text or "WITHHELD" in remarks_text:
            signals.append(
                Signal(
                    analyzer=self.name,
                    severity=SignalSeverity.LOW,
                    label="WHOIS privacy enabled",
                    detail="Registrant contact information is redacted / privacy-protected",
                )
            )

        return signals
