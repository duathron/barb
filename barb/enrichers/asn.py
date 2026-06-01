"""ASN enricher — hosting infrastructure lookup via Team Cymru WHOIS.

Resolves the URL's hostname to an IP, then queries Team Cymru's public
WHOIS service (``whois.cymru.com``, port 43) to retrieve the hosting ASN.
No API key required.  Stdlib socket only.

This enricher is **INFO-only**: it provides analyst context (ASN number,
name, country, BGP prefix) for pivoting but has zero score impact.

Privacy / security notes
------------------------
- Only the resolved IP is sent to Team Cymru (``whois.cymru.com``).
- The hostname is resolved by the system resolver — standard DNS, same as
  any browser lookup.
- The analyzed URL itself is **never fetched or contacted**.
- All errors are fail-open: any failure returns ``[]``, never raises.
"""

from __future__ import annotations

import socket
from typing import Optional

from barb.models import ParsedURL, Signal, SignalSeverity


class ASNEnricher:
    """Look up the hosting ASN of the resolved IP via Team Cymru WHOIS."""

    @property
    def name(self) -> str:
        return "osint:asn"

    def __init__(self, timeout: float = 3.0) -> None:
        self._timeout = timeout

    # ------------------------------------------------------------------
    # Testable helpers
    # ------------------------------------------------------------------

    def _resolve_ip(self, host: str) -> Optional[str]:
        """Resolve *host* to its first A-record IP; return None on failure."""
        old = socket.getdefaulttimeout()
        socket.setdefaulttimeout(self._timeout)
        try:
            results = socket.getaddrinfo(host, None, socket.AF_INET)
            if results:
                return results[0][4][0]
        except Exception:
            pass
        finally:
            socket.setdefaulttimeout(old)
        return None

    def _query_cymru(self, ip: str, timeout: float) -> Optional[str]:
        """Send a verbose Team Cymru WHOIS query for *ip*; return raw text or None."""
        try:
            with socket.create_connection(("whois.cymru.com", 43), timeout=timeout) as sock:
                sock.sendall(f"begin\nverbose\n{ip}\nend\n".encode())
                chunks: list[bytes] = []
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    chunks.append(chunk)
            return b"".join(chunks).decode(errors="replace")
        except Exception:
            return None

    def _parse_cymru(self, raw: str) -> Optional[dict]:
        """Parse a verbose Team Cymru WHOIS response.

        Expected format (after the header line)::

            AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name
            13335   | 1.1.1.1 | 1.1.1.0/24 | US | arin | 2010-07-14 | CLOUDFLARENET, US

        Returns a dict with keys ``asn``, ``cc``, ``as_name``, ``prefix``,
        or None if no parseable data line is found.
        """
        if not raw:
            return None
        for line in raw.splitlines():
            # Skip the header line (contains the literal text "AS Name" or "BGP Prefix")
            if "AS Name" in line or "BGP Prefix" in line:
                continue
            parts = line.split("|")
            if len(parts) < 7:
                continue
            asn = parts[0].strip()
            prefix = parts[2].strip()
            cc = parts[3].strip()
            as_name = parts[6].strip()
            # Validate: asn should be numeric
            if not asn.isdigit():
                continue
            return {"asn": asn, "cc": cc, "as_name": as_name, "prefix": prefix}
        return None

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def enrich(self, parsed_url: ParsedURL) -> list[Signal]:
        """Return a single INFO signal with the hosting ASN, or [] on any failure."""
        try:
            host = parsed_url.host.lower()

            # Resolve IP
            if parsed_url.is_ip:
                ip: Optional[str] = host
            else:
                ip = self._resolve_ip(host)
            if ip is None:
                return []

            # Query Team Cymru
            raw = self._query_cymru(ip, self._timeout)
            if raw is None:
                return []

            # Parse response
            info = self._parse_cymru(raw)
            if info is None:
                return []

            detail = (
                f"IP {ip} hosted on AS{info['asn']} {info['as_name']} "
                f"({info['cc']}), prefix {info['prefix']}"
            )
            return [Signal(
                analyzer=self.name,
                severity=SignalSeverity.INFO,
                label="Hosting infrastructure (ASN)",
                detail=detail,
            )]
        except Exception:
            return []  # Fail-open: no exception escapes enrich()
