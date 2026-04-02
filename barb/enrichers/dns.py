"""DNS resolution enricher.

Performs a system DNS lookup for the analyzed domain using stdlib only.
No external packages or API keys required.

Signals
-------
HIGH   — domain resolves to loopback / known sinkhole IP
MEDIUM — domain does not resolve (NXDOMAIN / timeout)
MEDIUM — domain resolves to private / reserved address space
"""

from __future__ import annotations

import ipaddress
import socket

from barb.models import ParsedURL, Signal, SignalSeverity

# Known sinkhole addresses (small curated list)
_SINKHOLE_IPS: frozenset[str] = frozenset({
    "0.0.0.0",
    "74.208.246.4",    # SecureWorks sinkhole
    "204.11.56.48",    # CAIDA
    "199.127.232.105", # SURBL
    "52.8.228.23",     # ISC SANS
})


class DNSEnricher:
    """Resolve the domain via the system DNS resolver and flag suspicious results."""

    @property
    def name(self) -> str:
        return "osint:dns"

    def __init__(self, timeout: float = 2.0) -> None:
        self._timeout = timeout

    def enrich(self, parsed_url: ParsedURL) -> list[Signal]:
        """Resolve domain and return signals for suspicious resolution results."""
        if parsed_url.is_ip:
            return []  # Already handled by ip_url analyzer

        host = parsed_url.host.lower()
        signals: list[Signal] = []

        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(self._timeout)
        try:
            results = socket.getaddrinfo(host, None)
            ips = {r[4][0] for r in results}
            for ip_str in ips:
                try:
                    addr = ipaddress.ip_address(ip_str)
                except ValueError:
                    continue
                if addr.is_loopback or ip_str in _SINKHOLE_IPS:
                    signals.append(Signal(
                        analyzer=self.name,
                        severity=SignalSeverity.HIGH,
                        label="Sinkhole or loopback IP",
                        detail=f"Domain resolves to suspicious address: {ip_str}",
                    ))
                elif addr.is_private:
                    signals.append(Signal(
                        analyzer=self.name,
                        severity=SignalSeverity.MEDIUM,
                        label="Private IP address",
                        detail=f"Domain resolves to private address: {ip_str}",
                    ))
        except socket.gaierror:
            signals.append(Signal(
                analyzer=self.name,
                severity=SignalSeverity.MEDIUM,
                label="DNS does not resolve",
                detail=f"Domain {host!r} does not resolve (NXDOMAIN or DNS error)",
            ))
        except OSError:
            pass  # Unexpected OS error — fail-open
        finally:
            socket.setdefaulttimeout(old_timeout)

        return signals
