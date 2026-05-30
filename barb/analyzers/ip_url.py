"""IP URL analyzer — detects URLs using IP addresses instead of domains."""

from __future__ import annotations

from barb.models import ParsedURL, Signal, SignalSeverity


class IPURLAnalyzer:
    """Detect URLs that use IP addresses instead of domain names."""

    @property
    def name(self) -> str:
        return "ip_url"

    def analyze(self, parsed_url: ParsedURL) -> list[Signal]:
        signals: list[Signal] = []

        if parsed_url.is_ip:
            signals.append(Signal(
                analyzer=self.name,
                severity=SignalSeverity.HIGH,
                label="IP-based URL",
                detail=f"URL uses IP address '{parsed_url.host}' instead of a domain name",
            ))

            # Userinfo in IP-based URL is particularly suspicious
            if parsed_url.userinfo:
                signals.append(Signal(
                    analyzer=self.name,
                    severity=SignalSeverity.CRITICAL,
                    label="Userinfo in IP-based URL",
                    detail=f"URL contains userinfo '{parsed_url.userinfo}' with IP address",
                ))
        elif parsed_url.userinfo:
            # "@" obfuscation on a domain host: the part before '@' is userinfo, not the
            # real host. Attackers put a brand-like string there so the URL *looks*
            # legitimate while resolving to the host after '@'.
            signals.append(Signal(
                analyzer=self.name,
                severity=SignalSeverity.CRITICAL,
                label="Userinfo in URL",
                detail=(
                    f"URL contains userinfo '{parsed_url.userinfo}' before '@'; "
                    f"the real host is '{parsed_url.host}'"
                ),
            ))

        return signals
