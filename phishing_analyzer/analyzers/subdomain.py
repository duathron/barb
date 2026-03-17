"""Subdomain analyzer — detects excessive depth and squatting patterns."""

from __future__ import annotations

from phishing_analyzer.models import ParsedURL, Signal, SignalSeverity


class SubdomainAnalyzer:
    """Detect suspicious subdomain patterns."""

    @property
    def name(self) -> str:
        return "subdomain"

    def analyze(self, parsed_url: ParsedURL) -> list[Signal]:
        signals: list[Signal] = []
        parts = parsed_url.host.split(".")

        # Excessive subdomain depth (more than 3 levels: sub.domain.tld)
        if len(parts) > 4:
            signals.append(Signal(
                analyzer=self.name,
                severity=SignalSeverity.HIGH,
                label="Excessive subdomain depth",
                detail=f"Domain has {len(parts)} levels: {parsed_url.host}",
            ))
        elif len(parts) > 3:
            signals.append(Signal(
                analyzer=self.name,
                severity=SignalSeverity.LOW,
                label="Deep subdomain",
                detail=f"Domain has {len(parts)} levels: {parsed_url.host}",
            ))

        # Suspicious keywords in subdomains
        suspicious_keywords = [
            "login", "signin", "secure", "account", "verify", "update",
            "confirm", "banking", "password", "auth", "validation",
        ]
        for part in parts[:-2]:  # Exclude domain and TLD
            lower_part = part.lower()
            for keyword in suspicious_keywords:
                if keyword in lower_part:
                    signals.append(Signal(
                        analyzer=self.name,
                        severity=SignalSeverity.MEDIUM,
                        label="Suspicious subdomain keyword",
                        detail=f"Subdomain '{part}' contains '{keyword}'",
                    ))
                    break

        return signals
