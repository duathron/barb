"""Enricher protocol — structural typing interface for OSINT enrichers."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from barb.models import ParsedURL, Signal


@runtime_checkable
class EnricherProtocol(Protocol):
    """Interface that all OSINT enrichers must implement.

    Enrichers are network-dependent and opt-in (``--osint`` flag).
    They produce Signal objects that are appended to the heuristic signals,
    and the risk score / verdict is recomputed with the full combined set.
    """

    @property
    def name(self) -> str:
        """Unique enricher identifier (e.g., 'osint:dns', 'osint:rdap')."""
        ...

    def enrich(self, parsed_url: ParsedURL) -> list[Signal]:
        """Enrich a parsed URL and return detected signals. Must be fail-open."""
        ...
