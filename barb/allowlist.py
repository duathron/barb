"""Allowlist helper for known-good registrable domains.

The allowlist (barb/data/allowlist.json) is a curated starter set of well-known
legitimate registrable domains.  It covers all official brand domains from
brands.json plus common top sites (search, CDN, social, banking, SaaS, etc.).
It can be expanded from the Tranco top-1M list via an offline build step —
no runtime download is performed.

Suppression contract (enforced in barb/main.py::_analyze_single):
    If the registrable domain OR full host matches the allowlist,
    signals from analyzers tld, typosquat, homoglyph, and the entropy
    signal whose label == "High entropy domain" are dropped.
    ip_url, keyword, encoding, lexical, subdomain, and brand signals are kept.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

_DATA_FILE = Path(__file__).parent / "data" / "allowlist.json"


@lru_cache(maxsize=1)
def _load_allowlist() -> frozenset[str]:
    """Load and cache the allowlist. Returns empty set if file is missing (fail-open)."""
    try:
        with open(_DATA_FILE) as f:
            entries = json.load(f)
        return frozenset(str(e).lower().strip() for e in entries)
    except (FileNotFoundError, json.JSONDecodeError):
        return frozenset()


def _registrable_domain(host: str) -> str:
    """Extract the registrable domain (last two labels) from a host."""
    parts = host.lower().strip().split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host.lower().strip()


def is_allowlisted(host: str) -> bool:
    """Return True if host or its registrable domain is in the allowlist."""
    allowlist = _load_allowlist()
    host_lower = host.lower().strip()
    if host_lower in allowlist:
        return True
    reg = _registrable_domain(host_lower)
    return reg in allowlist
