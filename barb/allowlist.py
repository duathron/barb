"""Allowlist helper for known-good registrable domains.

The allowlist is loaded from one of two locations, in priority order:

1. **User-override** ``~/.barb/data/allowlist.json`` — written by ``barb update-data``
   when the user opts in to refresh from the Tranco top-1M list.  This file is
   never created or overwritten automatically; it only exists after an explicit
   user invocation of ``barb update-data``.

2. **Bundled curated list** ``barb/data/allowlist.json`` — the default starter set
   shipped with the package.  It covers all official brand domains from
   brands.json plus common top sites (search, CDN, social, banking, SaaS, etc.).

A user who never runs ``barb update-data`` always gets the bundled list — behaviour
is completely unchanged from previous versions.

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
_USER_OVERRIDE = Path.home() / ".barb" / "data" / "allowlist.json"


@lru_cache(maxsize=1)
def _load_allowlist() -> frozenset[str]:
    """Load and cache the allowlist.

    Prefers the user-override (``~/.barb/data/allowlist.json``) when it exists
    and is readable; falls back to the bundled curated list otherwise.
    Returns an empty set on any read/parse failure (fail-open).
    """
    for candidate in (_USER_OVERRIDE, _DATA_FILE):
        try:
            with open(candidate) as f:
                entries = json.load(f)
            return frozenset(str(e).lower().strip() for e in entries)
        except FileNotFoundError:
            continue  # Try next candidate
        except json.JSONDecodeError:
            continue  # Corrupt file → try next candidate
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
