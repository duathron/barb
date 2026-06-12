"""Offline allowlist staleness check for barb.

Mirrors the version_check.py / banner.py pattern:
- Offline only (file mtime, no network).
- Fail-open — never raises; never blocks analysis.
- Opt-outable via config flag (``allowlist_check.enabled``).
- Output goes to stderr only (keeps machine stdout clean).

Public API
----------
get_effective_allowlist_age_days() -> float
    Return the age in days of the effective allowlist file (user override if
    present, else bundled).  Returns 0.0 on any error.

check_allowlist_staleness(max_age_days, enabled) -> None
    If enabled and the effective allowlist is older than max_age_days, print
    a one-line hint to stderr.  Never raises.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

# Mirror the paths from allowlist.py
_BUNDLED_DATA_FILE = Path(__file__).parent / "data" / "allowlist.json"
_USER_OVERRIDE = Path.home() / ".barb" / "data" / "allowlist.json"

_DEFAULT_MAX_AGE_DAYS = 90


def get_effective_allowlist_age_days() -> float:
    """Return the age in days of the effective allowlist file.

    Prefers the user override (``~/.barb/data/allowlist.json``) when it
    exists and is stat-able; falls back to the bundled file otherwise.
    Returns 0.0 on any error so the caller never crashes.
    """
    try:
        for candidate in (_USER_OVERRIDE, _BUNDLED_DATA_FILE):
            try:
                mtime = candidate.stat().st_mtime
                age_seconds = time.time() - mtime
                return max(0.0, age_seconds / 86400)
            except OSError:
                continue
        return 0.0
    except Exception:
        return 0.0


def check_allowlist_staleness(
    max_age_days: int = _DEFAULT_MAX_AGE_DAYS,
    enabled: bool = True,
) -> None:
    """Print a one-line stderr hint if the effective allowlist is stale.

    Parameters
    ----------
    max_age_days:
        Number of days after which the allowlist is considered stale.
        Default: 90.
    enabled:
        Set to False to suppress the check entirely (mirrors
        ``update_check.enabled`` in config).
    """
    if not enabled:
        return

    try:
        age_days = get_effective_allowlist_age_days()
        if age_days > max_age_days:
            age_int = int(age_days)
            print(
                f"  allowlist is {age_int} days old — run `barb update-data` to refresh",
                file=sys.stderr,
            )
    except Exception:
        pass  # fail-open: staleness warning never blocks anything
