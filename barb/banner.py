"""ASCII art banner for barb — compact figlet-style."""

from __future__ import annotations

import sys

from . import __version__


_BANNER = r"""
 _               _
| |__  __ _ _ __| |__
| '_ \/ _` | '__| '_ \
|_.__/\__,_|_|  |_.__/
"""

_INFO = " v{version} | by Christian Huhn | Phishing URL Analysis"
_LINE = " " + "─" * 50


def show_banner(
    *,
    quiet: bool = False,
    update_check_enabled: bool = True,
    check_interval_hours: int = 24,
) -> None:
    """Print the barb ASCII-art banner to stderr.

    The banner is suppressed when:
    - *quiet* is True (via ``-q`` flag or ``output.quiet`` in config.yaml)
    - stdout is not a TTY (i.e. output is piped)
    """
    if quiet:
        return
    if not sys.stdout.isatty():
        return

    print(_BANNER, file=sys.stderr)
    print(_INFO.format(version=__version__), file=sys.stderr)
    print(_LINE, file=sys.stderr)

    # Version update notice (non-blocking, fail-silent)
    if update_check_enabled:
        try:
            from .version_check import check_for_update

            latest = check_for_update(check_interval_hours)
            if latest:
                print(f"  Update available: {__version__} -> {latest}", file=sys.stderr)
                print("  pip install --upgrade barb-phish", file=sys.stderr)
        except Exception:
            pass
