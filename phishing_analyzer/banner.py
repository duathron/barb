"""ASCII art banner for phishing-analyzer."""

from __future__ import annotations

import sys


BANNER = r"""
    ╔═══════════════════════════════════╗
    ║   🎣  phishing-analyzer  v{ver}  ║
    ║   Heuristic URL Analysis Engine   ║
    ╚═══════════════════════════════════╝
"""


def show_banner(version: str, quiet: bool = False) -> None:
    """Print the ASCII banner unless suppressed or piped."""
    if quiet or not sys.stderr.isatty():
        return
    print(BANNER.format(ver=version), file=sys.stderr)
