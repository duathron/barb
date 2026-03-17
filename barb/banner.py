"""ASCII art banner for barb — fishhook design based on barb.png reference."""

from __future__ import annotations

import sys

from . import __version__


_BANNER = r"""
                                            ╭──╮
      ╭─────────────────────────────────────╯  │
 ╭────╯                                       │
─╯         ╭──────────────────╮           ╭───╯
          ╱                    ╲         ╱
         ╱                      ╲   ╭───╯
        ╱                        ╰──╯
       │
       │     █▀▀▄  ▄▀▀▄  █▀▀▄  █▀▀▄
        ╲    █▀▀█  █▀▀█  █▄▄▀  █▀▀█
         ╲   ▀▀▀   ▀  ▀  ▀  ▀  ▀▀▀
          ╲
"""

_INFO = " v{version} | by Christian Huhn | Phishing URL Analysis"
_LINE = " " + "─" * 50


def show_banner(*, quiet: bool = False) -> None:
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
