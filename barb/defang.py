"""URL defanging and refanging utilities.

Copied from vex to avoid cross-project dependency.
"""

from __future__ import annotations

import re


def defang_url(url: str) -> str:
    """Convert a live URL to a defanged representation.

    - http/https → hxxp/hxxps
    - :// → [://]
    - . → [.]
    """
    result = url
    result = re.sub(r"(?i)https", "hxxps", result)
    result = re.sub(r"(?i)http", "hxxp", result)
    result = result.replace("://", "[://]")
    result = result.replace(".", "[.]")
    return result


def refang_url(url: str) -> str:
    """Convert a defanged URL back to its live form.

    Reverses: hxxp→http, [://]→://, [.]→.
    """
    result = url
    result = re.sub(r"(?i)hxxps", "https", result)
    result = re.sub(r"(?i)hxxp", "http", result)
    result = result.replace("[://]", "://")
    result = result.replace("[.]", ".")
    return result
