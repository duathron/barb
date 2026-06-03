"""URL defanging and refanging utilities.

Copied from vex to avoid cross-project dependency.
Refang patterns copied from sift (cross-project copy, not import).
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


# ---------------------------------------------------------------------------
# Refang — comprehensive defang reversal (copied from sift, not imported)
# ---------------------------------------------------------------------------

# ``[at]``/``(at)``/``{at}`` are refanged only when followed by a
# domain-shape token within 60 characters.  Without the lookahead we would
# corrupt prose like ``state[at]rest`` or ``array[at]index``.
_AT_DOMAIN_LOOKAHEAD = r"(?=[A-Za-z0-9._\-]{1,60}(?:\[dot\]|\.))"

# Each pair = (compiled regex, replacement).  Order matters: barb's own
# ``[://]`` bracket group must run first so ``hxxps[://]evil[.]com`` round-
# trips correctly before the scheme pattern strips ``hxxps``.
_DEFANG_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # barb-specific: [://] → :// (barb's own defang_url emits this form)
    (re.compile(r"\[://\]"), "://"),
    # Schemes
    (re.compile(r"\bhxxp(s?)://", re.IGNORECASE), r"http\1://"),
    (re.compile(r"\bhxtp(s?)://", re.IGNORECASE), r"http\1://"),
    (re.compile(r"\bfxp://", re.IGNORECASE), r"ftp://"),
    # Bracketed separators (always safe — ``[.]`` is overwhelmingly a defang)
    (re.compile(r"\[\.\]"), "."),
    (re.compile(r"\(\.\)"), "."),
    (re.compile(r"\{\.\}"), "."),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[/\]"), "/"),
    # Word-form dot separators (rarely seen outside defang contexts).
    (re.compile(r"\[dot\]", re.IGNORECASE), "."),
    (re.compile(r"\{dot\}", re.IGNORECASE), "."),
    # @ sign — only refang when domain-shape follows; avoids corrupting
    # prose like ``state[at]rest``.
    (re.compile(r"\[at\]" + _AT_DOMAIN_LOOKAHEAD, re.IGNORECASE), "@"),
    (re.compile(r"\(at\)" + _AT_DOMAIN_LOOKAHEAD, re.IGNORECASE), "@"),
    (re.compile(r"\{at\}" + _AT_DOMAIN_LOOKAHEAD, re.IGNORECASE), "@"),
    # Fullwidth Unicode lookalikes
    (re.compile("．"), "."),  # FULLWIDTH FULL STOP
    (re.compile("＠"), "@"),  # FULLWIDTH COMMERCIAL AT
    (re.compile("："), ":"),  # FULLWIDTH COLON
    (re.compile("／"), "/"),  # FULLWIDTH SOLIDUS
]

# Zero-width / BOM characters stripped before matching.
_ZERO_WIDTH_TABLE = {
    0x200B: None,  # ZERO WIDTH SPACE
    0x200C: None,  # ZERO WIDTH NON-JOINER
    0x200D: None,  # ZERO WIDTH JOINER
    0xFEFF: None,  # ZERO WIDTH NO-BREAK SPACE / BOM
    0x2060: None,  # WORD JOINER
}


def refang_url(url: str) -> str:
    """Convert a defanged URL back to its live form.

    Handles ``hxxp://``, ``hxxps[://]``, ``[.]``, ``(.)``, ``{.}``,
    ``[dot]``, ``{dot}``, ``[at]``/``(at)``/``{at}`` (with domain lookahead),
    fullwidth Unicode lookalikes, and zero-width invisibles.

    Idempotent: a live URL is returned unchanged; running twice == once.
    IPv6 bracket notation (``http://[::1]/x``) is preserved because ``[::]``
    does not match the ``[.]`` or ``[:/]`` patterns.
    """
    if not url:
        return url
    # Strip zero-width characters first so they don't break later regexes.
    url = url.translate(_ZERO_WIDTH_TABLE)
    for rx, repl in _DEFANG_PATTERNS:
        url = rx.sub(repl, url)
    return url
