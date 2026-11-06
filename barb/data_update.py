"""Opt-in Tranco-based allowlist updater for barb.

This module is ONLY invoked via `barb update-data`.  Nothing in the analyze
path imports or calls it.  No automatic downloads ever occur.

Public API
----------
fetch_tranco(source_url, timeout)  -> bytes
parse_tranco(raw, top_n)           -> list[str]
write_user_allowlist(domains)      -> Path
user_allowlist_path()              -> Path
"""

from __future__ import annotations

import io
import json
import os
import re
import tempfile
import zipfile
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

_DEFAULT_TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
_MAX_BYTES = 50 * 1024 * 1024  # 50 MB hard cap
_MAX_ZIP_MEMBERS = 16
_MAX_ZIP_UNCOMPRESSED = 128 * 1024 * 1024  # real list is ~23 MB; >= 4x headroom
_MAX_LINE_BYTES = 65536
_MAX_LINES = 2_000_000  # real list ~1M rows; counts EVERY line incl. blank ones
_MAX_DOMAIN_LEN = 253
_DOMAIN_RE = re.compile(r"^[a-z0-9._-]+$")


def user_allowlist_path() -> Path:
    """Return ``~/.barb/data/allowlist.json`` (user-override location)."""
    return Path.home() / ".barb" / "data" / "allowlist.json"


def fetch_tranco(source_url: str, timeout: float = 30.0) -> bytes:
    """Download *source_url* and return the raw bytes.

    Constraints
    -----------
    - Rejects any non-``https://`` URL immediately (no network call made).
    - Refuses responses larger than 50 MB.
    - Uses only stdlib ``urllib``; no third-party dependencies.

    Raises
    ------
    RuntimeError
        On HTTPS rejection, size cap exceeded, or any network / HTTP error.
    """
    if not source_url.startswith("https://"):
        raise RuntimeError(
            f"HTTPS required — rejected non-https source URL: {source_url!r}. "
            "barb only downloads data over an encrypted connection."
        )

    try:
        with urlopen(source_url, timeout=timeout) as resp:  # noqa: S310
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > _MAX_BYTES:
                    raise RuntimeError(
                        f"Download aborted: response exceeded the {_MAX_BYTES // (1024 * 1024)} MB size cap."
                    )
                chunks.append(chunk)
            return b"".join(chunks)
    except RuntimeError:
        raise
    except URLError as exc:
        raise RuntimeError(f"Network error fetching {source_url!r}: {exc}") from exc
    except Exception as exc:
        raise RuntimeError(f"Unexpected error fetching {source_url!r}: {exc}") from exc


def parse_tranco(raw: bytes, top_n: int) -> list[str]:
    """Parse Tranco list bytes into a deduplicated list of registrable domains.

    Accepts
    -------
    - A ZIP archive containing a CSV file (e.g. ``top-1m.csv.zip``).
    - A plain CSV with rows ``rank,domain`` (or just ``domain`` per line).

    Returns the first *top_n* unique, lowercased domains in rank order.
    Skips blank lines and a header row if present (``rank`` in first field).

    Never executes downloaded content — pure data parsing.
    """
    # Detect ZIP by magic bytes
    if raw[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            infos = zf.infolist()
            if len(infos) > _MAX_ZIP_MEMBERS:
                raise RuntimeError(f"Archive rejected: more than {_MAX_ZIP_MEMBERS} members.")
            if sum(i.file_size for i in infos) > _MAX_ZIP_UNCOMPRESSED:
                raise RuntimeError(
                    f"Archive rejected: uncompressed size exceeds {_MAX_ZIP_UNCOMPRESSED // (1024 * 1024)} MB."
                )
            # Pick the first .csv file; fall back to first member
            names = [i.filename for i in infos]
            if not names:
                raise RuntimeError("Archive rejected: no members.")
            csv_names = [n for n in names if n.lower().endswith(".csv")]
            member = csv_names[0] if csv_names else names[0]
            # Stream the member: a header can lie about its size, a deflate stream
            # can expand ~1000x, so never materialise the whole member in memory.
            with zf.open(member) as fh:
                return _collect_domains(_iter_zip_lines(fh), top_n)
    return _collect_domains(_iter_zip_lines(io.BytesIO(raw)), top_n)


def _iter_zip_lines(fh):
    """Yield decoded lines from a binary stream with bounded per-line memory and line count."""
    count = 0
    while True:
        chunk = fh.readline(_MAX_LINE_BYTES)
        if not chunk:
            return
        count += 1
        if count > _MAX_LINES:
            raise RuntimeError("Archive rejected: too many lines.")
        if len(chunk) >= _MAX_LINE_BYTES and not chunk.endswith(b"\n"):
            raise RuntimeError("Archive rejected: line too long.")
        yield from chunk.decode("utf-8", errors="replace").splitlines()


def _collect_domains(lines, top_n: int) -> list[str]:
    seen: set[str] = set()
    domains: list[str] = []

    for line in lines:
        line = line.strip()
        if not line:
            continue
        parts = line.split(",", 1)
        if len(parts) == 2:
            rank_field, domain_field = parts
            # Skip header row
            if rank_field.strip().lower() == "rank":
                continue
            domain = domain_field.strip().lower()
        else:
            # Plain domain-per-line format
            domain = parts[0].strip().lower()
            if domain.lower() == "domain":
                continue  # header

        if len(domain) > _MAX_DOMAIN_LEN or not _DOMAIN_RE.match(domain):
            continue  # not a hostname (oversized, binary, whitespace, ...)

        if domain and domain not in seen:
            seen.add(domain)
            domains.append(domain)
            if len(domains) >= top_n:
                break

    return domains


def _load_bundled_domains() -> list[str]:
    """Load the bundled curated allowlist entries."""
    bundled = Path(__file__).parent / "data" / "allowlist.json"
    try:
        with open(bundled) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def write_user_allowlist(domains: list[str]) -> Path:
    """Merge bundled curated entries with *domains* and write atomically.

    Write location: ``~/.barb/data/allowlist.json``

    Security
    --------
    - Directory created with mode ``0o700``.
    - File written with mode ``0o600`` (via tempfile + ``os.replace``).
    - Atomic: uses a temporary file in the same directory, then ``os.replace``.

    Returns the path of the written file.
    """
    dest = user_allowlist_path()
    dest_dir = dest.parent

    # Create ~/.barb/data/ with secure permissions
    dest_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

    # Merge: bundled curated entries are never lost
    bundled = _load_bundled_domains()
    merged: list[str] = list(dict.fromkeys([d.lower().strip() for d in bundled] + [d.lower().strip() for d in domains]))

    payload = json.dumps(merged, indent=2, ensure_ascii=False)

    # Atomic write: temp file in the same directory, then os.replace
    fd, tmp_path = tempfile.mkstemp(dir=dest_dir, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(payload)
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, dest)
    except Exception:
        # Clean up temp file on failure
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise

    return dest
