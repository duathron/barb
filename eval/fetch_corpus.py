"""Opt-in corpus builder for the barb eval harness.

Downloads a real labeled corpus from public feeds and writes it to a local
gitignored CSV file.  This is a **dev tool** — it is never shipped in the
barb-phish package and is never called by CI.

WARNING: The output file contains LIVE phishing URLs stored as data strings.
Do NOT open or visit any URL from this file.  The file is written to
``eval/corpus/`` which is gitignored and will never be committed.

Usage:
    python -m eval.fetch_corpus
    python -m eval.fetch_corpus --out eval/corpus/real.csv --benign-n 500
    python -m eval.fetch_corpus --help
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path
from typing import Optional
from urllib.error import URLError
from urllib.request import urlopen

# Reuse barb's Tranco downloader and parser — no duplication.
from barb.data_update import _DEFAULT_TRANCO_URL, fetch_tranco, parse_tranco

_DEFAULT_PHISHING_URL = "https://openphish.com/feed.txt"
_MAX_BYTES = 50 * 1024 * 1024  # 50 MB hard cap (mirrors data_update)
_DEFAULT_OUT = Path(__file__).parent / "corpus" / "real.csv"


# ---------------------------------------------------------------------------
# Core functions (importable for tests)
# ---------------------------------------------------------------------------


def fetch_phishing(
    source_url: str = _DEFAULT_PHISHING_URL,
    timeout: float = 30.0,
) -> list[str]:
    """Download the phishing feed at *source_url* and return a list of URLs.

    Constraints
    -----------
    - Rejects any non-``https://`` URL immediately (no network call made).
    - Caps download at 50 MB.
    - Strips blank lines and lines beginning with ``#``.
    - Uses stdlib ``urllib`` only.

    Parameters
    ----------
    source_url:
        HTTPS URL of a plain-text phishing feed (one URL per line).
    timeout:
        Socket timeout in seconds.

    Returns
    -------
    list[str]
        Parsed phishing URLs (stripped, non-blank, non-comment).

    Raises
    ------
    RuntimeError
        On HTTPS rejection, size cap exceeded, or any network / HTTP error.
    """
    if not source_url.startswith("https://"):
        raise RuntimeError(
            f"HTTPS required — rejected non-https phishing source URL: {source_url!r}. "
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
                        f"Download aborted: response exceeded the "
                        f"{_MAX_BYTES // (1024 * 1024)} MB size cap."
                    )
                chunks.append(chunk)
            raw = b"".join(chunks)
    except RuntimeError:
        raise
    except URLError as exc:
        raise RuntimeError(
            f"Network error fetching phishing feed {source_url!r}: {exc}"
        ) from exc
    except Exception as exc:
        raise RuntimeError(
            f"Unexpected error fetching phishing feed {source_url!r}: {exc}"
        ) from exc

    text = raw.decode("utf-8", errors="replace")
    urls: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            urls.append(line)
    return urls


def build_benign(
    top_n: int,
    tranco_url: Optional[str] = None,
    timeout: float = 30.0,
) -> list[str]:
    """Return the top *top_n* Tranco domains as ``https://<domain>/`` URLs.

    Delegates to ``barb.data_update.fetch_tranco`` and ``parse_tranco`` so
    the HTTPS enforcement and size cap are inherited automatically.

    Parameters
    ----------
    top_n:
        Number of domains to return.
    tranco_url:
        Override the default Tranco ZIP URL.  Must be ``https://``.
    timeout:
        Socket timeout in seconds (forwarded to ``fetch_tranco``).

    Returns
    -------
    list[str]
        URLs of the form ``https://<domain>/``.

    Raises
    ------
    RuntimeError
        Propagated from ``fetch_tranco`` on network / HTTPS / size errors.
    """
    url = tranco_url if tranco_url is not None else _DEFAULT_TRANCO_URL
    raw = fetch_tranco(url, timeout=timeout)
    domains = parse_tranco(raw, top_n=top_n)
    return [f"https://{domain}/" for domain in domains]


def write_corpus(
    phishing_urls: list[str],
    benign_urls: list[str],
    out_path: Path,
) -> Path:
    """Write a labeled CSV corpus to *out_path*.

    The CSV has a header row ``url,label``.  Phishing rows carry label
    ``phishing``; benign rows carry label ``benign``.  Duplicate URLs are
    removed (first occurrence wins, preserving order).

    Parameters
    ----------
    phishing_urls:
        List of phishing URL strings.
    benign_urls:
        List of benign URL strings.
    out_path:
        Destination path (parent directories are created as needed).

    Returns
    -------
    Path
        The resolved path of the written file.
    """
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    seen: set[str] = set()
    rows: list[tuple[str, str]] = []
    for url in phishing_urls:
        url = url.strip()
        if url and url not in seen:
            seen.add(url)
            rows.append((url, "phishing"))
    for url in benign_urls:
        url = url.strip()
        if url and url not in seen:
            seen.add(url)
            rows.append((url, "benign"))

    with open(out_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["url", "label"])
        writer.writerows(rows)

    return out_path.resolve()


def build_corpus(
    out_path: Path = _DEFAULT_OUT,
    benign_n: int = 500,
    phishing_url: str = _DEFAULT_PHISHING_URL,
    tranco_url: Optional[str] = None,
    timeout: float = 30.0,
) -> Path:
    """Orchestrate fetch_phishing + build_benign + write_corpus.

    Prints a summary of the counts per label and the output path.

    WARNING: The output file contains LIVE phishing URLs stored as data
    strings.  Do NOT open or visit any URL from this file.  The file is
    written to a gitignored location and will never be committed.

    Parameters
    ----------
    out_path:
        Destination CSV path (default: ``eval/corpus/real.csv``).
    benign_n:
        Number of Tranco top domains to use as benign examples.
    phishing_url:
        HTTPS URL of the phishing feed (default: OpenPhish community feed).
    tranco_url:
        Override the default Tranco ZIP URL (optional).
    timeout:
        Network timeout in seconds for both fetches.

    Returns
    -------
    Path
        Resolved path of the written corpus CSV.
    """
    print(f"Fetching phishing feed: {phishing_url}")
    phishing_urls = fetch_phishing(phishing_url, timeout=timeout)
    print(f"  -> {len(phishing_urls)} phishing URLs fetched")

    print(f"Fetching Tranco top-{benign_n} domains for benign baseline...")
    benign_urls = build_benign(benign_n, tranco_url=tranco_url, timeout=timeout)
    print(f"  -> {len(benign_urls)} benign URLs built")

    written = write_corpus(phishing_urls, benign_urls, out_path)
    total = len(phishing_urls) + len(benign_urls)
    print()
    print(f"Corpus written: {written}")
    print(f"  phishing : {len(phishing_urls)}")
    print(f"  benign   : {len(benign_urls)}")
    print(f"  total    : {total}")
    print()
    print(
        "NOTE: This file contains LIVE phishing URLs stored as data strings. "
        "Do NOT open or visit any URL from this file. "
        "The file is gitignored and will never be committed to the repository."
    )
    return written


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="eval.fetch_corpus",
        description=(
            "Opt-in corpus builder for the barb eval harness. "
            "Downloads a real labeled phishing+benign CSV to a local gitignored path. "
            "WARNING: output contains LIVE phishing URLs as data — do not visit them."
        ),
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=_DEFAULT_OUT,
        metavar="PATH",
        help=f"Output CSV path (default: {_DEFAULT_OUT}).",
    )
    parser.add_argument(
        "--benign-n",
        dest="benign_n",
        type=int,
        default=500,
        metavar="N",
        help="Number of Tranco top domains to use as benign examples (default: 500).",
    )
    parser.add_argument(
        "--phishing-source",
        dest="phishing_source",
        default=_DEFAULT_PHISHING_URL,
        metavar="URL",
        help=(
            f"HTTPS URL of the phishing feed (default: {_DEFAULT_PHISHING_URL}). "
            "Must be https://."
        ),
    )
    parser.add_argument(
        "--tranco-source",
        dest="tranco_source",
        default=None,
        metavar="URL",
        help=(
            "Override the Tranco ZIP URL (default: barb.data_update default). "
            "Must be https://."
        ),
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        metavar="SECONDS",
        help="Network timeout in seconds for both fetches (default: 30).",
    )
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> None:
    """CLI entry point."""
    args = _parse_args(argv)

    # Validate HTTPS for user-supplied sources before making any network call.
    if not args.phishing_source.startswith("https://"):
        print(
            f"ERROR: --phishing-source must be an https:// URL, got: {args.phishing_source!r}",
            file=sys.stderr,
        )
        sys.exit(1)
    if args.tranco_source is not None and not args.tranco_source.startswith("https://"):
        print(
            f"ERROR: --tranco-source must be an https:// URL, got: {args.tranco_source!r}",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        build_corpus(
            out_path=args.out,
            benign_n=args.benign_n,
            phishing_url=args.phishing_source,
            tranco_url=args.tranco_source,
            timeout=args.timeout,
        )
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
