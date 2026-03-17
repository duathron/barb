"""Shared helpers for analyzers."""

from __future__ import annotations

import json
from pathlib import Path

_DATA_DIR = Path(__file__).parent.parent / "data"


def load_data(filename: str) -> dict | list:
    """Load a bundled JSON data file."""
    path = _DATA_DIR / filename
    with open(path) as f:
        return json.load(f)
