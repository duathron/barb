"""Tests for allowlist staleness warning (B2).

TDD: write tests BEFORE implementation.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from barb.allowlist_staleness import (
    check_allowlist_staleness,
    get_effective_allowlist_age_days,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_json(path: Path, data: list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))


# ---------------------------------------------------------------------------
# get_effective_allowlist_age_days
# ---------------------------------------------------------------------------


def test_age_uses_user_override_when_present(tmp_path, monkeypatch):
    """When user override exists, its mtime is used — not the bundled file."""
    override = tmp_path / "allowlist.json"
    _write_json(override, ["example.com"])
    # Set mtime to 100 days ago
    old_mtime = time.time() - 100 * 86400
    import os

    os.utime(override, (old_mtime, old_mtime))

    monkeypatch.setattr("barb.allowlist_staleness._USER_OVERRIDE", override)

    age = get_effective_allowlist_age_days()
    assert 99 <= age <= 101


def test_age_falls_back_to_bundled_when_no_override(monkeypatch):
    """When user override is absent, the bundled file mtime is used."""
    # Point user override at a non-existent path
    monkeypatch.setattr(
        "barb.allowlist_staleness._USER_OVERRIDE",
        Path("/nonexistent/allowlist_missing.json"),
    )
    # Bundled file always exists in the package — age should be a small positive number
    age = get_effective_allowlist_age_days()
    assert age >= 0


def test_age_user_override_unreadable_falls_back_to_bundled(tmp_path, monkeypatch):
    """If user override file has an OS error, fall back to bundled gracefully."""
    # Create a directory at the override path (unreadable as a file)
    override = tmp_path / "bad_allowlist"
    override.mkdir()
    monkeypatch.setattr("barb.allowlist_staleness._USER_OVERRIDE", override)

    # Should not raise; falls back to bundled
    age = get_effective_allowlist_age_days()
    assert age >= 0


# ---------------------------------------------------------------------------
# check_allowlist_staleness
# ---------------------------------------------------------------------------


def test_stale_prints_warning_to_stderr(tmp_path, monkeypatch, capsys):
    """Stale allowlist (> threshold days) prints a one-line hint to stderr."""
    override = tmp_path / "allowlist.json"
    _write_json(override, ["example.com"])
    # 200 days old — well past the 90-day default
    old_mtime = time.time() - 200 * 86400
    import os

    os.utime(override, (old_mtime, old_mtime))

    monkeypatch.setattr("barb.allowlist_staleness._USER_OVERRIDE", override)

    check_allowlist_staleness(max_age_days=90, enabled=True)

    captured = capsys.readouterr()
    assert "allowlist" in captured.err.lower()
    assert "barb update-data" in captured.err


def test_stale_warning_goes_to_stderr_not_stdout(tmp_path, monkeypatch, capsys):
    """Warning must appear on stderr, not stdout (keeps machine output clean)."""
    override = tmp_path / "allowlist.json"
    _write_json(override, ["example.com"])
    old_mtime = time.time() - 200 * 86400
    import os

    os.utime(override, (old_mtime, old_mtime))

    monkeypatch.setattr("barb.allowlist_staleness._USER_OVERRIDE", override)

    check_allowlist_staleness(max_age_days=90, enabled=True)

    captured = capsys.readouterr()
    assert captured.out == ""  # nothing to stdout
    assert "barb update-data" in captured.err


def test_fresh_allowlist_prints_nothing(tmp_path, monkeypatch, capsys):
    """Fresh allowlist (< threshold days) must produce no output."""
    override = tmp_path / "allowlist.json"
    _write_json(override, ["example.com"])
    # Only 5 days old
    recent_mtime = time.time() - 5 * 86400
    import os

    os.utime(override, (recent_mtime, recent_mtime))

    monkeypatch.setattr("barb.allowlist_staleness._USER_OVERRIDE", override)

    check_allowlist_staleness(max_age_days=90, enabled=True)

    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out == ""


def test_opt_out_suppresses_warning_even_when_stale(tmp_path, monkeypatch, capsys):
    """When enabled=False the check is a no-op regardless of age."""
    override = tmp_path / "allowlist.json"
    _write_json(override, ["example.com"])
    old_mtime = time.time() - 365 * 86400  # a year old
    import os

    os.utime(override, (old_mtime, old_mtime))

    monkeypatch.setattr("barb.allowlist_staleness._USER_OVERRIDE", override)

    check_allowlist_staleness(max_age_days=90, enabled=False)

    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out == ""


def test_warning_reports_age_in_days(tmp_path, monkeypatch, capsys):
    """Warning message must include the approximate age in days."""
    override = tmp_path / "allowlist.json"
    _write_json(override, ["example.com"])
    old_mtime = time.time() - 150 * 86400
    import os

    os.utime(override, (old_mtime, old_mtime))

    monkeypatch.setattr("barb.allowlist_staleness._USER_OVERRIDE", override)

    check_allowlist_staleness(max_age_days=90, enabled=True)

    captured = capsys.readouterr()
    # Message must contain the numeric age
    assert "150" in captured.err or "149" in captured.err or "151" in captured.err


def test_missing_override_uses_bundled_no_crash(monkeypatch, capsys):
    """Missing user override must not raise; falls back to bundled file silently."""
    monkeypatch.setattr(
        "barb.allowlist_staleness._USER_OVERRIDE",
        Path("/nonexistent/missing_override.json"),
    )
    # Must not raise regardless of bundled file age
    check_allowlist_staleness(max_age_days=90, enabled=True)
    # No assertion on output — bundled file may or may not be stale


def test_check_never_raises_on_exception(monkeypatch, capsys):
    """check_allowlist_staleness is fail-open — never raises."""
    # Point both files at invalid paths to provoke any potential errors
    monkeypatch.setattr(
        "barb.allowlist_staleness._USER_OVERRIDE",
        Path("/does/not/exist/a.json"),
    )
    monkeypatch.setattr(
        "barb.allowlist_staleness._BUNDLED_DATA_FILE",
        Path("/does/not/exist/b.json"),
    )
    # Must not raise
    check_allowlist_staleness(max_age_days=90, enabled=True)
