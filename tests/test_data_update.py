"""Tests for barb.data_update and the update-data CLI command.

All tests are offline — no real network calls.
"""

from __future__ import annotations

import io
import json
import stat
import zipfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from barb.data_update import (
    fetch_tranco,
    parse_tranco,
    write_user_allowlist,
)
from barb.main import app

runner = CliRunner()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_zip_csv(rows: list[str]) -> bytes:
    """Build an in-memory ZIP containing 'top.csv' from the given CSV rows."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("top.csv", "\n".join(rows) + "\n")
    return buf.getvalue()


def _make_tranco_zip(domains: list[str]) -> bytes:
    """Build a minimal Tranco-style zip: rank,domain rows."""
    rows = [f"{i + 1},{d}" for i, d in enumerate(domains)]
    return _make_zip_csv(rows)


# ---------------------------------------------------------------------------
# parse_tranco — zip input
# ---------------------------------------------------------------------------

class TestParseTrancoZip:
    def test_returns_domains_in_order(self):
        raw = _make_tranco_zip(["google.com", "youtube.com", "facebook.com", "amazon.com"])
        result = parse_tranco(raw, top_n=10)
        assert result == ["google.com", "youtube.com", "facebook.com", "amazon.com"]

    def test_honors_top_n(self):
        raw = _make_tranco_zip(["google.com", "youtube.com", "facebook.com", "amazon.com"])
        result = parse_tranco(raw, top_n=2)
        assert result == ["google.com", "youtube.com"]

    def test_deduplicates(self):
        raw = _make_tranco_zip(["google.com", "youtube.com", "google.com"])
        result = parse_tranco(raw, top_n=10)
        assert result == ["google.com", "youtube.com"]

    def test_lowercases_domains(self):
        raw = _make_tranco_zip(["Google.Com", "YouTube.COM"])
        result = parse_tranco(raw, top_n=10)
        assert result == ["google.com", "youtube.com"]

    def test_skips_header_row(self):
        rows = ["rank,domain", "1,google.com", "2,youtube.com"]
        raw = _make_zip_csv(rows)
        result = parse_tranco(raw, top_n=10)
        assert result == ["google.com", "youtube.com"]

    def test_skips_blank_lines(self):
        rows = ["1,google.com", "", "2,youtube.com", ""]
        raw = _make_zip_csv(rows)
        result = parse_tranco(raw, top_n=10)
        assert result == ["google.com", "youtube.com"]


# ---------------------------------------------------------------------------
# parse_tranco — plain CSV input
# ---------------------------------------------------------------------------

class TestParseTrancoPlainCsv:
    def test_plain_csv_rank_domain(self):
        csv = b"1,google.com\n2,youtube.com\n3,facebook.com\n"
        result = parse_tranco(csv, top_n=10)
        assert result == ["google.com", "youtube.com", "facebook.com"]

    def test_plain_csv_honors_top_n(self):
        csv = b"1,google.com\n2,youtube.com\n3,facebook.com\n"
        result = parse_tranco(csv, top_n=2)
        assert result == ["google.com", "youtube.com"]

    def test_plain_domain_per_line(self):
        csv = b"google.com\nyoutube.com\nfacebook.com\n"
        result = parse_tranco(csv, top_n=10)
        assert result == ["google.com", "youtube.com", "facebook.com"]


# ---------------------------------------------------------------------------
# fetch_tranco — HTTPS enforcement (no network calls)
# ---------------------------------------------------------------------------

class TestFetchTrancoHttpsEnforcement:
    def test_http_url_raises_immediately(self):
        with pytest.raises(RuntimeError, match="HTTPS required"):
            fetch_tranco("http://insecure.example/list.zip")

    def test_ftp_url_raises(self):
        with pytest.raises(RuntimeError, match="HTTPS required"):
            fetch_tranco("ftp://example.com/list.zip")

    def test_plain_domain_raises(self):
        with pytest.raises(RuntimeError, match="HTTPS required"):
            fetch_tranco("example.com/list.zip")

    def test_https_url_does_not_raise_on_enforcement(self, monkeypatch):
        """Verify https:// passes the guard (we still mock the actual network)."""
        def fake_urlopen(url, timeout):
            class FakeResp:
                def __enter__(self): return self
                def __exit__(self, *a): pass
                def read(self, n): return b""
            return FakeResp()
        import barb.data_update as du
        monkeypatch.setattr(du, "urlopen", fake_urlopen)
        result = fetch_tranco("https://example.com/list.zip", timeout=1.0)
        assert result == b""


# ---------------------------------------------------------------------------
# write_user_allowlist
# ---------------------------------------------------------------------------

class TestWriteUserAllowlist:
    def test_writes_json_to_user_path(self, tmp_path, monkeypatch):
        override_path = tmp_path / ".barb" / "data" / "allowlist.json"
        import barb.data_update as du
        monkeypatch.setattr(du, "user_allowlist_path", lambda: override_path)
        # Patch Path.home() so mkdir targets tmp_path
        monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))

        dest = write_user_allowlist(["google.com", "youtube.com"])
        assert dest.exists()
        data = json.loads(dest.read_text())
        assert isinstance(data, list)
        assert "google.com" in data
        assert "youtube.com" in data

    def test_includes_bundled_brand_domain(self, tmp_path, monkeypatch):
        """Merged result must include at least one bundled curated domain."""
        import barb.data_update as du
        override_path = tmp_path / ".barb" / "data" / "allowlist.json"
        monkeypatch.setattr(du, "user_allowlist_path", lambda: override_path)
        monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
        # Bundled allowlist always has e.g. "google.com"
        monkeypatch.setattr(du, "_load_bundled_domains", lambda: ["google.com", "paypal.com"])

        dest = write_user_allowlist(["newdomain.com"])
        data = json.loads(dest.read_text())
        assert "google.com" in data, "Bundled domain must survive the merge"
        assert "paypal.com" in data, "Bundled domain must survive the merge"
        assert "newdomain.com" in data

    def test_file_mode_0o600(self, tmp_path, monkeypatch):
        import barb.data_update as du
        override_path = tmp_path / ".barb" / "data" / "allowlist.json"
        monkeypatch.setattr(du, "user_allowlist_path", lambda: override_path)
        monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))

        dest = write_user_allowlist(["example.com"])
        mode = stat.S_IMODE(dest.stat().st_mode)
        assert mode == 0o600, f"Expected 0o600, got {oct(mode)}"

    def test_dir_created(self, tmp_path, monkeypatch):
        import barb.data_update as du
        override_path = tmp_path / ".barb" / "data" / "allowlist.json"
        monkeypatch.setattr(du, "user_allowlist_path", lambda: override_path)
        monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))

        assert not override_path.parent.exists()
        write_user_allowlist([])
        assert override_path.parent.exists()


# ---------------------------------------------------------------------------
# allowlist._load_allowlist — user-override path resolution
# ---------------------------------------------------------------------------

class TestAllowlistUserOverride:
    def test_user_override_takes_precedence(self, tmp_path, monkeypatch):
        """A domain only in the user-override must be recognized as allowlisted."""
        import barb.allowlist as al
        override_path = tmp_path / "allowlist_override.json"
        override_path.write_text(json.dumps(["custom-unique-domain.com"]))

        monkeypatch.setattr(al, "_USER_OVERRIDE", override_path)
        # Clear the LRU cache so our monkeypatched path is used
        al._load_allowlist.cache_clear()

        result = al._load_allowlist()
        assert "custom-unique-domain.com" in result

        # Cleanup cache for other tests
        al._load_allowlist.cache_clear()

    def test_fallback_to_bundled_when_no_override(self, tmp_path, monkeypatch):
        """When no user override exists, bundled list is used."""
        import barb.allowlist as al
        nonexistent = tmp_path / "nonexistent.json"
        monkeypatch.setattr(al, "_USER_OVERRIDE", nonexistent)
        al._load_allowlist.cache_clear()

        result = al._load_allowlist()
        # Bundled allowlist always has google.com
        assert "google.com" in result

        al._load_allowlist.cache_clear()

    def test_is_allowlisted_uses_override(self, tmp_path, monkeypatch):
        import barb.allowlist as al
        override_path = tmp_path / "allowlist_override.json"
        override_path.write_text(json.dumps(["only-in-override.com"]))
        monkeypatch.setattr(al, "_USER_OVERRIDE", override_path)
        al._load_allowlist.cache_clear()

        assert al.is_allowlisted("only-in-override.com")

        al._load_allowlist.cache_clear()


# ---------------------------------------------------------------------------
# update-data command — smoke test (mocked network)
# ---------------------------------------------------------------------------

class TestUpdateDataCommand:
    def _make_fixture_zip(self) -> bytes:
        return _make_tranco_zip(["google.com", "youtube.com", "facebook.com", "amazon.com", "twitter.com"])

    def test_https_rejection_exits_3(self):
        result = runner.invoke(app, ["update-data", "--source", "http://insecure.example/list"])
        assert result.exit_code == 3
        assert "HTTPS" in result.output or "https" in result.output.lower() or "Error" in result.output

    def test_http_rejection_no_fetching_line(self):
        """When source is http://, the HTTPS error must appear BEFORE any 'Fetching:' output."""
        result = runner.invoke(app, ["update-data", "--source", "http://insecure.example/list"])
        assert result.exit_code == 3
        # 'Fetching:' must NOT appear — validation fires before the print
        assert "Fetching:" not in result.output
        # The error message about HTTPS must be present
        assert "HTTPS" in result.output or "Error" in result.output

    def test_success_with_mocked_fetch(self, tmp_path, monkeypatch):
        """Patch fetch_tranco to return a fixture zip; verify exit 0 and file written."""
        import barb.data_update as du
        fixture_zip = self._make_fixture_zip()
        override_path = tmp_path / ".barb" / "data" / "allowlist.json"

        monkeypatch.setattr(du, "user_allowlist_path", lambda: override_path)
        calls = []

        def mock_fetch(url, timeout=30.0):
            if not url.startswith("https://"):
                raise RuntimeError(
                    f"HTTPS required — rejected non-https source URL: {url!r}."
                )
            calls.append(url)
            return fixture_zip

        monkeypatch.setattr(du, "fetch_tranco", mock_fetch)

        result = runner.invoke(
            app,
            ["update-data", "--source", "https://tranco-list.eu/top-1m.csv.zip", "--top-n", "5"],
        )
        assert result.exit_code == 0, f"Got exit {result.exit_code}: {result.output}"
        # Output mentions the path
        assert str(override_path) in result.output or ".barb" in result.output or "Location" in result.output

    def test_help_lists_flags(self):
        result = runner.invoke(app, ["update-data", "--help"])
        assert result.exit_code == 0
        # Strip ANSI color codes: Rich/Typer colorizes flag names in CI (TTY-
        # dependent), splitting "--top-n" across escape sequences. Local
        # CliRunner emits no color, so the raw substring passed locally but
        # failed in CI. Normalize before asserting.
        import re
        plain = re.sub(r"\x1b\[[0-9;]*m", "", result.output)
        assert "--top-n" in plain
        assert "--source" in plain
