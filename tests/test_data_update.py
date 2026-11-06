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
                def __enter__(self):
                    return self

                def __exit__(self, *a):
                    pass

                def read(self, n):
                    return b""

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
                raise RuntimeError(f"HTTPS required — rejected non-https source URL: {url!r}.")
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


# ---------------------------------------------------------------------------
# parse_tranco — bounded zip parsing
# ---------------------------------------------------------------------------

_MIB = 1024 * 1024


def _zip_streamed(chunks, name: str = "top.csv") -> bytes:
    """Build a deflate ZIP whose single member is the concatenation of *chunks*."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        with zf.open(name, "w") as fh:
            for chunk in chunks:
                fh.write(chunk)
    return buf.getvalue()


def _repeat(block: bytes, total: int):
    """Yield *block* repeatedly until about *total* bytes were produced."""
    chunk = block * (_MIB // len(block))
    for _ in range(total // len(chunk)):
        yield chunk


class TestParseTrancoZipBounds:
    def test_rejects_zip_exceeding_uncompressed_cap(self, monkeypatch):
        import barb.data_update as du

        monkeypatch.setattr(du, "_MAX_ZIP_UNCOMPRESSED", 1_000_000)
        raw = _zip_streamed(_repeat(b"1,a.example\n", 5 * _MIB))
        assert len(raw) < 100_000  # a tiny archive that inflates to ~5 MB
        with pytest.raises(RuntimeError, match="uncompressed"):
            parse_tranco(raw, top_n=10)

    def test_rejects_too_many_members(self):
        import barb.data_update as du

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for i in range(du._MAX_ZIP_MEMBERS + 1):
                zf.writestr(f"m{i}.csv", "1,a.example\n")
        with pytest.raises(RuntimeError, match="members"):
            parse_tranco(buf.getvalue(), top_n=10)

    def test_header_that_lies_about_size_is_not_trusted(self):
        # Declare 100 bytes in the central directory while the member inflates to 5 MB.
        raw = bytearray(_zip_streamed(_repeat(b"1,a.example\n", 5 * _MIB)))
        cd = raw.rindex(b"PK\x01\x02")
        raw[cd + 24 : cd + 28] = (100).to_bytes(4, "little")
        with pytest.raises(zipfile.BadZipFile):
            parse_tranco(bytes(raw), top_n=10**9)

    def test_realistic_top1m_shape_is_accepted(self):
        rows = (f"{i},domain{i}.example.com\n".encode() for i in range(1, 1_000_001))
        raw = _zip_streamed([b"".join(rows)])
        result = parse_tranco(raw, top_n=1_000_000)
        assert len(result) == 1_000_000
        assert result[0] == "domain1.example.com"

    def test_memory_bounded_when_top_n_reached_early(self):
        import tracemalloc

        head = "".join(f"{i},d{i}.example\n" for i in range(2000)).encode()

        def chunks():
            yield head
            yield from _repeat(b"1,filler.example\n", 100 * _MIB)

        raw = _zip_streamed(chunks())
        tracemalloc.start()
        try:
            result = parse_tranco(raw, top_n=1000)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        assert len(result) == 1000
        assert peak < 32 * _MIB

    def test_top_n_never_reached_still_completes(self):
        # 1.5M duplicate rows: inside the line budget, top_n never reached.
        raw = _zip_streamed([b"1,dup.example\n" * 1_500_000])
        assert parse_tranco(raw, top_n=1000) == ["dup.example"]

    def test_member_without_newline_is_bounded(self):
        import tracemalloc

        raw = _zip_streamed(_repeat(b"x", 100 * _MIB))
        tracemalloc.start()
        try:
            with pytest.raises(RuntimeError, match="line too long"):
                parse_tranco(raw, top_n=10)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        assert peak < 8 * _MIB


class TestParseTrancoLineBudget:
    @pytest.mark.parametrize(
        "block",
        [b"\n", b"\r\n", b"1,a.com\n"],
        ids=["blank-lf", "blank-crlf", "short-valid-dupes"],
    )
    def test_zip_with_too_many_lines_is_rejected_fast(self, block):
        import time

        raw = _zip_streamed(_repeat(block, 127 * _MIB))
        t0 = time.monotonic()
        with pytest.raises(RuntimeError, match="too many lines"):
            parse_tranco(raw, top_n=1000)
        # Generous: shared CI runners are slow; the unfixed code needed 18-104 s and never raised.
        assert time.monotonic() - t0 < 30

    def test_raw_csv_with_too_many_lines_is_rejected_bounded(self):
        import time
        import tracemalloc

        raw = b"\n" * (50 * _MIB)
        tracemalloc.start()
        t0 = time.monotonic()
        try:
            with pytest.raises(RuntimeError, match="too many lines"):
                parse_tranco(raw, top_n=1000)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        assert time.monotonic() - t0 < 30
        assert peak < 16 * _MIB

    def test_raw_csv_long_line_is_rejected(self):
        with pytest.raises(RuntimeError, match="line too long"):
            parse_tranco(b"x" * 200_000, top_n=10)

    def test_empty_zip_is_rejected(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w"):
            pass
        with pytest.raises(RuntimeError, match="no members"):
            parse_tranco(buf.getvalue(), top_n=10)


class TestParseTrancoDomainValidation:
    def test_oversized_binary_and_junk_rows_are_skipped_punycode_kept(self):
        raw = b"\n".join(
            [
                b"1,good.example",
                b"2," + b"a" * 300 + b".com",
                b"3,\x00\xff\x80binary",
                b"4,has space.example",
                b"5,xn--80ak6aa92e.com",
                b"6,UPPER.Example",
                b"7,xn--mnchen-3ya.de",
            ]
        )
        assert parse_tranco(raw, top_n=10) == [
            "good.example",
            "xn--80ak6aa92e.com",
            "upper.example",
            "xn--mnchen-3ya.de",
        ]

    def test_bare_domain_format_is_validated_too(self):
        assert parse_tranco(b"ok.example\nbad/path\n", top_n=10) == ["ok.example"]

    @pytest.mark.parametrize(
        "junk",
        ["....", "-", "_", ".", "a..b", "com", "-a.com", "a-.com", "a_b.com", "a" * 64 + ".com", ".com", "a.-"],
    )
    def test_malformed_names_are_skipped(self, junk):
        assert parse_tranco(f"1,{junk}\n2,ok.example\n".encode(), top_n=10) == ["ok.example"]

    @pytest.mark.parametrize(
        "suffix",
        [
            "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "com.br",
            "net.br", "co.jp", "co.nz", "co.za", "com.cn", "com.mx", "co.in", "com.tr",
        ],
    )  # fmt: skip
    def test_public_suffixes_are_rejected_but_names_below_them_kept(self, suffix):
        assert parse_tranco(f"1,{suffix}\n2,example.{suffix}\n".encode(), top_n=10) == [f"example.{suffix}"]

    def test_single_trailing_dot_is_normalised(self):
        assert parse_tranco(b"1,example.com.\n", top_n=10) == ["example.com"]

    def test_total_length_over_253_is_skipped_even_with_valid_labels(self):
        long_name = ".".join(["a" * 60] * 5) + ".com"  # every label valid, 309 chars total
        assert parse_tranco(f"1,{long_name}\n2,ok.example\n".encode(), top_n=10) == ["ok.example"]


class TestLineBudgetCountsYieldedLines:
    def test_cr_only_chunks_are_counted_per_line(self):
        import time

        # Each 64 KiB chunk holds ~65k "lines" once splitlines() runs.
        raw = _zip_streamed(_repeat((b"\r" * 65534 + b"\n"), 20 * _MIB))
        t0 = time.monotonic()
        with pytest.raises(RuntimeError, match="too many lines"):
            parse_tranco(raw, top_n=1000)
        assert time.monotonic() - t0 < 30


class TestUpdateDataZeroDomains:
    def test_zero_valid_domains_keeps_existing_allowlist_and_exits_3(self, tmp_path, monkeypatch):
        import barb.data_update as du

        dest = tmp_path / ".barb" / "data" / "allowlist.json"
        dest.parent.mkdir(parents=True)
        dest.write_text('["keep.example"]')
        monkeypatch.setattr(du, "user_allowlist_path", lambda: dest)
        monkeypatch.setattr(du, "fetch_tranco", lambda url, timeout=30.0: b"1,bad domain\n2,/x\n")
        result = runner.invoke(app, ["update-data", "--source", "https://tranco-list.eu/x.csv"])
        assert result.exit_code == 3, result.output
        assert "no valid domains" in result.output
        assert dest.read_text() == '["keep.example"]'
        assert "written" not in result.output

    def _run(self, tmp_path, monkeypatch, payload: bytes, args=()):
        import barb.data_update as du

        dest = tmp_path / ".barb" / "data" / "allowlist.json"
        dest.parent.mkdir(parents=True)
        original = json.dumps([f"keep{i}.example" for i in range(5000)]).encode()
        dest.write_bytes(original)
        monkeypatch.setattr(du, "user_allowlist_path", lambda: dest)
        monkeypatch.setattr(du, "fetch_tranco", lambda url, timeout=30.0: payload)
        result = runner.invoke(app, ["update-data", "--source", "https://tranco-list.eu/x.csv", *args])
        return result, dest, original

    def test_junk_and_public_suffix_only_archive_keeps_5000_entry_allowlist(self, tmp_path, monkeypatch):
        result, dest, original = self._run(tmp_path, monkeypatch, b"1,....\n2,-\n3,co.uk\n4,com\n")
        assert result.exit_code == 3, result.output
        assert dest.read_bytes() == original

    def test_result_below_ten_percent_of_top_n_is_refused(self, tmp_path, monkeypatch):
        payload = "".join(f"{i},d{i}.example\n" for i in range(100)).encode()  # 100 < 10% of 5000
        result, dest, original = self._run(tmp_path, monkeypatch, payload)
        assert result.exit_code == 3, result.output
        assert "valid domains" in result.output
        assert dest.read_bytes() == original

    def test_result_at_ten_percent_is_accepted(self, tmp_path, monkeypatch):
        payload = "".join(f"{i},d{i}.example\n" for i in range(500)).encode()  # exactly 10%
        result, dest, original = self._run(tmp_path, monkeypatch, payload)
        assert result.exit_code == 0, result.output
        assert dest.read_bytes() != original
