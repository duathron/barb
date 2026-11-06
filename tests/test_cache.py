"""Tests for the SQLite OSINT result cache."""

from __future__ import annotations

import os
import sqlite3
import stat
import time
from unittest.mock import MagicMock, patch

import pytest

from barb.cache import OsintCache
from barb.models import Signal, SignalSeverity


def _sig(label: str = "test", sev: SignalSeverity = SignalSeverity.HIGH) -> Signal:
    return Signal(analyzer="osint:dns", severity=sev, label=label, detail="d")


@pytest.fixture
def cache(tmp_path):
    c = OsintCache(db_path=tmp_path / "cache.db")
    yield c
    c.close()


# ---------------------------------------------------------------------------
# Round-trip
# ---------------------------------------------------------------------------


def test_set_then_get_returns_signals(cache):
    signals = [_sig("a"), _sig("b", SignalSeverity.MEDIUM)]
    cache.set("evil.com", signals)
    result = cache.get("evil.com", ttl_seconds=3600)
    assert result is not None
    assert [s.label for s in result] == ["a", "b"]
    assert result[1].severity == SignalSeverity.MEDIUM


def test_get_miss_returns_none(cache):
    assert cache.get("never-seen.com", ttl_seconds=3600) is None


def test_cached_empty_list_is_a_hit_not_a_miss(cache):
    cache.set("clean.com", [])
    result = cache.get("clean.com", ttl_seconds=3600)
    assert result == []  # hit with no signals, distinct from None (miss)


def test_host_lookup_is_case_insensitive(cache):
    cache.set("Evil.COM", [_sig("x")])
    assert cache.get("evil.com", ttl_seconds=3600) is not None


# ---------------------------------------------------------------------------
# TTL / expiry
# ---------------------------------------------------------------------------


def test_expired_entry_returns_none(cache):
    cache.set("evil.com", [_sig()])
    # ttl of 0 → any positive age is expired
    assert cache.get("evil.com", ttl_seconds=0) is None


def test_fresh_within_ttl(cache):
    cache.set("evil.com", [_sig()])
    assert cache.get("evil.com", ttl_seconds=10_000) is not None


def test_old_timestamp_expires(cache, tmp_path):
    cache.set("evil.com", [_sig()])
    # Backdate the row well beyond the TTL.
    conn = sqlite3.connect(str(tmp_path / "cache.db"))
    conn.execute("UPDATE osint_cache SET cached_at = ?", (time.time() - 99_999,))
    conn.commit()
    conn.close()
    assert cache.get("evil.com", ttl_seconds=3600) is None


# ---------------------------------------------------------------------------
# Overwrite / clear
# ---------------------------------------------------------------------------


def test_set_overwrites_existing(cache):
    cache.set("evil.com", [_sig("old")])
    cache.set("evil.com", [_sig("new")])
    result = cache.get("evil.com", ttl_seconds=3600)
    assert [s.label for s in result] == ["new"]


def test_clear_empties_cache(cache):
    cache.set("a.com", [_sig()])
    cache.set("b.com", [_sig()])
    cache.clear()
    assert cache.get("a.com", ttl_seconds=3600) is None
    assert cache.get("b.com", ttl_seconds=3600) is None


# ---------------------------------------------------------------------------
# Fail-open behavior
# ---------------------------------------------------------------------------


def test_corrupt_row_returns_none(cache, tmp_path):
    conn = sqlite3.connect(str(tmp_path / "cache.db"))
    conn.execute(
        "INSERT INTO osint_cache (host, signals_json, cached_at) VALUES (?, ?, ?)",
        ("bad.com", "{not valid json", time.time()),
    )
    conn.commit()
    conn.close()
    assert cache.get("bad.com", ttl_seconds=3600) is None


def test_disabled_cache_is_safe(tmp_path):
    c = OsintCache(db_path=tmp_path / "cache.db")
    c._conn = None  # simulate a connection that failed to open
    assert c.get("evil.com", ttl_seconds=3600) is None
    c.set("evil.com", [_sig()])  # must not raise
    c.clear()  # must not raise


# ---------------------------------------------------------------------------
# Security: file permissions
# ---------------------------------------------------------------------------


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions only")
def test_db_file_permissions_are_0600(tmp_path):
    db = tmp_path / "cache.db"
    c = OsintCache(db_path=db)
    c.set("evil.com", [_sig()])
    mode = stat.S_IMODE(db.stat().st_mode)
    assert mode == 0o600
    c.close()


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions only")
def test_wal_and_shm_sidecars_are_0600(tmp_path):
    old = os.umask(0o022)
    try:
        cache_dir = tmp_path / "sub"
        c = OsintCache(db_path=cache_dir / "cache.db")
        c.set("evil.com", [_sig()])
        names = sorted(p.name for p in cache_dir.iterdir())
        assert "cache.db-wal" in names and "cache.db-shm" in names
        for entry in cache_dir.iterdir():
            assert stat.S_IMODE(entry.stat().st_mode) == 0o600, entry.name
        assert stat.S_IMODE(cache_dir.stat().st_mode) == 0o700
        c.close()
    finally:
        os.umask(old)


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions only")
def test_stale_world_readable_sidecars_are_tightened(tmp_path):
    """A 0644 -wal/-shm left behind by an older barb is tightened on open."""
    old = os.umask(0o022)
    try:
        db = tmp_path / "cache.db"
        for suffix in ("-wal", "-shm"):
            stale = tmp_path / f"cache.db{suffix}"
            stale.write_bytes(b"\x00" * 32768)  # invalid/stale content, reused in place
            stale.chmod(0o644)
        c = OsintCache(db_path=db)
        c.set("evil.com", [_sig()])
        for suffix in ("-wal", "-shm"):
            mode = stat.S_IMODE((tmp_path / f"cache.db{suffix}").stat().st_mode)
            assert mode == 0o600, suffix
        c.close()
    finally:
        os.umask(old)


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions only")
def test_cache_never_world_readable_at_creation(tmp_path, monkeypatch):
    """The db file must already be 0600 when sqlite3.connect first sees it."""
    old = os.umask(0o022)
    db = tmp_path / "cache.db"
    seen: list = []
    real_connect = sqlite3.connect

    def spy(database, *args, **kwargs):
        try:
            seen.append(stat.S_IMODE(os.stat(database).st_mode))
        except FileNotFoundError:
            seen.append(None)
        return real_connect(database, *args, **kwargs)

    monkeypatch.setattr("barb.cache.sqlite3.connect", spy)
    try:
        c = OsintCache(db_path=db)
        c.close()
    finally:
        os.umask(old)
    assert seen == [0o600]


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions only")
def test_cache_refuses_symlink_db(tmp_path):
    target = tmp_path / "victim.txt"
    target.write_bytes(b"")  # empty file: sqlite would happily initialise it
    target.chmod(0o644)
    link = tmp_path / "cache.db"
    link.symlink_to(target)
    c = OsintCache(db_path=link)
    c.set("evil.com", [_sig()])
    assert c.get("evil.com", ttl_seconds=60) is None
    c.close()
    assert target.read_bytes() == b""
    assert stat.S_IMODE(target.stat().st_mode) == 0o644


# ---------------------------------------------------------------------------
# Integration: _run_enrichers uses the cache
# ---------------------------------------------------------------------------


def test_run_enrichers_caches_and_skips_second_network_call(tmp_path):
    from barb.config import AppConfig
    from barb.url_parser import parse_url

    shared = OsintCache(db_path=tmp_path / "cache.db")
    parsed = parse_url("https://evil.com/login")
    config = AppConfig()

    dns_instance = MagicMock()
    dns_instance.enrich.return_value = [_sig("dns-hit")]
    rdap_instance = MagicMock()
    rdap_instance.enrich.return_value = []
    crtsh_instance = MagicMock()
    crtsh_instance.enrich.return_value = []
    asn_instance = MagicMock()
    asn_instance.enrich.return_value = []

    with (
        patch("barb.cache.get_cache", return_value=shared),
        patch("barb.enrichers.dns.DNSEnricher", return_value=dns_instance),
        patch("barb.enrichers.rdap.RDAPEnricher", return_value=rdap_instance),
        patch("barb.enrichers.crtsh.CrtShEnricher", return_value=crtsh_instance),
        patch("barb.enrichers.asn.ASNEnricher", return_value=asn_instance),
    ):
        from barb.main import _run_enrichers

        first = _run_enrichers(parsed, config, use_cache=True)
        second = _run_enrichers(parsed, config, use_cache=True)

    assert [s.label for s in first] == ["dns-hit"]
    assert [s.label for s in second] == ["dns-hit"]
    # Second call served from cache → enrichers invoked only once.
    assert dns_instance.enrich.call_count == 1
    shared.close()


def test_run_enrichers_no_cache_always_queries(tmp_path):
    from barb.config import AppConfig
    from barb.url_parser import parse_url

    shared = OsintCache(db_path=tmp_path / "cache.db")
    parsed = parse_url("https://evil.com/login")
    config = AppConfig()

    dns_instance = MagicMock()
    dns_instance.enrich.return_value = [_sig("dns-hit")]
    rdap_instance = MagicMock()
    rdap_instance.enrich.return_value = []
    crtsh_instance = MagicMock()
    crtsh_instance.enrich.return_value = []
    asn_instance = MagicMock()
    asn_instance.enrich.return_value = []

    with (
        patch("barb.cache.get_cache", return_value=shared),
        patch("barb.enrichers.dns.DNSEnricher", return_value=dns_instance),
        patch("barb.enrichers.rdap.RDAPEnricher", return_value=rdap_instance),
        patch("barb.enrichers.crtsh.CrtShEnricher", return_value=crtsh_instance),
        patch("barb.enrichers.asn.ASNEnricher", return_value=asn_instance),
    ):
        from barb.main import _run_enrichers

        _run_enrichers(parsed, config, use_cache=False)
        _run_enrichers(parsed, config, use_cache=False)

    # use_cache=False → both calls hit the enrichers.
    assert dns_instance.enrich.call_count == 2
    shared.close()
