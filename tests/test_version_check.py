"""Tests for version check module."""

from __future__ import annotations

from barb.version_check import _parse_version


def test_parse_version_simple():
    assert _parse_version("1.0.0") == (1, 0, 0)


def test_parse_version_with_v_prefix():
    assert _parse_version("v1.2.3") == (1, 2, 3)


def test_parse_version_comparison():
    assert _parse_version("1.1.0") > _parse_version("1.0.0")
    assert _parse_version("2.0.0") > _parse_version("1.9.9")
    assert _parse_version("1.0.0") == _parse_version("v1.0.0")


def test_parse_version_invalid():
    assert _parse_version("invalid") == (0,)
    assert _parse_version("") == (0,)
