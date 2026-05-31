"""Tests for URL parser."""

from __future__ import annotations

import pytest

from barb.url_parser import parse_url


def test_parse_simple_url():
    result = parse_url("https://www.example.com/path?q=1")
    assert result.scheme == "https"
    assert result.host == "www.example.com"
    assert result.path == "/path"
    assert result.query == "q=1"
    assert not result.is_ip


def test_parse_ip_url():
    result = parse_url("http://192.168.1.1/login")
    assert result.is_ip
    assert result.host == "192.168.1.1"


def test_parse_punycode_url():
    result = parse_url("http://xn--pypal-4ve.com")
    assert result.is_punycode


def test_url_length_cap():
    with pytest.raises(ValueError, match="exceeds maximum length"):
        parse_url("http://example.com/" + "a" * 2100)


def test_parse_url_without_scheme():
    result = parse_url("www.example.com/path")
    assert result.scheme == "http"
    assert result.host == "www.example.com"


# Fix 4: empty / whitespace-only input
def test_parse_url_empty_raises():
    with pytest.raises(ValueError, match="Empty URL"):
        parse_url("")


def test_parse_url_whitespace_only_raises():
    with pytest.raises(ValueError, match="Empty URL"):
        parse_url("   ")


# Fix 5: host with embedded whitespace
def test_parse_url_not_a_url_raises():
    with pytest.raises(ValueError, match="host contains whitespace"):
        parse_url("not a url")


def test_parse_url_host_with_embedded_space_raises():
    # urllib.parse preserves spaces in the netloc when no scheme is inferred
    with pytest.raises(ValueError, match="host contains whitespace"):
        parse_url("http://bad host.com")


# Conservative: bare domain, localhost, and IP URLs must still work
def test_parse_url_bare_domain_ok():
    result = parse_url("example.com")
    assert result.host == "example.com"


def test_parse_url_localhost_ok():
    result = parse_url("localhost")
    assert result.host == "localhost"


def test_parse_url_ip_url_ok():
    result = parse_url("http://192.0.2.10/login")
    assert result.is_ip
    assert result.host == "192.0.2.10"
