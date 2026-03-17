"""Tests for URL parser."""

from __future__ import annotations

import pytest

from phishing_analyzer.url_parser import parse_url


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
