"""Tests for individual analyzers."""

from __future__ import annotations

from barb.analyzers.entropy import EntropyAnalyzer
from barb.analyzers.ip_url import IPURLAnalyzer
from barb.analyzers.subdomain import SubdomainAnalyzer
from barb.url_parser import parse_url


def test_entropy_analyzer_high_entropy():
    analyzer = EntropyAnalyzer()
    parsed = parse_url("http://x7k2m9pq3z.evil.com/login")
    signals = analyzer.analyze(parsed)
    assert len(signals) > 0
    assert signals[0].analyzer == "entropy"


def test_entropy_analyzer_normal_domain():
    analyzer = EntropyAnalyzer()
    parsed = parse_url("https://www.google.com")
    signals = analyzer.analyze(parsed)
    assert len(signals) == 0


def test_ip_url_analyzer():
    analyzer = IPURLAnalyzer()
    parsed = parse_url("http://192.168.1.1/login")
    signals = analyzer.analyze(parsed)
    assert len(signals) == 1
    assert signals[0].label == "IP-based URL"


def test_subdomain_depth():
    analyzer = SubdomainAnalyzer()
    parsed = parse_url("http://login.secure.paypal.com.evil.com")
    signals = analyzer.analyze(parsed)
    assert any("depth" in s.label.lower() or "deep" in s.label.lower() for s in signals)
