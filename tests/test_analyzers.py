"""Tests for individual analyzers."""

from __future__ import annotations

from barb.analyzers.entropy import EntropyAnalyzer
from barb.analyzers.homoglyph import HomoglyphAnalyzer
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


def test_ip_url_userinfo_on_domain_host():
    # The "@" obfuscation trick: visible part looks like a brand, real host is after @.
    analyzer = IPURLAnalyzer()
    parsed = parse_url("https://paypal.com@evil-login.com/verify")
    signals = analyzer.analyze(parsed)
    labels = [s.label for s in signals]
    assert "Userinfo in URL" in labels
    sig = next(s for s in signals if s.label == "Userinfo in URL")
    assert sig.severity.name == "CRITICAL"


def test_ip_url_no_userinfo_no_signal():
    analyzer = IPURLAnalyzer()
    parsed = parse_url("https://www.google.com/search")
    assert analyzer.analyze(parsed) == []


def test_homoglyph_mixed_script_label():
    # "pаypal" — Latin letters with a Cyrillic 'а' (U+0430) mixed in.
    analyzer = HomoglyphAnalyzer()
    parsed = parse_url("https://pаypal.com/login")
    labels = [s.label for s in analyzer.analyze(parsed)]
    assert "Mixed-script domain label" in labels


def test_homoglyph_pure_ascii_no_mixed_script():
    analyzer = HomoglyphAnalyzer()
    parsed = parse_url("https://www.google.com")
    labels = [s.label for s in analyzer.analyze(parsed)]
    assert "Mixed-script domain label" not in labels


def test_homoglyph_single_script_label_not_flagged_as_mixed():
    # Each label stays within one script (Cyrillic label + Latin TLD) → not mixed.
    analyzer = HomoglyphAnalyzer()
    parsed = parse_url("https://пример.com")
    labels = [s.label for s in analyzer.analyze(parsed)]
    assert "Mixed-script domain label" not in labels


def test_subdomain_depth():
    analyzer = SubdomainAnalyzer()
    parsed = parse_url("http://login.secure.paypal.com.evil.com")
    signals = analyzer.analyze(parsed)
    assert any("depth" in s.label.lower() or "deep" in s.label.lower() for s in signals)
