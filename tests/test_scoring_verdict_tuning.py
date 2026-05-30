"""Tests for MeetUp 2026-05-30 scoring/verdict tuning decisions D1, D2, D4."""

from __future__ import annotations

from barb.analyzers.homoglyph import HomoglyphAnalyzer
from barb.config import AppConfig
from barb.models import RiskVerdict, Signal, SignalSeverity
from barb.scoring import compute_risk_score, determine_verdict
from barb.url_parser import parse_url

# ---------------------------------------------------------------------------
# D1 — Severity-floor in determine_verdict
# ---------------------------------------------------------------------------


class TestSeverityFloor:
    def test_critical_signal_floors_to_high_risk(self):
        """Single CRITICAL signal with low score → floor to HIGH_RISK."""
        config = AppConfig()
        # Score of 0 (INFO only) but one CRITICAL present → HIGH_RISK minimum
        signals = [
            Signal(analyzer="test", severity=SignalSeverity.INFO, label="x", detail="x"),
            Signal(analyzer="test", severity=SignalSeverity.CRITICAL, label="x", detail="x"),
        ]
        score = compute_risk_score(signals, config)
        verdict = determine_verdict(score, signals, config)
        assert verdict in (RiskVerdict.HIGH_RISK, RiskVerdict.PHISHING)

    def test_high_signal_floors_to_suspicious(self):
        """Single HIGH signal with low score → floor to SUSPICIOUS minimum."""
        config = AppConfig()
        # LOW-points-only score = 1 (below suspicious threshold of 4) but HIGH present
        signals = [
            Signal(analyzer="test", severity=SignalSeverity.LOW, label="x", detail="x"),
            Signal(analyzer="test", severity=SignalSeverity.HIGH, label="x", detail="x"),
        ]
        score = compute_risk_score(signals, config)
        verdict = determine_verdict(score, signals, config)
        assert verdict in (RiskVerdict.SUSPICIOUS, RiskVerdict.HIGH_RISK, RiskVerdict.PHISHING)

    def test_medium_signal_no_floor(self):
        """MEDIUM-only signals must not trigger any floor."""
        config = AppConfig()
        signals = [
            Signal(analyzer="test", severity=SignalSeverity.MEDIUM, label="x", detail="x"),
        ]
        score = compute_risk_score(signals, config)  # 2 pts → LOW_RISK (threshold 1)
        verdict = determine_verdict(score, signals, config)
        assert verdict == RiskVerdict.LOW_RISK  # 2 pts → LOW_RISK, no floor

    def test_no_signals_safe(self):
        config = AppConfig()
        verdict = determine_verdict(0.0, [], config)
        assert verdict == RiskVerdict.SAFE

    def test_phishing_score_stays_phishing_with_critical(self):
        """PHISHING score + CRITICAL → still PHISHING (floor never lowers)."""
        config = AppConfig()
        signals = [
            Signal(analyzer="test", severity=SignalSeverity.CRITICAL, label="x", detail="x"),
        ] * 4  # 4×5 = 20 pts → PHISHING
        score = compute_risk_score(signals, config)
        verdict = determine_verdict(score, signals, config)
        assert verdict == RiskVerdict.PHISHING

    def test_critical_floor_does_not_lower_phishing(self):
        """If score already gives PHISHING, CRITICAL floor must not lower it."""
        config = AppConfig()
        # Force phishing by score alone (>= 13), use only CRITICAL for simplicity
        signals = [
            Signal(analyzer="homoglyph", severity=SignalSeverity.CRITICAL, label="x", detail="x"),
        ] * 3  # 15 pts
        score = compute_risk_score(signals, config)
        assert score >= 13
        verdict = determine_verdict(score, signals, config)
        assert verdict == RiskVerdict.PHISHING


# ---------------------------------------------------------------------------
# D2 — Homoglyph per-char CRITICAL only on mixed-script labels
# ---------------------------------------------------------------------------


class TestHomoglyphCriticalOnlyMixedScript:
    def test_mixed_script_label_emits_per_char_critical(self):
        """pаypal.com: Cyrillic 'а' in otherwise-Latin label → per-char CRITICAL."""
        analyzer = HomoglyphAnalyzer()
        # 'а' here is Cyrillic U+0430, rest Latin
        parsed = parse_url("https://pаypal.com/login")
        signals = analyzer.analyze(parsed)
        critical = [s for s in signals if s.severity == SignalSeverity.CRITICAL]
        assert len(critical) >= 1, "Expected at least one CRITICAL for Cyrillic 'а' in mixed label"

    def test_pure_cyrillic_label_no_per_char_critical(self):
        """пример.рф: all-Cyrillic label → zero per-char CRITICAL signals."""
        analyzer = HomoglyphAnalyzer()
        parsed = parse_url("https://пример.рф")
        signals = analyzer.analyze(parsed)
        critical = [s for s in signals if s.severity == SignalSeverity.CRITICAL
                    and s.label == "Homoglyph character detected"]
        assert critical == [], f"Pure-Cyrillic IDN must not produce per-char CRITICAL; got {critical}"

    def test_pure_ascii_no_critical(self):
        """google.com: pure ASCII → no CRITICAL homoglyph signals."""
        analyzer = HomoglyphAnalyzer()
        parsed = parse_url("https://www.google.com")
        signals = analyzer.analyze(parsed)
        critical = [s for s in signals if s.severity == SignalSeverity.CRITICAL]
        assert critical == []


# ---------------------------------------------------------------------------
# D4 — LOW info signal for pure non-ASCII IDN labels
# ---------------------------------------------------------------------------


class TestIDNInfoSignal:
    def test_pure_cyrillic_idn_emits_low_signal(self):
        """пример.рф: all-Cyrillic alphabetic chars → ONE LOW 'Internationalized domain' signal per label."""
        analyzer = HomoglyphAnalyzer()
        parsed = parse_url("https://пример.рф")
        signals = analyzer.analyze(parsed)
        idn_signals = [s for s in signals if s.label == "Internationalized domain (non-ASCII)"]
        assert len(idn_signals) >= 1, "Expected at least one LOW IDN signal"
        for sig in idn_signals:
            assert sig.severity == SignalSeverity.LOW

    def test_mixed_script_label_does_not_get_idn_signal(self):
        """Mixed-script label is NOT a pure IDN, must not get IDN LOW signal."""
        analyzer = HomoglyphAnalyzer()
        parsed = parse_url("https://pаypal.com/login")
        signals = analyzer.analyze(parsed)
        idn_signals = [s for s in signals if s.label == "Internationalized domain (non-ASCII)"]
        assert idn_signals == [], "Mixed-script label must not emit IDN LOW signal"

    def test_pure_ascii_no_idn_signal(self):
        """google.com: pure ASCII → no IDN signal."""
        analyzer = HomoglyphAnalyzer()
        parsed = parse_url("https://www.google.com")
        signals = analyzer.analyze(parsed)
        idn_signals = [s for s in signals if s.label == "Internationalized domain (non-ASCII)"]
        assert idn_signals == []


# ---------------------------------------------------------------------------
# Acceptance cases (per spec)
# ---------------------------------------------------------------------------


class TestAcceptanceCases:
    def test_ac1_paypal_userinfo_high_risk(self):
        """AC1: paypal.com@evil.com → HIGH_RISK (CRITICAL userinfo floor)."""
        from barb.main import _analyze_single
        config = AppConfig()
        result = _analyze_single("https://paypal.com@evil.com", config)
        assert result.verdict in (RiskVerdict.HIGH_RISK, RiskVerdict.PHISHING), (
            f"Expected HIGH_RISK or PHISHING, got {result.verdict}"
        )

    def test_ac2_g00gle_typosquat_suspicious(self):
        """AC2: g00gle.com → SUSPICIOUS (HIGH typosquat floor)."""
        from barb.main import _analyze_single
        config = AppConfig()
        result = _analyze_single("https://g00gle.com", config)
        assert result.verdict in (RiskVerdict.SUSPICIOUS, RiskVerdict.HIGH_RISK, RiskVerdict.PHISHING), (
            f"Expected >= SUSPICIOUS, got {result.verdict}"
        )

    def test_ac3_paypal_cyrillic_a_phishing(self):
        """AC3: pаypal.com (Cyrillic 'а') → PHISHING (CRITICAL + HIGH_RISK mixed-script)."""
        from barb.main import _analyze_single
        config = AppConfig()
        # Cyrillic 'а' U+0430
        result = _analyze_single("https://pаypal.com/login", config)
        assert result.verdict == RiskVerdict.PHISHING, (
            f"Expected PHISHING for mixed-script paypal spoof, got {result.verdict}"
        )

    def test_ac4_pure_cyrillic_idn_not_phishing(self):
        """AC4: пример.рф → NOT PHISHING; no per-char CRITICAL; has LOW IDN signal."""
        from barb.main import _analyze_single
        config = AppConfig()
        result = _analyze_single("https://пример.рф", config)
        # Must not be PHISHING
        assert result.verdict in (RiskVerdict.SAFE, RiskVerdict.LOW_RISK, RiskVerdict.SUSPICIOUS), (
            f"Expected <= SUSPICIOUS for pure Cyrillic IDN, got {result.verdict}"
        )
        # No per-char CRITICAL homoglyph
        critical = [s for s in result.signals
                    if s.severity == SignalSeverity.CRITICAL and s.label == "Homoglyph character detected"]
        assert critical == [], f"Must not have per-char CRITICAL for pure-Cyrillic IDN: {critical}"
        # Has IDN LOW signal
        idn = [s for s in result.signals if s.label == "Internationalized domain (non-ASCII)"]
        assert len(idn) >= 1, "Expected IDN LOW signal for pure Cyrillic host"

    def test_ac5_evil_ru_login_safe(self):
        """AC5: https://evil.ru/login → SAFE (unchanged behaviour)."""
        from barb.main import _analyze_single
        config = AppConfig()
        result = _analyze_single("https://evil.ru/login", config)
        assert result.verdict in (RiskVerdict.SAFE, RiskVerdict.LOW_RISK), (
            f"Expected SAFE or LOW_RISK for evil.ru/login, got {result.verdict}"
        )

    def test_ac6_plain_google_safe(self):
        """AC6: https://www.google.com → SAFE, no new signals."""
        from barb.main import _analyze_single
        config = AppConfig()
        result = _analyze_single("https://www.google.com", config)
        assert result.verdict == RiskVerdict.SAFE, (
            f"Expected SAFE for www.google.com, got {result.verdict}"
        )
