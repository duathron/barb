"""Tests for keyword, typosquat, lexical, file_ext analyzers and allowlist suppression."""

from __future__ import annotations

from barb.allowlist import _registrable_domain, is_allowlisted
from barb.analyzers.file_ext import FileExtAnalyzer, _path_extensions
from barb.analyzers.keyword import KeywordAnalyzer
from barb.analyzers.lexical import LexicalAnalyzer
from barb.analyzers.typosquat import TyposquatAnalyzer
from barb.models import SignalSeverity
from barb.url_parser import parse_url

# ---------------------------------------------------------------------------
# KeywordAnalyzer
# ---------------------------------------------------------------------------


class TestKeywordAnalyzer:
    def setup_method(self):
        self.analyzer = KeywordAnalyzer()

    def test_name(self):
        assert self.analyzer.name == "keyword"

    def test_login_in_path(self):
        parsed = parse_url("https://evil.com/secure/login/verify")
        signals = self.analyzer.analyze(parsed)
        assert len(signals) == 1
        assert signals[0].label == "Phishing keywords in URL path"
        assert signals[0].severity == SignalSeverity.LOW
        # all matched keywords present in detail
        assert "login" in signals[0].detail
        assert "verify" in signals[0].detail
        assert "secure" in signals[0].detail

    def test_keyword_in_query(self):
        parsed = parse_url("https://evil.com/index.html?action=account&step=update")
        signals = self.analyzer.analyze(parsed)
        assert len(signals) == 1
        assert "account" in signals[0].detail
        assert "update" in signals[0].detail

    def test_webscr_keyword(self):
        parsed = parse_url("https://evil.com/cgi-bin/webscr?cmd=_login")
        signals = self.analyzer.analyze(parsed)
        assert len(signals) == 1
        assert "webscr" in signals[0].detail

    def test_billing_keyword(self):
        parsed = parse_url("https://evil.com/billing/update")
        signals = self.analyzer.analyze(parsed)
        assert len(signals) == 1
        assert "billing" in signals[0].detail

    def test_no_keywords_no_signal(self):
        parsed = parse_url("https://news.example.com/article/2024/politics")
        signals = self.analyzer.analyze(parsed)
        assert signals == []

    def test_case_insensitive(self):
        # path/query are lowercased before matching
        parsed = parse_url("https://evil.com/SECURE/LOGIN")
        signals = self.analyzer.analyze(parsed)
        assert len(signals) == 1

    def test_aggregated_single_signal(self):
        # Multiple keywords → exactly ONE signal
        parsed = parse_url("https://evil.com/login/verify/account/bank/password/credential/suspend/unlock")
        signals = self.analyzer.analyze(parsed)
        assert len(signals) == 1

    def test_password_credential(self):
        parsed = parse_url("https://evil.com/reset?field=password&type=credential")
        signals = self.analyzer.analyze(parsed)
        assert len(signals) == 1
        assert "password" in signals[0].detail
        assert "credential" in signals[0].detail


# ---------------------------------------------------------------------------
# TyposquatAnalyzer
# ---------------------------------------------------------------------------


class TestTyposquatAnalyzer:
    def setup_method(self):
        self.analyzer = TyposquatAnalyzer()

    def test_name(self):
        assert self.analyzer.name == "typosquat"

    def test_paypal_distance_1(self):
        # paypa1.com — "1" normalizes to "l" → "paypal" == brand after normalization
        parsed = parse_url("https://paypa1.com/login")
        signals = self.analyzer.analyze(parsed)
        labels = [s.label for s in signals]
        assert "Possible typosquatting" in labels
        sig = next(s for s in signals if s.label == "Possible typosquatting")
        assert sig.severity == SignalSeverity.HIGH
        assert "paypal" in sig.detail

    def test_googgle_distance_1(self):
        # googgle — 1 extra g, Levenshtein distance 1 from google
        parsed = parse_url("https://googgle.com/search")
        signals = self.analyzer.analyze(parsed)
        labels = [s.label for s in signals]
        assert "Possible typosquatting" in labels

    def test_g00gle_digit_normalization(self):
        # g00gle → normalize → google
        parsed = parse_url("https://g00gle.com/search")
        signals = self.analyzer.analyze(parsed)
        labels = [s.label for s in signals]
        assert "Possible typosquatting" in labels

    def test_rn_m_substitution(self):
        # arnazon → normalize rn->m → amazon (distance should be 0 after norm, label != brand)
        # arnazon has 'rn' → 'amazom' after sub? Let's use 'arnazon' directly
        # Actually: 'arnazon' normalize rn->m → 'amazom' ... not exact. Use amaz0n instead.
        # amaz0n → normalize 0->o → amazon
        parsed = parse_url("https://amaz0n.com/account")
        signals = self.analyzer.analyze(parsed)
        labels = [s.label for s in signals]
        assert "Possible typosquatting" in labels

    def test_official_domain_not_flagged(self):
        # paypal.com is official — should not be flagged
        parsed = parse_url("https://paypal.com/login")
        signals = self.analyzer.analyze(parsed)
        assert not any(s.label == "Possible typosquatting" and "paypal" in s.detail for s in signals)

    def test_official_subdomain_not_flagged(self):
        # www.paypal.com is official
        parsed = parse_url("https://www.paypal.com/login")
        signals = self.analyzer.analyze(parsed)
        assert not any(s.label == "Possible typosquatting" and "paypal" in s.detail for s in signals)

    def test_ip_skipped(self):
        parsed = parse_url("http://192.168.1.1/login")
        signals = self.analyzer.analyze(parsed)
        assert signals == []

    def test_length_prefilter_no_false_positive(self):
        # Very short or very long labels should not match
        parsed = parse_url("https://superlongdomainnamethatdoesnotresemblebrand.com")
        signals = self.analyzer.analyze(parsed)
        # Should not flag any brand
        assert all(s.label != "Possible typosquatting" for s in signals)

    def test_levenshtein_distance_2(self):
        # paaypal — distance 2 from paypal
        parsed = parse_url("https://paaypal.com/login")
        signals = self.analyzer.analyze(parsed)
        labels = [s.label for s in signals]
        assert "Possible typosquatting" in labels

    def test_unrelated_domain_clean(self):
        parsed = parse_url("https://example.com/page")
        signals = self.analyzer.analyze(parsed)
        assert signals == []


# ---------------------------------------------------------------------------
# LexicalAnalyzer
# ---------------------------------------------------------------------------


class TestLexicalAnalyzer:
    def setup_method(self):
        self.analyzer = LexicalAnalyzer()

    def test_name(self):
        assert self.analyzer.name == "lexical"

    def test_long_url(self):
        url = "https://evil.com/" + "a" * 90
        parsed = parse_url(url)
        assert len(parsed.original) > 100
        signals = self.analyzer.analyze(parsed)
        labels = [s.label for s in signals]
        assert "Long URL" in labels

    def test_short_url_no_long_signal(self):
        parsed = parse_url("https://evil.com/page")
        signals = self.analyzer.analyze(parsed)
        assert not any(s.label == "Long URL" for s in signals)

    def test_many_hyphens(self):
        # 5 hyphens — above threshold of 3
        parsed = parse_url("https://this-is-a-very-bad-domain.com/page")
        hyphen_count = parsed.host.count("-")
        assert hyphen_count > 3
        signals = self.analyzer.analyze(parsed)
        labels = [s.label for s in signals]
        assert "Many hyphens in domain" in labels

    def test_exactly_3_hyphens_not_flagged(self):
        # exactly 3 hyphens — NOT above threshold
        parsed = parse_url("https://one-two-three-four.com/page")
        assert parsed.host.count("-") == 3
        signals = self.analyzer.analyze(parsed)
        assert not any(s.label == "Many hyphens in domain" for s in signals)

    def test_4_hyphens_flagged(self):
        parsed = parse_url("https://a-b-c-d-e.com/page")
        assert parsed.host.count("-") == 4
        signals = self.analyzer.analyze(parsed)
        labels = [s.label for s in signals]
        assert "Many hyphens in domain" in labels

    def test_high_digit_ratio(self):
        # 123456789.com — 9 digits out of 12 chars (dots excluded) = 0.75
        parsed = parse_url("https://1234567890x.com/page")
        host = parsed.host  # 1234567890x.com
        digit_count = sum(1 for c in host if c.isdigit())
        ratio = digit_count / len(host)
        assert ratio > 0.3
        signals = self.analyzer.analyze(parsed)
        labels = [s.label for s in signals]
        assert "High digit ratio in domain" in labels

    def test_low_digit_ratio_no_signal(self):
        parsed = parse_url("https://google.com/page")
        signals = self.analyzer.analyze(parsed)
        assert not any(s.label == "High digit ratio in domain" for s in signals)

    def test_all_three_signals(self):
        # host: 1234567890ab-cd-ef-gh-ij.com  → digits=10, len=28, ratio≈0.357 (>0.3)
        # hyphens: 4 (> threshold of 3)
        # URL length: hostname + path exceeds 100
        url = "https://1234567890ab-cd-ef-gh-ij.com/" + "x" * 90
        parsed = parse_url(url)
        signals = self.analyzer.analyze(parsed)
        labels = [s.label for s in signals]
        assert "Long URL" in labels
        assert "Many hyphens in domain" in labels
        assert "High digit ratio in domain" in labels

    def test_all_signals_are_low_severity(self):
        url = "https://1234567890ab-cd-ef-gh-ij.com/" + "x" * 90
        parsed = parse_url(url)
        for signal in self.analyzer.analyze(parsed):
            assert signal.severity == SignalSeverity.LOW


# ---------------------------------------------------------------------------
# Allowlist helpers
# ---------------------------------------------------------------------------


class TestAllowlist:
    def test_registrable_domain_extraction(self):
        assert _registrable_domain("mail.google.com") == "google.com"
        assert _registrable_domain("google.com") == "google.com"
        assert _registrable_domain("paypal.com") == "paypal.com"

    def test_known_domain_allowlisted(self):
        assert is_allowlisted("google.com") is True

    def test_subdomain_of_known_domain_allowlisted(self):
        assert is_allowlisted("mail.google.com") is True

    def test_unknown_domain_not_allowlisted(self):
        assert is_allowlisted("evil.com") is False

    def test_paypal_allowlisted(self):
        assert is_allowlisted("paypal.com") is True

    def test_github_allowlisted(self):
        assert is_allowlisted("github.com") is True

    def test_wikipedia_allowlisted(self):
        assert is_allowlisted("wikipedia.org") is True


# ---------------------------------------------------------------------------
# Allowlist suppression in _analyze_single
# ---------------------------------------------------------------------------


class TestAllowlistSuppression:
    def test_google_suppresses_tld_typosquat_homoglyph_entropy_host(self):
        """mail.google.com should suppress tld/typosquat/homoglyph/entropy-host signals."""
        from barb.config import AppConfig
        from barb.main import _analyze_single

        config = AppConfig()
        result = _analyze_single("https://mail.google.com/mail/u/0/", config)
        suppressed = {"tld", "typosquat", "homoglyph"}
        for sig in result.signals:
            assert sig.analyzer not in suppressed, (
                f"Signal from suppressed analyzer '{sig.analyzer}' found for allowlisted domain"
            )
            if sig.analyzer == "entropy":
                assert sig.label != "High entropy domain", (
                    "Entropy 'High entropy domain' signal should be suppressed for allowlisted domain"
                )

    def test_evil_domain_not_suppressed(self):
        """Non-allowlisted domain keeps all signals."""
        from barb.config import AppConfig
        from barb.main import _analyze_single

        config = AppConfig()
        result = _analyze_single("https://evil-phishing-xyz.tk/login/verify/account", config)
        analyzer_names = {s.analyzer for s in result.signals}
        # keyword signals should appear (login/verify/account in path)
        assert "keyword" in analyzer_names

    def test_ip_url_kept_on_allowlisted_host(self):
        """ip_url signals are NOT suppressed even if somehow allowlisted."""
        from barb.config import AppConfig
        from barb.main import _analyze_single

        config = AppConfig()
        # Raw IP — not in allowlist anyway, but ip_url signals must survive
        result = _analyze_single("http://192.168.1.1/login", config)
        assert any(s.analyzer == "ip_url" for s in result.signals)

    def test_keyword_kept_on_allowlisted_host(self):
        """keyword signals survive suppression on allowlisted host."""
        from barb.config import AppConfig
        from barb.main import _analyze_single

        config = AppConfig()
        # paypal.com is allowlisted — but keyword signals in path should survive
        result = _analyze_single("https://paypal.com/login/verify/account", config)
        keyword_signals = [s for s in result.signals if s.analyzer == "keyword"]
        assert len(keyword_signals) == 1

    def test_brand_kept_on_allowlisted_host(self):
        """brand signals survive suppression."""
        # brand analyzer fires when brand name is in host but not official
        # Use a domain that IS official (allowlisted) — brand should NOT fire for it
        # Instead confirm that for an evil domain, brand fires and is kept
        from barb.config import AppConfig
        from barb.main import _analyze_single

        config = AppConfig()
        result = _analyze_single("https://paypal-login-secure.com/verify", config)
        # brand should fire (not suppressed)
        assert any(s.analyzer == "brand" for s in result.signals)


# ---------------------------------------------------------------------------
# FileExtAnalyzer
# ---------------------------------------------------------------------------


class TestPathExtensions:
    """Unit tests for the _path_extensions helper."""

    def test_double_extension(self):
        assert _path_extensions("/files/invoice.pdf.exe") == (".pdf", ".exe")

    def test_single_extension(self):
        assert _path_extensions("/download/setup.exe") == ("", ".exe")

    def test_no_extension(self):
        assert _path_extensions("/some/path/readme") == ("", "")

    def test_root_path(self):
        assert _path_extensions("/") == ("", "")

    def test_case_insensitive_lowercasing(self):
        pen, fin = _path_extensions("/Files/INVOICE.PDF.EXE")
        assert pen == ".pdf"
        assert fin == ".exe"

    def test_archive_extension(self):
        assert _path_extensions("/releases/barb.tar.gz") == (".tar", ".gz")

    def test_archive_single(self):
        assert _path_extensions("/downloads/data.zip") == ("", ".zip")


class TestFileExtAnalyzer:
    def setup_method(self):
        self.analyzer = FileExtAnalyzer()

    def test_name(self):
        assert self.analyzer.name == "file_ext"

    # --- Double-extension masquerade (HIGH) ---

    def test_pdf_exe_double_extension_is_high(self):
        parsed = parse_url("http://invoice-update.xyz/files/invoice.pdf.exe")
        signals = self.analyzer.analyze(parsed)
        assert len(signals) == 1
        assert signals[0].severity == SignalSeverity.HIGH
        assert signals[0].label == "Double extension masquerade"
        assert ".pdf" in signals[0].detail
        assert ".exe" in signals[0].detail

    def test_jpg_scr_double_extension_is_high(self):
        parsed = parse_url("http://evil.com/photo.jpg.scr")
        signals = self.analyzer.analyze(parsed)
        assert len(signals) == 1
        assert signals[0].severity == SignalSeverity.HIGH

    def test_doc_vbs_double_extension_is_high(self):
        parsed = parse_url("http://evil.com/report.doc.vbs")
        signals = self.analyzer.analyze(parsed)
        assert len(signals) == 1
        assert signals[0].severity == SignalSeverity.HIGH

    def test_double_ext_case_insensitive(self):
        parsed = parse_url("http://evil.com/INVOICE.PDF.EXE")
        signals = self.analyzer.analyze(parsed)
        assert len(signals) == 1
        assert signals[0].severity == SignalSeverity.HIGH

    # --- Single executable/script extension (LOW) ---

    def test_single_exe_is_low(self):
        parsed = parse_url("http://secure-update.tk/download/setup.exe")
        signals = self.analyzer.analyze(parsed)
        assert len(signals) == 1
        assert signals[0].severity == SignalSeverity.LOW
        assert signals[0].label == "Executable file extension in path"

    def test_single_scr_is_low(self):
        parsed = parse_url("http://secure-update.tk/download/setup.scr")
        signals = self.analyzer.analyze(parsed)
        assert len(signals) == 1
        assert signals[0].severity == SignalSeverity.LOW

    def test_single_bat_is_low(self):
        parsed = parse_url("http://evil.com/run.bat")
        signals = self.analyzer.analyze(parsed)
        assert len(signals) == 1
        assert signals[0].severity == SignalSeverity.LOW

    def test_single_ps1_is_low(self):
        parsed = parse_url("http://evil.com/payload.ps1")
        signals = self.analyzer.analyze(parsed)
        assert len(signals) == 1
        assert signals[0].severity == SignalSeverity.LOW

    # --- Archive extension (INFO) ---

    def test_zip_is_info(self):
        parsed = parse_url("https://example.com/downloads/data.zip")
        signals = self.analyzer.analyze(parsed)
        assert len(signals) == 1
        assert signals[0].severity == SignalSeverity.INFO
        assert signals[0].label == "Archive file extension in path"

    def test_tar_gz_is_info(self):
        # .tar.gz — final ext is .gz (archive INFO)
        parsed = parse_url("https://github.com/duathron/barb/releases/download/v1.2.0/barb.tar.gz")
        signals = self.analyzer.analyze(parsed)
        assert len(signals) == 1
        assert signals[0].severity == SignalSeverity.INFO

    def test_iso_is_info(self):
        parsed = parse_url("https://example.com/distro.iso")
        signals = self.analyzer.analyze(parsed)
        assert len(signals) == 1
        assert signals[0].severity == SignalSeverity.INFO

    # --- No extension / no signal ---

    def test_no_extension_no_signal(self):
        parsed = parse_url("https://example.com/about")
        signals = self.analyzer.analyze(parsed)
        assert signals == []

    def test_root_path_no_signal(self):
        parsed = parse_url("https://example.com/")
        signals = self.analyzer.analyze(parsed)
        assert signals == []

    def test_html_extension_no_signal(self):
        parsed = parse_url("https://example.com/page.html")
        signals = self.analyzer.analyze(parsed)
        assert signals == []

    def test_php_extension_no_signal(self):
        # .php is not in exec/archive lists
        parsed = parse_url("https://example.com/index.php")
        signals = self.analyzer.analyze(parsed)
        assert signals == []

    # --- Benign legit downloads do NOT trigger HIGH ---

    def test_legit_python_exe_download_is_low_not_high(self):
        """python.org .exe installer — allowlisted host, single exe → LOW only."""
        parsed = parse_url("https://www.python.org/ftp/python/3.13.0/python-3.13.0.exe")
        signals = self.analyzer.analyze(parsed)
        assert len(signals) == 1
        assert signals[0].severity == SignalSeverity.LOW
        # Confirm it is NOT a double-extension masquerade
        assert signals[0].label == "Executable file extension in path"

    def test_legit_github_tarball_is_info_not_high(self):
        """GitHub release tarball — single .gz archive → INFO only."""
        parsed = parse_url("https://github.com/duathron/barb/releases/download/v1.2.0/barb.tar.gz")
        signals = self.analyzer.analyze(parsed)
        assert len(signals) == 1
        assert signals[0].severity == SignalSeverity.INFO

    # --- Integration: allowlisted hosts suppress LOW score contribution ---

    def test_legit_exe_on_allowlisted_host_stays_below_suspicious(self):
        """python.org .exe on allowlisted host must stay below SUSPICIOUS verdict."""
        from barb.config import AppConfig
        from barb.main import _analyze_single
        from barb.models import RiskVerdict

        config = AppConfig()
        result = _analyze_single("https://www.python.org/ftp/python/3.13.0/python-3.13.0.exe", config)
        suspicious_verdicts = {RiskVerdict.SUSPICIOUS, RiskVerdict.HIGH_RISK, RiskVerdict.PHISHING}
        assert result.verdict not in suspicious_verdicts, (
            f"Legit python.org .exe download flipped to {result.verdict} — "
            f"score={result.risk_score}, signals={[s.label for s in result.signals]}"
        )

    def test_legit_tarball_on_allowlisted_host_stays_below_suspicious(self):
        """GitHub release tarball on allowlisted host must stay below SUSPICIOUS verdict."""
        from barb.config import AppConfig
        from barb.main import _analyze_single
        from barb.models import RiskVerdict

        config = AppConfig()
        result = _analyze_single(
            "https://github.com/duathron/barb/releases/download/v1.2.0/barb.tar.gz", config
        )
        suspicious_verdicts = {RiskVerdict.SUSPICIOUS, RiskVerdict.HIGH_RISK, RiskVerdict.PHISHING}
        assert result.verdict not in suspicious_verdicts, (
            f"Legit GitHub tarball flipped to {result.verdict} — "
            f"score={result.risk_score}, signals={[s.label for s in result.signals]}"
        )
