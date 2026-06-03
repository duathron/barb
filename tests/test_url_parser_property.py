"""Property-based tests for barb's URL parse boundary and offline pipeline.

Covers:
- parse_url: only raises ValueError (never TypeError/AttributeError/etc.)
- defang_url / refang_url: never crash on arbitrary input, always return str
- _analyze_single offline pipeline: garbage in → no uncontrolled crash
- Regression anchors for known phishing-ish inputs (punycode, homoglyph)
"""

from __future__ import annotations

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from barb.defang import defang_url, refang_url
from barb.models import ParsedURL
from barb.url_parser import parse_url

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _url_like() -> st.SearchStrategy[str]:
    """Strategy for URL-shaped strings (scheme + host)."""
    schemes = st.sampled_from(["http", "https", "ftp", "hxxp", "hxxps"])
    labels = st.text(
        alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd"), whitelist_characters="-"),
        min_size=1,
        max_size=20,
    )
    tlds = st.sampled_from(["com", "net", "org", "tk", "xyz", "ru", "cn", "io"])
    host = st.builds(lambda a, b, tld: f"{a}.{b}.{tld}", labels, labels, tlds)
    path = st.one_of(
        st.just(""),
        st.text(
            alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd"), whitelist_characters="/-_.~"),
            max_size=60,
        ),
    )
    return st.builds(lambda s, h, p: f"{s}://{h}/{p}", schemes, host, path)


# ---------------------------------------------------------------------------
# Property 1: parse_url raises ONLY ValueError (or returns ParsedURL)
# ---------------------------------------------------------------------------


@given(st.text())
@settings(max_examples=500, suppress_health_check=[HealthCheck.too_slow])
def test_parse_url_only_raises_valueerror(value: str) -> None:
    """For ANY input string, parse_url returns a ParsedURL OR raises ValueError.

    Any other exception type (TypeError, AttributeError, IndexError, etc.) is a
    bug in the parser's input contract.
    """
    try:
        result = parse_url(value)
    except ValueError:
        return  # controlled, allowed
    assert result is not None  # returned a ParsedURL without raising


@given(st.binary().map(lambda b: b.decode("utf-8", errors="replace")))
@settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
def test_parse_url_only_raises_valueerror_decoded_bytes(value: str) -> None:
    """Same guarantee for strings decoded from arbitrary bytes (covers surrogates)."""
    try:
        result = parse_url(value)
    except ValueError:
        return
    assert result is not None


# ---------------------------------------------------------------------------
# Property 2: defang_url / refang_url never crash, always return str
# ---------------------------------------------------------------------------


@given(st.text())
@settings(max_examples=500, suppress_health_check=[HealthCheck.too_slow])
def test_defang_url_never_crashes(value: str) -> None:
    """defang_url must never raise and must return a str."""
    result = defang_url(value)
    assert isinstance(result, str)


@given(st.text())
@settings(max_examples=500, suppress_health_check=[HealthCheck.too_slow])
def test_refang_url_never_crashes(value: str) -> None:
    """refang_url must never raise and must return a str."""
    result = refang_url(value)
    assert isinstance(result, str)


@given(_url_like())
@settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
def test_defang_refang_url_like_strings(url: str) -> None:
    """defang then refang on URL-shaped strings: both functions return str, no crash."""
    defanged = defang_url(url)
    assert isinstance(defanged, str)
    refanged = refang_url(defanged)
    assert isinstance(refanged, str)


# ---------------------------------------------------------------------------
# Property 3: offline analysis pipeline — no uncontrolled crash on garbage
# ---------------------------------------------------------------------------


@given(st.text())
@settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
def test_offline_pipeline_no_uncontrolled_crash_on_text(value: str) -> None:
    """Feeding arbitrary text into the offline analysis pipeline must not produce
    an uncontrolled exception.  ValueError from parse_url is the controlled
    rejection path; anything else is a bug.
    """
    from barb.config import AppConfig
    from barb.main import _analyze_single

    config = AppConfig()
    try:
        result = _analyze_single(value, config, explain=False, osint=False)
    except ValueError:
        return  # controlled rejection at the parse boundary
    assert result is not None


@given(_url_like())
@settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
def test_offline_pipeline_no_uncontrolled_crash_on_url_like(url: str) -> None:
    """URL-shaped strings must complete the full offline pipeline without crashing."""
    from barb.config import AppConfig
    from barb.main import _analyze_single

    config = AppConfig()
    try:
        result = _analyze_single(url, config, explain=False, osint=False)
    except ValueError:
        return  # parse rejection is fine
    assert result is not None
    assert result.verdict is not None
    assert result.risk_score >= 0


# ---------------------------------------------------------------------------
# Property 4: each analyzer's analyze() never crashes on well-formed ParsedURL
#             (constructed with unusual-but-valid combinations)
# ---------------------------------------------------------------------------


def _make_parsed_url(
    host: str,
    scheme: str = "http",
    path: str = "/",
    is_ip: bool = False,
    is_punycode: bool = False,
) -> ParsedURL:
    """Construct a ParsedURL directly for analyzer property tests."""
    return ParsedURL(
        original=f"{scheme}://{host}{path}",
        scheme=scheme,
        host=host,
        path=path,
        is_ip=is_ip,
        is_punycode=is_punycode,
    )


_HOST_STRATEGY = st.one_of(
    # Plain ASCII labels
    st.from_regex(r"[a-z0-9]([a-z0-9\-]{0,18}[a-z0-9])?(\.[a-z0-9]{2,6})+", fullmatch=True),
    # IP-ish strings (may or may not be valid IPs — host field is a string)
    st.from_regex(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", fullmatch=True),
    # Punycode-like labels
    st.just("xn--80ak6aa92e.com"),
    st.just("xn--pypal-4ve.com"),
    # Unicode labels
    st.text(alphabet=st.characters(whitelist_categories=("Ll", "Lu")), min_size=3, max_size=20),
)

_SCHEME_STRATEGY = st.sampled_from(["http", "https", "ftp"])
_PATH_STRATEGY = st.one_of(
    st.just("/"),
    st.from_regex(r"/[a-zA-Z0-9/_\-.]{0,60}", fullmatch=True),
)


@given(host=_HOST_STRATEGY, scheme=_SCHEME_STRATEGY, path=_PATH_STRATEGY)
@settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
def test_all_analyzers_no_crash_on_constructed_urls(host: str, scheme: str, path: str) -> None:
    """Every analyzer's analyze() must not raise on a well-formed ParsedURL
    built from arbitrary (unusual but valid) components.
    """
    from barb.analyzers.brand import BrandAnalyzer
    from barb.analyzers.encoding import EncodingAnalyzer
    from barb.analyzers.entropy import EntropyAnalyzer
    from barb.analyzers.file_ext import FileExtAnalyzer
    from barb.analyzers.homoglyph import HomoglyphAnalyzer
    from barb.analyzers.ip_url import IPURLAnalyzer
    from barb.analyzers.keyword import KeywordAnalyzer
    from barb.analyzers.lexical import LexicalAnalyzer
    from barb.analyzers.shortener import ShortenerAnalyzer
    from barb.analyzers.subdomain import SubdomainAnalyzer
    from barb.analyzers.tld import TLDAnalyzer
    from barb.analyzers.typosquat import TyposquatAnalyzer

    analyzers = [
        EntropyAnalyzer(),
        HomoglyphAnalyzer(),
        TLDAnalyzer(),
        SubdomainAnalyzer(),
        BrandAnalyzer(),
        ShortenerAnalyzer(),
        EncodingAnalyzer(),
        IPURLAnalyzer(),
        KeywordAnalyzer(),
        LexicalAnalyzer(),
        TyposquatAnalyzer(),
        FileExtAnalyzer(),
    ]

    parsed = _make_parsed_url(host=host, scheme=scheme, path=path)

    for analyzer in analyzers:
        signals = analyzer.analyze(parsed)
        assert isinstance(signals, list)


# ---------------------------------------------------------------------------
# Regression anchors — lock behaviour on known phishing-ish inputs
# ---------------------------------------------------------------------------


def test_regression_punycode_host_parseable() -> None:
    """Punycode host must parse successfully and flag is_punycode=True."""
    result = parse_url("http://xn--80ak6aa92e.com")
    assert result.is_punycode is True
    assert result.host == "xn--80ak6aa92e.com"


def test_regression_punycode_pipeline_returns_result() -> None:
    """A punycode URL must complete the offline pipeline without error."""
    from barb.config import AppConfig
    from barb.main import _analyze_single

    result = _analyze_single("http://xn--80ak6aa92e.com", AppConfig(), explain=False, osint=False)
    assert result.verdict is not None
    assert result.risk_score >= 0


def test_regression_homoglyph_domain_detected() -> None:
    """A domain with a Cyrillic 'а' (U+0430) mixed with ASCII should trigger
    a homoglyph or mixed-script signal.
    """
    from barb.config import AppConfig
    from barb.main import _analyze_single

    # 'pаypal.com' where the 'а' is Cyrillic U+0430
    result = _analyze_single("https://pаypal.com/login", AppConfig(), explain=False, osint=False)
    analyzer_names = {s.analyzer for s in result.signals}
    # The homoglyph or mixed-script detector must have fired
    assert "homoglyph" in analyzer_names, (
        f"Expected 'homoglyph' signal for mixed-script domain; got signals from: {analyzer_names}"
    )


def test_regression_phishing_url_not_safe() -> None:
    """A classic phishing-pattern URL must not be rated SAFE."""
    from barb.config import AppConfig
    from barb.main import _analyze_single
    from barb.models import RiskVerdict

    result = _analyze_single(
        "http://paypal-secure-login.tk/verify/account",
        AppConfig(),
        explain=False,
        osint=False,
    )
    assert result.verdict != RiskVerdict.SAFE, (
        f"Expected non-SAFE verdict for phishing URL; got {result.verdict} (score={result.risk_score})"
    )


def test_regression_known_safe_url_low_score() -> None:
    """A benign URL (example.com) should have a low risk score."""
    from barb.config import AppConfig
    from barb.main import _analyze_single

    result = _analyze_single("https://example.com/", AppConfig(), explain=False, osint=False)
    assert result.risk_score < 10, f"Expected low score for example.com; got {result.risk_score}"


def test_regression_at_sign_obfuscation_critical() -> None:
    """An @-obfuscated URL (paypal.com@evil.com) must produce a CRITICAL signal."""
    from barb.config import AppConfig
    from barb.main import _analyze_single
    from barb.models import SignalSeverity

    result = _analyze_single(
        "http://paypal.com@evil-login.tk/verify",
        AppConfig(),
        explain=False,
        osint=False,
    )
    severities = {s.severity for s in result.signals}
    assert SignalSeverity.CRITICAL in severities, (
        f"Expected CRITICAL signal for @-obfuscated URL; got severities: {severities}"
    )
