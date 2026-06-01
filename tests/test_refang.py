"""Tests for refang_url (unit) and defanged-IOC input via analyze CLI."""

from __future__ import annotations

import json
import re

from typer.testing import CliRunner

from barb.defang import refang_url
from barb.main import app

runner = CliRunner()

_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(text: str) -> str:
    return _ANSI_ESCAPE.sub("", text)


# ---------------------------------------------------------------------------
# refang_url unit tests
# ---------------------------------------------------------------------------


def test_refang_hxxp_with_bracket_dot_at():
    """Full defanged IOC: hxxp://paypal[.]com@evil[.]tk/verify."""
    result = refang_url("hxxp://paypal[.]com@evil[.]tk/verify")
    assert result == "http://paypal.com@evil.tk/verify"


def test_refang_hxxps_bracket_scheme():
    """barb's own defang output: hxxps[://]micros0ft[.]tk round-trips."""
    result = refang_url("hxxps[://]micros0ft[.]tk")
    assert result == "https://micros0ft.tk"


def test_refang_bracket_dot_only():
    """evil[.]com → evil.com (no scheme)."""
    result = refang_url("evil[.]com")
    assert result == "evil.com"


def test_refang_paren_dot():
    """evil(.)com → evil.com."""
    result = refang_url("evil(.)com")
    assert result == "evil.com"


def test_refang_word_dot():
    """evil[dot]com → evil.com."""
    result = refang_url("evil[dot]com")
    assert result == "evil.com"


def test_refang_at_with_domain():
    """user[at]evil.com → user@evil.com (domain lookahead satisfied)."""
    result = refang_url("user[at]evil.com")
    assert result == "user@evil.com"


def test_refang_fullwidth_dot():
    """Fullwidth full stop: evil．com → evil.com."""
    result = refang_url("evil．com")
    assert result == "evil.com"


def test_refang_idempotent_live_url():
    """Live URL is returned unchanged."""
    url = "https://google.com"
    assert refang_url(url) == url


def test_refang_idempotent_double_pass():
    """Running refang twice produces the same result as once."""
    defanged = "hxxp://evil[.]com/path"
    once = refang_url(defanged)
    twice = refang_url(once)
    assert once == twice


def test_refang_ipv6_preserved():
    """IPv6 bracket notation is preserved — [::1] must not be mangled."""
    url = "http://[::1]/x"
    assert refang_url(url) == url


# ---------------------------------------------------------------------------
# CLI integration tests
# ---------------------------------------------------------------------------


def test_analyze_defanged_at_obfuscation_json():
    """hxxp://paypal[.]com@evil[.]tk/verify → host evil.tk, HIGH_RISK, no error."""
    result = runner.invoke(
        app,
        ["analyze", "hxxp://paypal[.]com@evil[.]tk/verify", "-o", "json", "-q"],
    )
    assert result.exit_code != 3, f"unexpected exit 3: {result.output}"
    data = json.loads(result.output)
    assert data["parsed_url"]["host"] == "evil.tk"
    assert data["verdict"] in ("HIGH_RISK", "PHISHING")


def test_analyze_defanged_bracket_scheme_json():
    """hxxps[://]micros0ft[.]tk → host micros0ft.tk, no error."""
    result = runner.invoke(
        app,
        ["analyze", "hxxps[://]micros0ft[.]tk", "-o", "json", "-q"],
    )
    assert result.exit_code != 3, f"unexpected exit 3: {result.output}"
    data = json.loads(result.output)
    assert data["parsed_url"]["host"] == "micros0ft.tk"


def test_analyze_live_url_unchanged():
    """A live URL is accepted as-is and returns a normal result."""
    result = runner.invoke(
        app,
        ["analyze", "https://google.com", "-o", "json", "-q"],
    )
    assert result.exit_code != 3, f"unexpected exit 3: {result.output}"
    data = json.loads(result.output)
    assert data["parsed_url"]["host"] == "google.com"
