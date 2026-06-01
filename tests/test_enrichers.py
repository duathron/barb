"""Tests for OSINT enrichers (DNS + RDAP)."""

from __future__ import annotations

import json
import socket
from unittest.mock import MagicMock, patch

from barb.enrichers.dns import DNSEnricher
from barb.enrichers.protocol import EnricherProtocol
from barb.enrichers.rdap import RDAPEnricher, _find_server
from barb.models import SignalSeverity
from barb.url_parser import parse_url

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parsed(url: str):
    return parse_url(url)


def _mock_rdap_response(events=None, remarks=None):
    """Build a minimal RDAP JSON response."""
    data = {}
    if events:
        data["events"] = events
    if remarks:
        data["remarks"] = remarks
    body = json.dumps(data).encode()
    mock_resp = MagicMock()
    mock_resp.read.return_value = body
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    return mock_resp


# ---------------------------------------------------------------------------
# Protocol compliance
# ---------------------------------------------------------------------------

def test_dns_enricher_implements_protocol():
    assert isinstance(DNSEnricher(), EnricherProtocol)


def test_rdap_enricher_implements_protocol():
    assert isinstance(RDAPEnricher(), EnricherProtocol)


# ---------------------------------------------------------------------------
# DNS enricher
# ---------------------------------------------------------------------------

def test_dns_skips_ip_url():
    enricher = DNSEnricher()
    result = enricher.enrich(_parsed("http://192.168.1.1/path"))
    assert result == []


def test_dns_nxdomain_returns_medium_signal():
    enricher = DNSEnricher()
    with patch("socket.getaddrinfo", side_effect=socket.gaierror("NXDOMAIN")):
        signals = enricher.enrich(_parsed("https://nonexistent-xyz-12345.example"))
    assert len(signals) == 1
    assert signals[0].severity == SignalSeverity.MEDIUM
    assert signals[0].analyzer == "osint:dns"


def test_dns_loopback_returns_high_signal():
    enricher = DNSEnricher()
    with patch("socket.getaddrinfo", return_value=[(None, None, None, None, ("127.0.0.1", 0))]):
        signals = enricher.enrich(_parsed("https://evil.com"))
    assert any(s.severity == SignalSeverity.HIGH for s in signals)


def test_dns_private_ip_returns_medium_signal():
    enricher = DNSEnricher()
    with patch("socket.getaddrinfo", return_value=[(None, None, None, None, ("10.0.0.1", 0))]):
        signals = enricher.enrich(_parsed("https://evil.com"))
    assert any(s.severity == SignalSeverity.MEDIUM for s in signals)


def test_dns_clean_resolution_returns_no_signals():
    enricher = DNSEnricher()
    with patch("socket.getaddrinfo", return_value=[(None, None, None, None, ("93.184.216.34", 0))]):
        signals = enricher.enrich(_parsed("https://example.com"))
    assert signals == []


def test_dns_os_error_is_ignored():
    enricher = DNSEnricher()
    with patch("socket.getaddrinfo", side_effect=OSError("unexpected")):
        signals = enricher.enrich(_parsed("https://example.com"))
    assert signals == []


# ---------------------------------------------------------------------------
# RDAP bootstrap helper
# ---------------------------------------------------------------------------

_SAMPLE_BOOTSTRAP = {
    "services": [
        [["com", "net"], ["https://rdap.verisign.com/com/v1/"]],
        [["org"], ["https://rdap.pir.org/"]],
    ],
    "_fetched_at": 9999999999,  # far future — never stale in tests
}


def test_find_server_known_tld():
    server = _find_server("com", _SAMPLE_BOOTSTRAP)
    assert server == "https://rdap.verisign.com/com/v1/"


def test_find_server_unknown_tld():
    server = _find_server("xyz", _SAMPLE_BOOTSTRAP)
    assert server is None


def test_find_server_case_insensitive():
    server = _find_server("COM", _SAMPLE_BOOTSTRAP)
    assert server is not None


# ---------------------------------------------------------------------------
# RDAP enricher
# ---------------------------------------------------------------------------

def test_rdap_skips_ip_url():
    enricher = RDAPEnricher()
    result = enricher.enrich(_parsed("http://192.168.1.1/login"))
    assert result == []


def test_rdap_young_domain_high_signal():
    from datetime import datetime, timedelta, timezone

    reg_date = (datetime.now(timezone.utc) - timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    events = [{"eventAction": "registration", "eventDate": reg_date}]
    enricher = RDAPEnricher()

    with patch("barb.enrichers.rdap._load_bootstrap", return_value=_SAMPLE_BOOTSTRAP):
        with patch("urllib.request.urlopen", return_value=_mock_rdap_response(events=events)):
            signals = enricher.enrich(_parsed("https://evil.com"))

    assert any(s.severity == SignalSeverity.HIGH for s in signals)


def test_rdap_medium_age_domain():
    from datetime import datetime, timedelta, timezone

    reg_date = (datetime.now(timezone.utc) - timedelta(days=60)).strftime("%Y-%m-%dT%H:%M:%SZ")
    events = [{"eventAction": "registration", "eventDate": reg_date}]
    enricher = RDAPEnricher()

    with patch("barb.enrichers.rdap._load_bootstrap", return_value=_SAMPLE_BOOTSTRAP):
        with patch("urllib.request.urlopen", return_value=_mock_rdap_response(events=events)):
            signals = enricher.enrich(_parsed("https://evil.com"))

    assert any(s.severity == SignalSeverity.MEDIUM for s in signals)


def test_rdap_old_domain_no_age_signal():
    from datetime import datetime, timedelta, timezone

    reg_date = (datetime.now(timezone.utc) - timedelta(days=500)).strftime("%Y-%m-%dT%H:%M:%SZ")
    events = [{"eventAction": "registration", "eventDate": reg_date}]
    enricher = RDAPEnricher()

    with patch("barb.enrichers.rdap._load_bootstrap", return_value=_SAMPLE_BOOTSTRAP):
        with patch("urllib.request.urlopen", return_value=_mock_rdap_response(events=events)):
            signals = enricher.enrich(_parsed("https://example.com"))

    age_signals = [s for s in signals if "registered" in s.label.lower()]
    assert age_signals == []


def test_rdap_privacy_protected():
    remarks = [{"description": ["REDACTED FOR PRIVACY"]}]
    enricher = RDAPEnricher()

    with patch("barb.enrichers.rdap._load_bootstrap", return_value=_SAMPLE_BOOTSTRAP):
        with patch("urllib.request.urlopen", return_value=_mock_rdap_response(remarks=remarks)):
            signals = enricher.enrich(_parsed("https://evil.com"))

    privacy_signals = [s for s in signals if "privacy" in s.label.lower()]
    assert len(privacy_signals) == 1
    assert privacy_signals[0].severity == SignalSeverity.LOW


def test_rdap_network_error_fails_open():
    enricher = RDAPEnricher()
    with patch("barb.enrichers.rdap._load_bootstrap", return_value=_SAMPLE_BOOTSTRAP):
        with patch("urllib.request.urlopen", side_effect=Exception("timeout")):
            signals = enricher.enrich(_parsed("https://evil.com"))
    assert signals == []


def test_rdap_unknown_tld_fails_open():
    enricher = RDAPEnricher()
    with patch("barb.enrichers.rdap._load_bootstrap", return_value=_SAMPLE_BOOTSTRAP):
        signals = enricher.enrich(_parsed("https://evil.unknowntld"))
    assert signals == []


# ---------------------------------------------------------------------------
# crt.sh enricher
# ---------------------------------------------------------------------------

from barb.enrichers.crtsh import CrtShEnricher  # noqa: E402


def _mock_crtsh_response(entries: list) -> MagicMock:
    """Build a mock urllib response returning a JSON array of CT entries."""
    body = json.dumps(entries).encode()
    mock_resp = MagicMock()
    mock_resp.read.return_value = body
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    return mock_resp


def _crtsh_entry(days_ago: int) -> dict:
    from datetime import datetime, timedelta, timezone
    dt = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return {"not_before": dt.strftime("%Y-%m-%dT%H:%M:%S"), "name_value": "example.com", "id": 1}


def test_crtsh_implements_protocol():
    from barb.enrichers.protocol import EnricherProtocol
    assert isinstance(CrtShEnricher(), EnricherProtocol)


def test_crtsh_recent_cert_3_days_medium_signal():
    """Certificate issued 3 days ago → MEDIUM signal."""
    enricher = CrtShEnricher()
    entries = [_crtsh_entry(3)]
    with patch("urllib.request.urlopen", return_value=_mock_crtsh_response(entries)):
        signals = enricher.enrich(_parsed("https://evil.com"))
    assert len(signals) == 1
    assert signals[0].severity == SignalSeverity.MEDIUM
    assert signals[0].analyzer == "osint:crtsh"
    assert "Recently issued" in signals[0].label


def test_crtsh_cert_20_days_low_signal():
    """Certificate issued 20 days ago → LOW signal."""
    enricher = CrtShEnricher()
    entries = [_crtsh_entry(20)]
    with patch("urllib.request.urlopen", return_value=_mock_crtsh_response(entries)):
        signals = enricher.enrich(_parsed("https://evil.com"))
    assert len(signals) == 1
    assert signals[0].severity == SignalSeverity.LOW
    assert signals[0].analyzer == "osint:crtsh"


def test_crtsh_old_cert_no_recency_signal():
    """Certificate issued 365 days ago → no recency signal."""
    enricher = CrtShEnricher()
    entries = [_crtsh_entry(365)]
    with patch("urllib.request.urlopen", return_value=_mock_crtsh_response(entries)):
        signals = enricher.enrich(_parsed("https://example.com"))
    assert signals == []


def test_crtsh_empty_array_info_signal():
    """Empty CT response → one INFO signal about missing records."""
    enricher = CrtShEnricher()
    with patch("urllib.request.urlopen", return_value=_mock_crtsh_response([])):
        signals = enricher.enrich(_parsed("https://example.com"))
    assert len(signals) == 1
    assert signals[0].severity == SignalSeverity.INFO
    assert "No certificate transparency" in signals[0].label


def test_crtsh_urlopen_raises_fails_open():
    """urlopen raising an exception → returns [], no exception propagated."""
    enricher = CrtShEnricher()
    with patch("urllib.request.urlopen", side_effect=OSError("connection refused")):
        signals = enricher.enrich(_parsed("https://evil.com"))
    assert signals == []


def test_crtsh_skips_ip_url():
    """IP-based URL → returns [] without making any network call."""
    enricher = CrtShEnricher()
    with patch("urllib.request.urlopen") as mock_open:
        signals = enricher.enrich(_parsed("http://192.168.1.1/login"))
    assert signals == []
    mock_open.assert_not_called()


def test_crtsh_most_recent_cert_used():
    """When multiple entries exist, the most recent not_before is used."""
    enricher = CrtShEnricher()
    entries = [_crtsh_entry(365), _crtsh_entry(3)]  # old + new
    with patch("urllib.request.urlopen", return_value=_mock_crtsh_response(entries)):
        signals = enricher.enrich(_parsed("https://evil.com"))
    # Should pick the 3-day-old cert → MEDIUM
    assert len(signals) == 1
    assert signals[0].severity == SignalSeverity.MEDIUM


def test_crtsh_malformed_not_before_skipped():
    """Entries with unparseable not_before are skipped gracefully."""
    enricher = CrtShEnricher()
    entries = [
        {"not_before": "not-a-date", "name_value": "evil.com", "id": 1},
        _crtsh_entry(3),
    ]
    with patch("urllib.request.urlopen", return_value=_mock_crtsh_response(entries)):
        signals = enricher.enrich(_parsed("https://evil.com"))
    assert len(signals) == 1
    assert signals[0].severity == SignalSeverity.MEDIUM
