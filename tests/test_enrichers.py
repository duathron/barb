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


# ---------------------------------------------------------------------------
# ASN enricher
# ---------------------------------------------------------------------------

from barb.enrichers.asn import ASNEnricher  # noqa: E402

_CYMRU_VERBOSE_HEADER = "AS      | IP               | BGP Prefix          | CC | Registry | Allocated  | AS Name\n"
_CYMRU_DATA_LINE = "13335   | 1.1.1.1          | 1.1.1.0/24          | US | arin     | 2010-07-14 | CLOUDFLARENET, US\n"
_CYMRU_SAMPLE_RESPONSE = _CYMRU_VERBOSE_HEADER + _CYMRU_DATA_LINE


def test_asn_implements_protocol():
    from barb.enrichers.protocol import EnricherProtocol
    assert isinstance(ASNEnricher(), EnricherProtocol)


# --- _parse_cymru unit tests ---

def test_parse_cymru_valid_response():
    """Realistic header+data line parses to correct dict."""
    enricher = ASNEnricher()
    result = enricher._parse_cymru(_CYMRU_SAMPLE_RESPONSE)
    assert result is not None
    assert result["asn"] == "13335"
    assert result["cc"] == "US"
    assert result["as_name"] == "CLOUDFLARENET, US"
    assert result["prefix"] == "1.1.1.0/24"


def test_parse_cymru_header_only_returns_none():
    """Response with only a header line and no data line → None."""
    enricher = ASNEnricher()
    result = enricher._parse_cymru(_CYMRU_VERBOSE_HEADER)
    assert result is None


def test_parse_cymru_empty_string_returns_none():
    """Empty string → None."""
    enricher = ASNEnricher()
    assert enricher._parse_cymru("") is None


def test_parse_cymru_malformed_line_returns_none():
    """Line with fewer than 7 pipe-separated fields → None."""
    enricher = ASNEnricher()
    bad = "13335 | 1.1.1.1 | 1.1.1.0/24\n"  # only 3 fields
    assert enricher._parse_cymru(bad) is None


def test_parse_cymru_non_numeric_asn_skipped():
    """Line whose first field is not numeric is skipped."""
    enricher = ASNEnricher()
    bad = "BOGUS   | 1.1.1.1 | 1.1.1.0/24 | US | arin | 2010-07-14 | SOME-NET, US\n"
    assert enricher._parse_cymru(bad) is None


# --- enrich() integration (patched helpers) ---

def test_asn_enrich_returns_one_info_signal():
    """Happy path: _resolve_ip → IP, _query_cymru → response → one INFO signal."""
    enricher = ASNEnricher()
    with patch.object(enricher, "_resolve_ip", return_value="1.1.1.1"), \
         patch.object(enricher, "_query_cymru", return_value=_CYMRU_SAMPLE_RESPONSE):
        signals = enricher.enrich(_parsed("https://example.com"))
    assert len(signals) == 1
    sig = signals[0]
    assert sig.severity == SignalSeverity.INFO
    assert sig.analyzer == "osint:asn"
    assert "AS13335" in sig.detail
    assert "CLOUDFLARENET" in sig.detail
    assert "1.1.1.1" in sig.detail


def test_asn_enrich_ip_url_skips_resolve():
    """IP-based URL goes straight to _query_cymru, _resolve_ip is not called."""
    enricher = ASNEnricher()
    with patch.object(enricher, "_resolve_ip") as mock_resolve, \
         patch.object(enricher, "_query_cymru", return_value=_CYMRU_SAMPLE_RESPONSE):
        signals = enricher.enrich(_parsed("http://1.1.1.1/path"))
    mock_resolve.assert_not_called()
    assert len(signals) == 1
    assert signals[0].severity == SignalSeverity.INFO


# --- fail-open tests ---

def test_asn_enrich_resolve_ip_returns_none_fails_open():
    """_resolve_ip returning None → returns [], no exception."""
    enricher = ASNEnricher()
    with patch.object(enricher, "_resolve_ip", return_value=None):
        signals = enricher.enrich(_parsed("https://nonexistent.example"))
    assert signals == []


def test_asn_enrich_query_cymru_returns_none_fails_open():
    """_query_cymru returning None → returns []."""
    enricher = ASNEnricher()
    with patch.object(enricher, "_resolve_ip", return_value="1.1.1.1"), \
         patch.object(enricher, "_query_cymru", return_value=None):
        signals = enricher.enrich(_parsed("https://example.com"))
    assert signals == []


def test_asn_enrich_query_cymru_raises_fails_open():
    """_query_cymru raising an exception → returns [], exception does not propagate."""
    enricher = ASNEnricher()
    with patch.object(enricher, "_resolve_ip", return_value="1.1.1.1"), \
         patch.object(enricher, "_query_cymru", side_effect=RuntimeError("network error")):
        signals = enricher.enrich(_parsed("https://example.com"))
    assert signals == []


def test_asn_enrich_parse_returns_none_fails_open():
    """_parse_cymru returning None → returns []."""
    enricher = ASNEnricher()
    with patch.object(enricher, "_resolve_ip", return_value="1.1.1.1"), \
         patch.object(enricher, "_query_cymru", return_value=_CYMRU_VERBOSE_HEADER):
        signals = enricher.enrich(_parsed("https://example.com"))
    assert signals == []
