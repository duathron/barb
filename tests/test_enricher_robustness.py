"""Robustness tests for OSINT enricher parsing of malformed external data.

Each test exercises a specific edge case where an external API field arrives
with an unexpected type (e.g. int where str expected, None where dict expected,
dict where list expected).  Every test asserts:
  1. No exception is raised (fail-open contract).
  2. The fallback result is sensible ([] or an appropriate signal set).

These tests were written to verify the defensive fixes for the int/str bug
class found in barb/enrichers/rdap.py and barb/enrichers/crtsh.py.
Each test would have raised AttributeError or TypeError BEFORE the fix.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

from barb.enrichers.crtsh import CrtShEnricher
from barb.enrichers.rdap import RDAPEnricher, _find_server
from barb.models import SignalSeverity
from barb.url_parser import parse_url

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SAMPLE_BOOTSTRAP = {
    "services": [
        [["com", "net"], ["https://rdap.verisign.com/com/v1/"]],
        [["org"], ["https://rdap.pir.org/"]],
    ],
    "_fetched_at": 9_999_999_999,
}


def _parsed(url: str):
    return parse_url(url)


def _mock_response(body: bytes) -> MagicMock:
    """Build a minimal mock urllib response wrapping *body*."""
    mock_resp = MagicMock()
    mock_resp.read.return_value = body
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    return mock_resp


def _rdap_response(data: object) -> MagicMock:
    return _mock_response(json.dumps(data).encode())


def _crtsh_response(data: object) -> MagicMock:
    return _mock_response(json.dumps(data).encode())


# ---------------------------------------------------------------------------
# _find_server — bootstrap data is external (IANA-fetched / cached)
# ---------------------------------------------------------------------------

class TestFindServerRobustness:
    """_find_server must not raise on malformed bootstrap services entries."""

    def test_services_entry_tlds_is_none(self):
        """tlds=None in a bootstrap entry — previously TypeError in generator."""
        bootstrap = {
            "services": [[None, ["https://rdap.verisign.com/com/v1/"]]],
            "_fetched_at": 9_999_999_999,
        }
        result = _find_server("com", bootstrap)
        assert result is None  # entry skipped, no match

    def test_services_entry_servers_is_none(self):
        """servers=None — previously TypeError."""
        bootstrap = {
            "services": [[["com"], None]],
            "_fetched_at": 9_999_999_999,
        }
        result = _find_server("com", bootstrap)
        assert result is None

    def test_services_entry_server_item_is_int(self):
        """servers[0] is int — previously AttributeError on int.rstrip('/')."""
        bootstrap = {
            "services": [[["com"], [42]]],
            "_fetched_at": 9_999_999_999,
        }
        result = _find_server("com", bootstrap)
        assert result is None  # int server skipped

    def test_services_entry_tlds_contains_non_str(self):
        """tlds list contains non-str items — should skip them without error."""
        bootstrap = {
            "services": [[["com", None, 99], ["https://rdap.verisign.com/com/v1/"]]],
            "_fetched_at": 9_999_999_999,
        }
        result = _find_server("com", bootstrap)
        # "com" is still in the list; valid entry must still resolve
        assert result == "https://rdap.verisign.com/com/v1/"

    def test_services_entry_is_not_list(self):
        """services list contains a non-list entry (e.g. string) — must skip."""
        bootstrap = {
            "services": ["unexpected_string"],
            "_fetched_at": 9_999_999_999,
        }
        result = _find_server("com", bootstrap)
        assert result is None


# ---------------------------------------------------------------------------
# RDAPEnricher — external RDAP JSON can be malformed
# ---------------------------------------------------------------------------

class TestRDAPEnricherRobustness:
    """RDAPEnricher.enrich() must return [] (or valid signals) on malformed data."""

    # ---- top-level response type ----

    def test_rdap_response_is_list_not_dict(self):
        """RDAP endpoint returns a JSON list instead of dict — fail-open."""
        enricher = RDAPEnricher()
        with patch("barb.enrichers.rdap._load_bootstrap", return_value=_SAMPLE_BOOTSTRAP), \
             patch("urllib.request.urlopen", return_value=_rdap_response([{"events": []}])):
            signals = enricher.enrich(_parsed("https://evil.com"))
        assert signals == []

    # ---- events array malformed ----

    def test_rdap_event_is_none(self):
        """events list contains None — previously AttributeError on None.get()."""
        enricher = RDAPEnricher()
        data = {"events": [None]}
        with patch("barb.enrichers.rdap._load_bootstrap", return_value=_SAMPLE_BOOTSTRAP), \
             patch("urllib.request.urlopen", return_value=_rdap_response(data)):
            signals = enricher.enrich(_parsed("https://evil.com"))
        assert signals == []

    def test_rdap_event_is_string(self):
        """events list contains a string — must skip without error."""
        enricher = RDAPEnricher()
        data = {"events": ["registration"]}
        with patch("barb.enrichers.rdap._load_bootstrap", return_value=_SAMPLE_BOOTSTRAP), \
             patch("urllib.request.urlopen", return_value=_rdap_response(data)):
            signals = enricher.enrich(_parsed("https://evil.com"))
        assert signals == []

    def test_rdap_event_date_is_int_epoch(self):
        """eventDate is an int (Unix epoch) — previously AttributeError on int.replace()."""
        enricher = RDAPEnricher()
        data = {"events": [{"eventAction": "registration", "eventDate": 1_700_000_000}]}
        with patch("barb.enrichers.rdap._load_bootstrap", return_value=_SAMPLE_BOOTSTRAP), \
             patch("urllib.request.urlopen", return_value=_rdap_response(data)):
            signals = enricher.enrich(_parsed("https://evil.com"))
        # int date skipped → no registration-age signal
        age_signals = [s for s in signals if "registered" in s.label.lower()]
        assert age_signals == []

    def test_rdap_event_date_is_dict(self):
        """eventDate is a dict — previously AttributeError on dict.replace()."""
        enricher = RDAPEnricher()
        data = {"events": [{"eventAction": "registration", "eventDate": {"value": "2024-01-01"}}]}
        with patch("barb.enrichers.rdap._load_bootstrap", return_value=_SAMPLE_BOOTSTRAP), \
             patch("urllib.request.urlopen", return_value=_rdap_response(data)):
            signals = enricher.enrich(_parsed("https://evil.com"))
        age_signals = [s for s in signals if "registered" in s.label.lower()]
        assert age_signals == []

    # ---- remarks array malformed ----

    def test_rdap_remark_is_none(self):
        """remarks list contains None — previously AttributeError on None.get()."""
        enricher = RDAPEnricher()
        data = {"remarks": [None]}
        with patch("barb.enrichers.rdap._load_bootstrap", return_value=_SAMPLE_BOOTSTRAP), \
             patch("urllib.request.urlopen", return_value=_rdap_response(data)):
            signals = enricher.enrich(_parsed("https://evil.com"))
        assert signals == []

    def test_rdap_remark_is_int(self):
        """remarks list contains an int — previously AttributeError."""
        enricher = RDAPEnricher()
        data = {"remarks": [42]}
        with patch("barb.enrichers.rdap._load_bootstrap", return_value=_SAMPLE_BOOTSTRAP), \
             patch("urllib.request.urlopen", return_value=_rdap_response(data)):
            signals = enricher.enrich(_parsed("https://evil.com"))
        assert signals == []

    def test_rdap_remark_description_is_int(self):
        """description is an int (non-iterable) — previously TypeError."""
        enricher = RDAPEnricher()
        data = {"remarks": [{"description": 42}]}
        with patch("barb.enrichers.rdap._load_bootstrap", return_value=_SAMPLE_BOOTSTRAP), \
             patch("urllib.request.urlopen", return_value=_rdap_response(data)):
            signals = enricher.enrich(_parsed("https://evil.com"))
        # Non-list description skipped; no false privacy signal raised
        privacy_signals = [s for s in signals if "privacy" in s.label.lower()]
        assert privacy_signals == []

    def test_rdap_remark_description_as_string_handled_gracefully(self):
        """A non-list (str) description is skipped — no crash, no signal.

        RFC 7483 remarks.description is a list of strings; a bare string is
        malformed. The isinstance(description, list) guard skips it. (The
        crash-inducing int/None case is covered by
        test_rdap_remark_description_is_int.)
        """
        enricher = RDAPEnricher()
        data = {"remarks": [{"description": "REDACTED FOR PRIVACY"}]}
        with patch("barb.enrichers.rdap._load_bootstrap", return_value=_SAMPLE_BOOTSTRAP), \
             patch("urllib.request.urlopen", return_value=_rdap_response(data)):
            signals = enricher.enrich(_parsed("https://evil.com"))
        privacy_signals = [s for s in signals if "privacy" in s.label.lower()]
        assert privacy_signals == []

    # ---- valid-data behaviour must be preserved ----

    def test_rdap_valid_registration_still_signals(self):
        """Valid eventDate string still produces a registration-age signal (no regression)."""
        enricher = RDAPEnricher()
        reg_date = (datetime.now(timezone.utc) - timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
        data = {"events": [{"eventAction": "registration", "eventDate": reg_date}]}
        with patch("barb.enrichers.rdap._load_bootstrap", return_value=_SAMPLE_BOOTSTRAP), \
             patch("urllib.request.urlopen", return_value=_rdap_response(data)):
            signals = enricher.enrich(_parsed("https://evil.com"))
        assert any(s.severity == SignalSeverity.HIGH for s in signals)

    def test_rdap_valid_privacy_remark_still_signals(self):
        """Valid remarks list-of-strings still triggers the privacy signal (no regression)."""
        enricher = RDAPEnricher()
        data = {"remarks": [{"description": ["REDACTED FOR PRIVACY"]}]}
        with patch("barb.enrichers.rdap._load_bootstrap", return_value=_SAMPLE_BOOTSTRAP), \
             patch("urllib.request.urlopen", return_value=_rdap_response(data)):
            signals = enricher.enrich(_parsed("https://evil.com"))
        privacy_signals = [s for s in signals if "privacy" in s.label.lower()]
        assert len(privacy_signals) == 1
        assert privacy_signals[0].severity == SignalSeverity.LOW


# ---------------------------------------------------------------------------
# CrtShEnricher — external crt.sh JSON can be malformed
# ---------------------------------------------------------------------------

class TestCrtShEnricherRobustness:
    """CrtShEnricher.enrich() must return [] on malformed external data."""

    def test_crtsh_response_is_dict_not_list(self):
        """crt.sh returns a JSON dict (e.g. rate-limit error) instead of list — fail-open."""
        enricher = CrtShEnricher()
        with patch("urllib.request.urlopen",
                   return_value=_crtsh_response({"error": "rate limited"})):
            signals = enricher.enrich(_parsed("https://evil.com"))
        assert signals == []

    def test_crtsh_response_is_null_json(self):
        """crt.sh returns JSON null — not a list → fail-open with []."""
        enricher = CrtShEnricher()
        with patch("urllib.request.urlopen", return_value=_crtsh_response(None)):
            signals = enricher.enrich(_parsed("https://evil.com"))
        # null → isinstance(None, list) is False → defensive return []
        assert signals == []

    def test_crtsh_entry_is_none(self):
        """entries list contains a None element — previously AttributeError on None.get()."""
        enricher = CrtShEnricher()
        recent = (datetime.now(timezone.utc) - timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%S")
        entries = [None, {"not_before": recent, "name_value": "evil.com", "id": 1}]
        with patch("urllib.request.urlopen", return_value=_crtsh_response(entries)):
            signals = enricher.enrich(_parsed("https://evil.com"))
        # None entry skipped; valid entry still processed → MEDIUM signal
        assert len(signals) == 1
        assert signals[0].severity == SignalSeverity.MEDIUM

    def test_crtsh_entry_is_int(self):
        """entries list contains an int — must skip without error."""
        enricher = CrtShEnricher()
        entries = [42, 99]
        with patch("urllib.request.urlopen", return_value=_crtsh_response(entries)):
            signals = enricher.enrich(_parsed("https://evil.com"))
        assert signals == []

    def test_crtsh_all_null_entries_returns_empty(self):
        """All entries are None — no valid dates → return []."""
        enricher = CrtShEnricher()
        entries = [None, None, None]
        with patch("urllib.request.urlopen", return_value=_crtsh_response(entries)):
            signals = enricher.enrich(_parsed("https://evil.com"))
        assert signals == []

    # ---- valid-data regression guards ----

    def test_crtsh_valid_recent_cert_still_signals(self):
        """Valid entries still produce a MEDIUM signal (no regression)."""
        enricher = CrtShEnricher()
        recent = (datetime.now(timezone.utc) - timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%S")
        entries = [{"not_before": recent, "name_value": "evil.com", "id": 1}]
        with patch("urllib.request.urlopen", return_value=_crtsh_response(entries)):
            signals = enricher.enrich(_parsed("https://evil.com"))
        assert len(signals) == 1
        assert signals[0].severity == SignalSeverity.MEDIUM
