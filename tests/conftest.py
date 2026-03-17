"""Shared test fixtures for barb."""

from __future__ import annotations

import pytest

from barb.config import AppConfig
from barb.url_parser import parse_url


@pytest.fixture
def default_config() -> AppConfig:
    """Default application configuration for tests."""
    return AppConfig()


@pytest.fixture
def safe_url():
    """A clearly safe URL."""
    return parse_url("https://www.google.com/search?q=test")


@pytest.fixture
def phishing_url():
    """A clearly phishing URL."""
    return parse_url("http://192.168.1.1/paypal-login/secure/verify")
