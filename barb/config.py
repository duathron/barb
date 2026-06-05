"""Configuration system for barb.

Priority hierarchy: CLI flags > env vars > ~/.barb/config.yaml > defaults.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel
from shipwright_kit.config import app_dir
from shipwright_kit.config import load_config as _resolve_config

_APP_DIR = app_dir("barb")  # ~/.barb (path only; created lazily by callers that need it)
_FILE_MODE = 0o600


class ScoringWeights(BaseModel):
    """Per-analyzer scoring weights."""

    entropy: float = 1.0
    homoglyph: float = 1.5
    tld: float = 1.0
    subdomain: float = 1.0
    brand: float = 1.2
    shortener: float = 0.8
    encoding: float = 1.0
    ip_url: float = 1.0
    typosquat: float = 1.3
    keyword: float = 0.6
    lexical: float = 0.5
    file_ext: float = 1.0


class ScoringThresholds(BaseModel):
    """Risk score thresholds for verdict tiers."""

    low_risk: int = 1
    suspicious: int = 4
    high_risk: int = 8
    phishing: int = 13


class ScoringConfig(BaseModel):
    """Scoring configuration."""

    weights: ScoringWeights = ScoringWeights()
    thresholds: ScoringThresholds = ScoringThresholds()


class ExplainConfig(BaseModel):
    """LLM explanation configuration."""

    provider: str = "template"
    model: Optional[str] = None
    api_key: Optional[str] = None
    send_url: bool = True
    ollama_host: str = "http://localhost:11434"


class OutputConfig(BaseModel):
    """Output configuration."""

    default_format: str = "rich"
    quiet: bool = False
    defang: bool = True


class UpdateCheckConfig(BaseModel):
    """Version update check configuration."""

    enabled: bool = True
    check_interval_hours: int = 24


class OsintConfig(BaseModel):
    """OSINT enrichment configuration (opt-in, network-dependent)."""

    dns_timeout: float = 2.0
    rdap_timeout: float = 5.0
    crtsh_timeout: float = 8.0
    asn_timeout: float = 3.0
    cache_ttl_hours: int = 6


class AppConfig(BaseModel):
    """Top-level application configuration."""

    scoring: ScoringConfig = ScoringConfig()
    explain: ExplainConfig = ExplainConfig()
    output: OutputConfig = OutputConfig()
    update_check: UpdateCheckConfig = UpdateCheckConfig()
    osint: OsintConfig = OsintConfig()


def _ensure_app_dir() -> Path:
    """Create application directory with secure permissions."""
    return app_dir("barb", create=True)


def _load_yaml(path: Path) -> dict:
    with open(path) as f:
        return yaml.safe_load(f) or {}


def load_config(config_path: Optional[Path] = None) -> AppConfig:
    """Load configuration from YAML file with env var overrides."""
    config = _resolve_config(
        [config_path, _APP_DIR / "config.yaml", Path("config.yaml")],
        loader=_load_yaml,
        validator=lambda data: AppConfig(**data),
    )

    # Env var overrides
    llm_key = os.getenv("BARB_LLM_KEY")
    if llm_key:
        config.explain.api_key = llm_key

    return config
