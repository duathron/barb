"""Configuration system for phishing-analyzer.

Priority hierarchy: CLI flags > env vars > ~/.phishing-analyzer/config.yaml > defaults.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel


_APP_DIR = Path.home() / ".phishing-analyzer"
_DIR_MODE = 0o700
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


class OutputConfig(BaseModel):
    """Output configuration."""

    default_format: str = "rich"
    quiet: bool = False
    defang: bool = True


class UpdateCheckConfig(BaseModel):
    """Version update check configuration."""

    enabled: bool = True
    check_interval_hours: int = 24


class AppConfig(BaseModel):
    """Top-level application configuration."""

    scoring: ScoringConfig = ScoringConfig()
    explain: ExplainConfig = ExplainConfig()
    output: OutputConfig = OutputConfig()
    update_check: UpdateCheckConfig = UpdateCheckConfig()


def _ensure_app_dir() -> Path:
    """Create application directory with secure permissions."""
    _APP_DIR.mkdir(mode=_DIR_MODE, parents=True, exist_ok=True)
    return _APP_DIR


def load_config(config_path: Optional[Path] = None) -> AppConfig:
    """Load configuration from YAML file with env var overrides."""
    data: dict = {}

    # Load from file
    paths = [p for p in [config_path, _APP_DIR / "config.yaml", Path("config.yaml")] if p and p.exists()]
    if paths:
        with open(paths[0]) as f:
            data = yaml.safe_load(f) or {}

    config = AppConfig(**data)

    # Env var overrides
    llm_key = os.getenv("PHISHING_ANALYZER_LLM_KEY")
    if llm_key:
        config.explain.api_key = llm_key

    return config
