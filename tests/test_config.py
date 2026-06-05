"""Characterization tests for barb config loading.

These lock in the CURRENT behavior of ``load_config`` BEFORE the G4 retrofit
onto ``shipwright_kit.config`` so the refactor can be proven behavior-preserving.

Field names verified against ``barb.config.AppConfig``:
``output.default_format`` (str, default "rich") and
``explain.api_key`` (Optional[str], default None).
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import barb.config
from barb.config import AppConfig, load_config


def test_defaults_when_no_file(tmp_path, monkeypatch):
    """No config file anywhere -> a default AppConfig is returned."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    # _APP_DIR is bound at import time; point it at an empty dir for isolation.
    monkeypatch.setattr(barb.config, "_APP_DIR", tmp_path / ".barb")

    config = load_config()

    assert isinstance(config, AppConfig)
    assert config.output.default_format == "rich"
    assert config.explain.api_key is None


def test_explicit_path_wins(tmp_path, monkeypatch):
    """An explicit config_path is loaded and its values take effect."""
    monkeypatch.setattr(barb.config, "_APP_DIR", tmp_path / ".barb")
    f = tmp_path / "c.yaml"
    f.write_text(textwrap.dedent("output:\n  default_format: json\n"))

    assert load_config(f).output.default_format == "json"


def test_user_config_used(tmp_path, monkeypatch):
    """When no explicit path is given, ~/.barb/config.yaml is used."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    appdir = tmp_path / ".barb"
    appdir.mkdir()
    monkeypatch.setattr(barb.config, "_APP_DIR", appdir)
    (appdir / "config.yaml").write_text("output:\n  default_format: json\n")

    assert load_config().output.default_format == "json"


def test_cwd_config_fallback(tmp_path, monkeypatch):
    """With no explicit path and no ~/.barb/config.yaml, ./config.yaml is used."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    # Point _APP_DIR at a dir with no config.yaml so the cwd file is the fallback.
    monkeypatch.setattr(barb.config, "_APP_DIR", tmp_path / ".barb")
    (tmp_path / "config.yaml").write_text("output:\n  default_format: json\n")

    assert load_config().output.default_format == "json"


def test_env_override(tmp_path, monkeypatch):
    """BARB_LLM_KEY env var overrides explain.api_key."""
    monkeypatch.setenv("BARB_LLM_KEY", "sekret")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.setattr(barb.config, "_APP_DIR", tmp_path / ".barb")

    assert load_config().explain.api_key == "sekret"
