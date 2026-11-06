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


def test_cwd_config_is_ignored(tmp_path, monkeypatch):
    """A ./config.yaml in the working directory must never influence the config."""
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    (cwd / "config.yaml").write_text(
        textwrap.dedent(
            """\
            output:
              default_format: json
            explain:
              ollama_host: http://attacker.example:11434
            scoring:
              thresholds:
                phishing: 99
            """
        )
    )
    monkeypatch.chdir(cwd)
    empty_app = tmp_path / "app"
    empty_app.mkdir()
    monkeypatch.setattr(barb.config, "_APP_DIR", empty_app)

    cfg = load_config()

    assert cfg.output.default_format == "rich"
    assert cfg.explain.ollama_host == "http://localhost:11434"
    assert cfg.scoring.thresholds.phishing == 13


def test_user_config_precedes_nothing_in_cwd(tmp_path, monkeypatch):
    """With both a user config and a CWD file present, only the user file counts."""
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    (cwd / "config.yaml").write_text("output:\n  default_format: console\n")
    appdir = tmp_path / "app"
    appdir.mkdir()
    (appdir / "config.yaml").write_text("output:\n  default_format: json\n")
    monkeypatch.chdir(cwd)
    monkeypatch.setattr(barb.config, "_APP_DIR", appdir)

    assert load_config().output.default_format == "json"


def test_env_override(tmp_path, monkeypatch):
    """BARB_LLM_KEY env var overrides explain.api_key."""
    monkeypatch.setenv("BARB_LLM_KEY", "sekret")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.setattr(barb.config, "_APP_DIR", tmp_path / ".barb")

    assert load_config().explain.api_key == "sekret"


_PHISH = "http://paypal.secure-login.verify-account.update.xyz/login/account/verify.exe.zip"


def _cli_env(tmp_path, monkeypatch):
    """Isolated HOME/app dir for CLI tests; returns the app dir."""
    appdir = tmp_path / "app"
    appdir.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "home"))
    monkeypatch.setattr(barb.config, "_APP_DIR", appdir)
    monkeypatch.delenv("BARB_LLM_KEY", raising=False)
    return appdir


def test_analyze_ignores_cwd_config(tmp_path, monkeypatch):
    """A threshold-99 config.yaml in the CWD must not downgrade a phishing verdict."""
    from typer.testing import CliRunner

    from barb.main import app

    _cli_env(tmp_path, monkeypatch)
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    (cwd / "config.yaml").write_text(
        "scoring:\n  thresholds:\n    phishing: 99\n    high_risk: 99\n    suspicious: 99\n"
    )
    monkeypatch.chdir(cwd)

    res = CliRunner().invoke(app, ["analyze", _PHISH, "-o", "json", "-q"])

    assert res.exit_code == 2, res.output
    assert "PHISHING" in res.output


def test_config_show_masks_api_key_from_env(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from barb.main import app

    _cli_env(tmp_path, monkeypatch)
    monkeypatch.setenv("BARB_LLM_KEY", "sk-SECRET123")

    res = CliRunner().invoke(app, ["config", "--show"])

    assert res.exit_code == 0
    assert "sk-SECRET123" not in res.output
    assert "api_key: '***'" in res.output


def test_config_show_masks_api_key_from_file(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from barb.main import app

    appdir = _cli_env(tmp_path, monkeypatch)
    (appdir / "config.yaml").write_text("explain:\n  api_key: sk-FILESECRET456\n")

    res = CliRunner().invoke(app, ["config", "--show"])

    assert res.exit_code == 0
    assert "sk-FILESECRET456" not in res.output
    assert "api_key: '***'" in res.output


def test_config_show_unset_key_stays_null(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from barb.main import app

    _cli_env(tmp_path, monkeypatch)

    res = CliRunner().invoke(app, ["config", "--show"])

    assert res.exit_code == 0
    assert "api_key: null" in res.output


_NUMERIC_KEY = "9876543210123456"


def test_invalid_config_error_does_not_echo_values(tmp_path, monkeypatch):
    """A non-string api_key must not leak into config validation errors."""
    from typer.testing import CliRunner

    from barb.main import app

    appdir = _cli_env(tmp_path, monkeypatch)
    (appdir / "config.yaml").write_text(f"explain:\n  api_key: {_NUMERIC_KEY}\n")

    for args in (["config", "--show"], ["analyze", _PHISH, "-o", "json", "-q"]):
        res = CliRunner().invoke(app, args, color=True)
        shown = res.output + repr(res.exception)
        assert _NUMERIC_KEY not in shown, args
        assert res.exit_code != 0, args
        assert "explain.api_key" in res.output, args
        assert "Traceback" not in res.output, args


_SHAPED_KEY = "sk-SECRETKEY123456"


def test_pretty_exceptions_do_not_show_locals():
    """Defence in depth: a traceback must never dump locals (API key)."""
    from barb.main import app

    assert app.pretty_exceptions_show_locals is False


def test_malformed_or_non_mapping_config_is_one_line_error(tmp_path, monkeypatch):
    """List-shaped or unparsable YAML must exit 3 without a traceback or the key."""
    from typer.testing import CliRunner

    from barb.main import app

    bodies = (
        f"- explain:\n    api_key: {_SHAPED_KEY}\n",
        f"explain:\n  api_key: {_SHAPED_KEY}: x\n",
    )
    appdir = _cli_env(tmp_path, monkeypatch)
    for body in bodies:
        (appdir / "config.yaml").write_text(body)
        for args in (["config", "--show"], ["analyze", _PHISH, "-o", "json", "-q"]):
            res = CliRunner().invoke(app, args, color=True)
            shown = res.output + repr(res.exception)
            assert res.exit_code == 3, (body, args, shown)
            assert "Traceback" not in shown, (body, args)
            assert _SHAPED_KEY not in shown, (body, args)
            assert "Error:" in shown, (body, args)


def test_config_show_redacts_ollama_userinfo(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from barb.main import app

    appdir = _cli_env(tmp_path, monkeypatch)
    (appdir / "config.yaml").write_text("explain:\n  ollama_host: http://user:pass@host:11434\n")

    res = CliRunner().invoke(app, ["config", "--show"])

    assert res.exit_code == 0
    assert "user:pass" not in res.output
    assert "http://***@host:11434" in res.output
