"""Every command's `--help` works and its usage line keeps UPPERCASE argument names.

typer 0.27 changed metavar printing: optional arguments render lowercase
(`[urls]...`, `[topic]`) and required ones brace-wrapped (`{name}`). barb's
usage lines read `[URLS]...` / `[TOPIC]`; these tests pin that on any typer.
"""

from __future__ import annotations

import enum
import re
from typing import Annotated

import pytest
import typer
import typer.main
from typer.testing import CliRunner

from barb.main import _plain_usage_piece, _PlainUsageCommand, app

runner = CliRunner()

_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
_WIDE = {"COLUMNS": "200"}
_ENVS = {
    "plain": _WIDE,
    "force_color": {**_WIDE, "FORCE_COLOR": "1"},
    "no_color": {**_WIDE, "NO_COLOR": "1"},
    "narrow": {"COLUMNS": "40"},
}


def _command_names() -> list[str]:
    group = typer.main.get_command(app)
    return sorted(group.commands)  # type: ignore[attr-defined]


def _usage_line(output: str) -> str:
    """The whole usage statement, joined across wrapped lines, ANSI-free."""
    lines = _ANSI.sub("", output).splitlines()
    for i, line in enumerate(lines):
        if line.strip().startswith("Usage:"):
            parts = [line.strip()]
            for cont in lines[i + 1 :]:
                if not cont.strip():
                    break
                parts.append(cont.strip())
            return " ".join(parts)
    raise AssertionError(f"no 'Usage:' line found in help output: {output!r}")


def _usage(name: str, env: dict[str, str]) -> str:
    result = runner.invoke(app, [name, "--help"], env=env)
    assert result.exception is None or isinstance(result.exception, SystemExit), repr(result.exception)
    assert result.exit_code == 0, result.output
    return _usage_line(result.output)


def test_command_discovery_is_not_empty() -> None:
    assert {"analyze", "config", "update-data", "manual", "version"} <= set(_command_names())


@pytest.mark.parametrize("env_name", sorted(_ENVS))
@pytest.mark.parametrize("name", _command_names())
def test_usage_line_has_no_placeholder_or_lowercase_argument(name: str, env_name: str) -> None:
    usage = _usage(name, _ENVS[env_name])
    assert "{" not in usage and "}" not in usage, usage
    # Everything after "[OPTIONS]" is an argument placeholder: none may be lowercase.
    tail = usage.split("[OPTIONS]", 1)[-1] if "[OPTIONS]" in usage else ""
    assert tail == tail.upper(), usage


@pytest.mark.parametrize("env_name", sorted(_ENVS))
def test_analyze_usage_ends_with_urls(env_name: str) -> None:
    assert _usage("analyze", _ENVS[env_name]).endswith("[URLS]..."), env_name


@pytest.mark.parametrize("env_name", sorted(_ENVS))
def test_manual_usage_ends_with_topic(env_name: str) -> None:
    assert _usage("manual", _ENVS[env_name]).endswith("[TOPIC]"), env_name


def test_root_help_works() -> None:
    result = runner.invoke(app, ["--help"], env=_WIDE)
    assert result.exit_code == 0, result.output
    assert "{" not in _usage_line(result.output)


def test_usage_line_joins_wrapped_continuation() -> None:
    wrapped = " Usage: barb analyze [OPTIONS]\n [urls]...\n\n Analyze URLs\n"
    assert _usage_line(wrapped) == "Usage: barb analyze [OPTIONS] [urls]..."


class _Fmt(str, enum.Enum):
    json = "json"
    text = "text"


def _throwaway_usage() -> str:
    """Usage line of a throwaway command that uses the barb command class."""
    sandbox = typer.Typer()

    @sandbox.command(cls=_PlainUsageCommand)
    def probe(
        name: Annotated[str, typer.Argument()],
        mode: Annotated[_Fmt, typer.Argument()] = _Fmt.json,
    ) -> None:
        pass

    @sandbox.command()
    def other() -> None:  # a second command keeps `probe` a named subcommand
        pass

    result = runner.invoke(sandbox, ["probe", "--help"], env=_WIDE)
    assert result.exit_code == 0, result.output
    return _usage_line(result.output)


def test_required_argument_is_bare_uppercase_name() -> None:
    usage = _throwaway_usage()
    assert "{" not in usage and "}" not in usage, usage
    assert " NAME " in f"{usage} ", usage


def test_choice_values_keep_their_case() -> None:
    usage = _throwaway_usage()
    assert "json|text" in usage, usage
    assert "JSON" not in usage and "TEXT" not in usage, usage
    assert "MODE" in usage, usage


@pytest.mark.parametrize(
    ("piece", "expected"),
    [
        ("[OPTIONS]", "[OPTIONS]"),
        ("{name}", "NAME"),
        ("[urls]...", "[URLS]..."),
        ("[topic]", "[TOPIC]"),
        ("{req}:<json|text>", "REQ:<json|text>"),
        ("[mode]:<json|text>", "[MODE]:<json|text>"),
        ("URLS...", "URLS..."),
    ],
)
def test_plain_usage_piece_changes_only_the_name(piece: str, expected: str) -> None:
    assert _plain_usage_piece(piece) == expected
