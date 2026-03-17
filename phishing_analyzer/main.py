"""Typer CLI application for phishing-analyzer."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Annotated, Optional

import typer

app = typer.Typer(
    name="phishing-analyzer",
    help="Heuristic phishing URL analyzer for SOC/DFIR workflows.",
    no_args_is_help=True,
)


@app.command()
def analyze(
    urls: Annotated[Optional[list[str]], typer.Argument(help="One or more URLs to analyze")] = None,
    file: Annotated[Optional[Path], typer.Option("--file", "-f", help="File containing URLs (one per line)")] = None,
    output: Annotated[str, typer.Option("--output", "-o", help="Output format: rich|console|json|csv")] = "rich",
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="Suppress banner")] = False,
    explain: Annotated[bool, typer.Option("--explain", "-e", help="Add LLM-powered explanation")] = False,
    threshold: Annotated[int, typer.Option("--threshold", "-t", help="Minimum risk score to report")] = 0,
    no_defang: Annotated[bool, typer.Option("--no-defang", help="Disable URL defanging in output")] = False,
) -> None:
    """Analyze one or more URLs for phishing indicators."""
    # TODO: Implement analyze command
    typer.echo("analyze command — not yet implemented")


@app.command()
def config(
    show: Annotated[bool, typer.Option("--show", help="Show current configuration")] = False,
) -> None:
    """View or modify configuration."""
    # TODO: Implement config command
    typer.echo("config command — not yet implemented")


@app.command()
def version() -> None:
    """Show version information."""
    from phishing_analyzer import __version__

    typer.echo(f"phishing-analyzer {__version__}")


def main() -> None:
    """Entry point for the CLI."""
    app()


if __name__ == "__main__":
    main()
