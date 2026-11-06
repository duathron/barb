"""python-dotenv is not used by barb and must not be a runtime dependency."""

from __future__ import annotations

import ast
import tomllib
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent


def test_no_python_dotenv_import():
    offenders = []
    for py in (_ROOT / "barb").rglob("*.py"):
        tree = ast.parse(py.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            else:
                continue
            if any(n == "dotenv" or n.startswith("dotenv.") for n in names):
                offenders.append(f"{py.relative_to(_ROOT)}:{node.lineno}")
    assert offenders == []


def test_dotenv_not_a_runtime_dependency():
    data = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    deps = data["project"]["dependencies"]
    assert not [d for d in deps if d.lower().replace("_", "-").startswith("python-dotenv")]
