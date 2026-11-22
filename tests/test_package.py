"""Packaging settings point at real things. (CI also installs the package and runs it.)"""
import importlib
from pathlib import Path

import pytest

import cryptoinv
from cryptoinv.cli import main
from cryptoinv.rules import DEFAULT_RULES

tomllib = pytest.importorskip("tomllib")   # standard library from Python 3.11
PYPROJECT = tomllib.loads((Path(__file__).parent.parent / "pyproject.toml").read_text(encoding="utf-8"))


def test_command_entry_point_exists():
    module_name, func_name = PYPROJECT["project"]["scripts"]["cryptoinv"].split(":")
    assert callable(getattr(importlib.import_module(module_name), func_name))


def test_rules_file_is_bundled_with_the_package():
    assert DEFAULT_RULES.exists()
    assert DEFAULT_RULES.name in PYPROJECT["tool"]["setuptools"]["package-data"]["cryptoinv"]


def test_version_comes_from_the_code():
    assert "version" in PYPROJECT["project"]["dynamic"]
    assert PYPROJECT["tool"]["setuptools"]["dynamic"]["version"]["attr"] == "cryptoinv.__version__"


def test_scanning_code_needs_no_dependencies():
    assert PYPROJECT["project"]["dependencies"] == []
    assert any(d.startswith("cryptography") for d in PYPROJECT["project"]["optional-dependencies"]["keys"])


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as e:
        main(["--version"])
    assert e.value.code == 0
    assert capsys.readouterr().out.strip() == f"cryptoinv {cryptoinv.__version__}"
