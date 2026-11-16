"""Load the lab modules by path. The lab directories are not Python packages."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load_module(relative: str, name: str):
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def git_lab():
    return SimpleNamespace(
        vuln=load_module("labs/01-git-config-exec/vulnerable.py", "lab01_vuln"),
        fix=load_module("labs/01-git-config-exec/fixed.py", "lab01_fix"),
        fixture=load_module("labs/01-git-config-exec/make_fixture.py", "lab01_fixture"),
    )


@pytest.fixture(scope="module")
def policy_lab():
    return SimpleNamespace(
        vuln=load_module("labs/02-policy-normalization/vulnerable.py", "lab02_vuln"),
        fix=load_module("labs/02-policy-normalization/fixed.py", "lab02_fix"),
    )
