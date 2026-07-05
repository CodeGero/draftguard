"""Test configuration and shared fixtures."""

import os
from pathlib import Path

import pytest


@pytest.fixture
def fixtures_dir() -> Path:
    """Path to the test fixtures directory."""
    return Path(__file__).parent / "fixtures"


@pytest.fixture
def dev_dir(fixtures_dir: Path) -> Path:
    """Path to dev fixtures."""
    return fixtures_dir / "dev"


@pytest.fixture
def staging_dir(fixtures_dir: Path) -> Path:
    """Path to staging fixtures."""
    return fixtures_dir / "staging"


@pytest.fixture
def prod_dir(fixtures_dir: Path) -> Path:
    """Path to prod fixtures."""
    return fixtures_dir / "prod"


@pytest.fixture
def dev_env_file(dev_dir: Path) -> Path:
    return dev_dir / ".env"


@pytest.fixture
def prod_env_file(prod_dir: Path) -> Path:
    return prod_dir / ".env"


@pytest.fixture(autouse=True)
def set_cwd_to_project_root(monkeypatch):
    """Set working directory to project root for all tests."""
    project_root = Path(__file__).parent.parent
    monkeypatch.chdir(project_root)
