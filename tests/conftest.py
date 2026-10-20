"""Shared pytest fixtures."""

from __future__ import annotations

import pytest

from reconatlas.config import Config
from reconatlas.http import HttpClient


@pytest.fixture
def config(tmp_path) -> Config:
    """A configuration that never touches the network cache or the network."""
    cfg = Config(
        timeout=5.0,
        connect_timeout=3.0,
        retries=0,
        rate_limit=0.0,
        cache_dir=tmp_path / "cache",
        cache_ttl=0,
        no_cache=True,
    )
    return cfg


@pytest.fixture
def http(config) -> HttpClient:
    return HttpClient(config)
