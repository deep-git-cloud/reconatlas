"""Tests for the HTTP client: caching, error handling and rate limiting."""

from __future__ import annotations

import json
import time

from reconatlas.config import Config
from reconatlas.http import Fetch, HttpClient


def test_fetch_handles_connection_errors(config) -> None:
    client = HttpClient(config)
    # Reserved TEST-NET-1 address, guaranteed not to answer.
    fetch = client.get("http://192.0.2.1:9/never", timeout=1.0)
    assert fetch.ok is False
    assert fetch.status == 0
    assert fetch.error
    assert fetch.json() is None


def test_cache_round_trip(tmp_path) -> None:
    cfg = Config(cache_dir=tmp_path / "cache", cache_ttl=600, rate_limit=0.0)
    client = HttpClient(cfg)

    path = client._cache_path("https://example.com/api", {"a": 1})
    original = Fetch(
        url="https://example.com/api",
        status=200,
        ok=True,
        text='{"hello": "world"}',
        headers={"Content-Type": "application/json"},
    )
    client._write_cache(path, original)

    restored = client._read_cache(path)
    assert restored is not None
    assert restored.cached is True
    assert restored.ok is True
    assert restored.json() == {"hello": "world"}
    assert restored.header("content-type") == "application/json"


def test_expired_cache_entries_are_ignored(tmp_path) -> None:
    cfg = Config(cache_dir=tmp_path / "cache", cache_ttl=1, rate_limit=0.0)
    client = HttpClient(cfg)
    path = client._cache_path("https://example.com/api", None)
    client._write_cache(path, Fetch(url="https://example.com/api", status=200, ok=True, text="x"))
    assert client._read_cache(path) is not None

    client.cfg.cache_ttl = 0
    assert client._read_cache(path) is None


def test_error_responses_expire_quickly(tmp_path) -> None:
    """A transient failure must not be pinned for the whole cache lifetime."""
    cfg = Config(cache_dir=tmp_path / "cache", cache_ttl=3600, rate_limit=0.0)
    client = HttpClient(cfg)
    path = client._cache_path("https://example.com/api", None)

    client._write_cache(path, Fetch(url="https://example.com/api", status=429, ok=False))
    assert client._read_cache(path) is not None  # still fresh

    # Fast-forward past the short error TTL.
    payload = json.loads(path.read_text())
    payload["expires_at"] = time.time() - 1
    path.write_text(json.dumps(payload))

    assert client._read_cache(path) is None


def test_successful_responses_use_the_full_ttl(tmp_path) -> None:
    cfg = Config(cache_dir=tmp_path / "cache", cache_ttl=3600, rate_limit=0.0)
    client = HttpClient(cfg)
    path = client._cache_path("https://example.com/api", None)
    client._write_cache(path, Fetch(url="https://example.com/api", status=200, ok=True, text="x"))

    payload = json.loads(path.read_text())
    assert payload["expires_at"] > time.time() + 3000


def test_no_cache_bypasses_the_cache(tmp_path) -> None:
    cfg = Config(cache_dir=tmp_path / "cache", cache_ttl=600, no_cache=True, rate_limit=0.0)
    client = HttpClient(cfg)
    path = client._cache_path("https://example.com/api", None)
    client._write_cache(path, Fetch(url="https://example.com/api", status=200, ok=True, text="x"))
    # With caching disabled the file is never written.
    assert not path.exists()


def test_header_lookup_is_case_insensitive() -> None:
    from reconatlas.http import Fetch

    fetch = Fetch(url="x", headers={"Content-Type": "application/json"})
    assert fetch.header("content-type") == "application/json"
    assert fetch.header("missing", "fallback") == "fallback"


def test_rate_limit_spaces_requests(tmp_path) -> None:
    cfg = Config(cache_dir=tmp_path / "c", no_cache=True, rate_limit=0.25)
    client = HttpClient(cfg)
    started = time.monotonic()
    client._throttle.wait("example.com")
    client._throttle.wait("example.com")
    elapsed = time.monotonic() - started
    assert elapsed >= 0.2
