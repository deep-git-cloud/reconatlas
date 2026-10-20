"""Tests for the Wayback and subdomain collectors."""

from __future__ import annotations

from reconatlas.http import Fetch
from reconatlas.modules.subdomains import _describe_failure, _is_valid_host
from reconatlas.modules.wayback import _timestamps


def test_describe_failure_reports_status() -> None:
    fetch = Fetch(url="x", status=502, ok=False)
    assert "502" in _describe_failure(fetch)


def test_describe_failure_includes_api_message() -> None:
    fetch = Fetch(
        url="x",
        status=429,
        ok=False,
        text='{"code":"rate_limited","message":"You have exceeded your quota"}',
    )
    described = _describe_failure(fetch)
    assert "429" in described
    assert "exceeded your quota" in described


def test_describe_failure_reports_connection_error() -> None:
    fetch = Fetch(url="x", error="ConnectionTimeout: timed out")
    assert "timed out" in _describe_failure(fetch)


def test_valid_host_filter() -> None:
    assert _is_valid_host("www.example.com", "example.com")
    assert not _is_valid_host("example.com.evil.org", "example.com")
    assert not _is_valid_host("", "example.com")
    assert not _is_valid_host("www.example.com", "other.com")


def test_timestamps_returns_empty_on_bad_payload(http, monkeypatch) -> None:
    monkeypatch.setattr(http, "get_json", lambda *a, **k: {"error": "nope"})
    assert _timestamps(http, "example.com", 10) == []


def test_timestamps_pulls_the_data_rows(http, monkeypatch) -> None:
    payload = [["timestamp"], ["20020120142510"], ["20240101000000"]]
    monkeypatch.setattr(http, "get_json", lambda *a, **k: payload)
    assert _timestamps(http, "example.com", 10) == ["20020120142510", "20240101000000"]


def test_timestamps_uses_reverse_sort_for_latest(http, monkeypatch) -> None:
    seen: dict = {}

    def fake_get_json(url, **kwargs):
        seen.update(kwargs.get("params", {}))
        return [["timestamp"], ["20240101000000"]]

    monkeypatch.setattr(http, "get_json", fake_get_json)
    _timestamps(http, "example.com", 1, reverse=True)
    assert seen["sort"] == "reverse"
    assert seen["limit"] == "1"
