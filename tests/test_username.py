"""Tests for the username platform logic that does not need the network."""

from __future__ import annotations

from reconatlas.modules.username import (
    PLATFORMS,
    _control_username,
    _is_inconclusive,
    _looks_like_not_found,
    _page_signals,
    platform_names,
)


def test_platforms_are_unique() -> None:
    names = [p.name for p in PLATFORMS]
    assert len(names) == len(set(names))


def test_platform_urls_contain_the_placeholder() -> None:
    for platform in PLATFORMS:
        assert "{u}" in platform.url


def test_control_username_is_unlikely_to_exist() -> None:
    control = _control_username()
    assert control.startswith("zzq")
    assert len(control) > 10
    assert control != _control_username()


def test_soft_404_markers() -> None:
    assert _looks_like_not_found("<h1>Sorry, this page isn't available.</h1>")
    assert _looks_like_not_found("<title>404 Not Found</title>")
    assert not _looks_like_not_found("<title>Real profile</title>")


def test_page_signals_detect_canonical() -> None:
    html = '<link rel="canonical" href="https://example.com/torvalds">'
    signals = _page_signals(html, "https://example.com/torvalds", "torvalds")
    assert signals["canonical_has_handle"] is True
    assert signals["url_has_handle"] is True


def test_page_signals_detect_og_url() -> None:
    html = '<meta property="og:url" content="https://example.com/torvalds">'
    signals = _page_signals(html, "https://example.com/", "torvalds")
    assert signals["og_url_has_handle"] is True
    assert signals["url_is_generic"] is True


def test_page_signals_generic_landing_page() -> None:
    signals = _page_signals("<html>hi</html>", "https://example.com/login", "torvalds")
    assert signals["url_is_generic"] is True
    assert signals["body_has_handle"] is False


def test_inconclusive_detection() -> None:
    assert _is_inconclusive("blocked (HTTP 403) - status unknown", {})
    assert _is_inconclusive("inconclusive: page is indistinguishable", {})
    assert _is_inconclusive("", {})
    assert not _is_inconclusive("404", {})
    assert not _is_inconclusive("soft-404 page", {})


def test_platform_names_helper() -> None:
    names = platform_names()
    assert "GitHub" in names
    assert "Reddit" in names
