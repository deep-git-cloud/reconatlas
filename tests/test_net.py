"""Tests for the network value helpers."""

from __future__ import annotations

import pytest

from reconatlas.util.net import (
    base_domain,
    host_of,
    is_domain,
    is_email,
    is_ip,
    is_private_ip,
    is_username,
    normalize_url,
    registrable_domain,
)


@pytest.mark.parametrize(
    "value,expected",
    [
        ("example.com", True),
        ("sub.example.co.uk", True),
        ("localhost", False),
        ("not a domain", False),
        ("-bad.com", False),
        ("example.com.", True),
    ],
)
def test_is_domain(value: str, expected: bool) -> None:
    assert is_domain(value) is expected


@pytest.mark.parametrize(
    "value,expected",
    [
        ("8.8.8.8", True),
        ("2001:4860:4860::8888", True),
        ("example.com", False),
        ("999.1.1.1", False),
    ],
)
def test_is_ip(value: str, expected: bool) -> None:
    assert is_ip(value) is expected


@pytest.mark.parametrize(
    "value,expected",
    [
        ("user@example.com", True),
        ("user.name+tag@mail.co.uk", True),
        ("not-an-email", False),
        ("@example.com", False),
    ],
)
def test_is_email(value: str, expected: bool) -> None:
    assert is_email(value) is expected


@pytest.mark.parametrize(
    "value,expected",
    [("torvalds", True), ("a.b", True), ("x", False), ("has space", False)],
)
def test_is_username(value: str, expected: bool) -> None:
    assert is_username(value) is expected


@pytest.mark.parametrize(
    "value,expected",
    [
        ("www.example.com", "example.com"),
        ("example.com", "example.com"),
        ("a.b.example.co.uk", "example.co.uk"),
        ("shop.example.com.au", "example.com.au"),
        ("8.8.8.8", "8.8.8.8"),
    ],
)
def test_registrable_domain(value: str, expected: str) -> None:
    assert registrable_domain(value) == expected


def test_host_of() -> None:
    assert host_of("https://www.example.com/path?q=1") == "www.example.com"
    assert host_of("example.com") == "example.com"


def test_base_domain() -> None:
    assert base_domain("https://deep.sub.example.com/x") == "example.com"


@pytest.mark.parametrize(
    "value,expected",
    [
        ("example.com", "https://example.com/"),
        ("http://example.com", "http://example.com/"),
        ("https://example.com/a?b=1", "https://example.com/a?b=1"),
    ],
)
def test_normalize_url(value: str, expected: str) -> None:
    assert normalize_url(value) == expected


def test_is_private_ip() -> None:
    assert is_private_ip("192.168.1.1")
    assert is_private_ip("127.0.0.1")
    assert not is_private_ip("8.8.8.8")
