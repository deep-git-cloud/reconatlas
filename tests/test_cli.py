"""Tests for the command line interface using a stubbed HTTP layer."""

from __future__ import annotations

import json

from click.testing import CliRunner

from reconatlas.cli import cli


def _runner() -> CliRunner:
    return CliRunner()


def test_help_lists_every_command() -> None:
    result = _runner().invoke(cli, ["--help"])
    assert result.exit_code == 0
    for command in (
        "domain", "dns", "subdomains", "ip", "web", "tls",
        "email", "username", "exif", "dorks", "breaches", "wayback", "report",
    ):
        assert command in result.output


def test_dorks_command_runs_offline() -> None:
    result = _runner().invoke(cli, ["dorks", "example.com", "--summary"])
    assert result.exit_code == 0
    assert "dorks" in result.output


def test_platforms_command() -> None:
    result = _runner().invoke(cli, ["platforms"])
    assert result.exit_code == 0
    assert "GitHub" in result.output


def test_dorks_json_export(tmp_path) -> None:
    out = tmp_path / "dorks.json"
    result = _runner().invoke(cli, ["dorks", "example.com", "--json", str(out), "--quiet"])
    assert result.exit_code == 0
    data = json.loads(out.read_text())
    assert data["target"] == "example.com"
    assert data["modules"]["dorks"]["findings"]


def test_invalid_domain_is_rejected() -> None:
    result = _runner().invoke(cli, ["dns", "not a domain"])
    assert result.exit_code != 0


def test_invalid_ip_is_rejected() -> None:
    result = _runner().invoke(cli, ["ip", "999.999.999.999"])
    assert result.exit_code != 0


def test_unknown_platform_is_rejected() -> None:
    result = _runner().invoke(cli, ["username", "someone", "--platform", "nosuchsite"])
    assert result.exit_code != 0
    assert "Unknown platform" in result.output


def test_exif_requires_an_existing_file() -> None:
    result = _runner().invoke(cli, ["exif", "/nonexistent/file.jpg"])
    assert result.exit_code != 0
