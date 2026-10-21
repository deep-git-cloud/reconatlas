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


def test_satellite_watch_rejects_exports(tmp_path) -> None:
    tle = tmp_path / "catalog.txt"
    tle.write_text(
        "USA 224 (KH-11 14)\n"
        "1 99999U 98067A   26293.54678875  .00016717  00000+0  30777-3 0  9993\n"
        "2 99999  51.6416 247.4627 0006703 130.5360 325.0288 15.49512742 10000\n",
        encoding="utf-8",
    )
    result = _runner().invoke(
        cli,
        ["satellite", "--tle-file", str(tle), "--watch", "1", "--json", str(tmp_path / "x.json")],
    )
    assert result.exit_code != 0
    assert "cannot be combined" in result.output


def test_satellite_viewer_rejects_exports_and_watch(tmp_path) -> None:
    tle = tmp_path / "catalog.txt"
    tle.write_text(
        "USA 224 (KH-11 14)\n"
        "1 99999U 98067A   26293.54678875  .00016717  00000+0  30777-3 0  9993\n"
        "2 99999  51.6416 247.4627 0006703 130.5360 325.0288 15.49512742 10000\n",
        encoding="utf-8",
    )
    base = ["satellite", "--tle-file", str(tle), "--viewer", "--no-browser"]

    result = _runner().invoke(cli, base + ["--json", str(tmp_path / "x.json")])
    assert result.exit_code != 0
    assert "cannot be combined" in result.output

    result = _runner().invoke(cli, base + ["--watch", "1"])
    assert result.exit_code != 0
    assert "cannot be combined" in result.output
