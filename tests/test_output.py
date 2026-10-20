"""Tests for the report model and the exporters."""

from __future__ import annotations

import csv
import json

from reconatlas.models import Finding, ModuleResult, Report
from reconatlas.output import export_csv, export_html, export_json, export_jsonl


def _sample_report() -> Report:
    report = Report(target="example.com", target_type="domain")
    result = ModuleResult(name="dns", status="ok")
    result.add(
        Finding(
            category="dns",
            key="A (IPv4 address)",
            value="1.2.3.4",
            source="dns.google (DoH)",
            severity="info",
        )
    )
    result.add(
        Finding(
            category="breach",
            key="Example",
            value="1,000 accounts",
            source="Have I Been Pwned",
            severity="risk",
            note="2020-01-01",
        )
    )
    report.add(result)
    return report


def test_report_to_dict_round_trips() -> None:
    report = _sample_report()
    data = report.to_dict()
    assert data["target"] == "example.com"
    assert data["modules"]["dns"]["status"] == "ok"
    assert len(data["modules"]["dns"]["findings"]) == 2
    json.loads(report.to_json())


def test_by_category_filters() -> None:
    report = _sample_report()
    assert len(report.by_category("breach")) == 1
    assert report.by_category("nothing") == []


def test_export_json(tmp_path) -> None:
    path = export_json(_sample_report(), tmp_path / "out.json")
    data = json.loads(path.read_text())
    assert data["target"] == "example.com"


def test_export_csv(tmp_path) -> None:
    path = export_csv(_sample_report(), tmp_path / "out.csv")
    rows = list(csv.DictReader(path.open()))
    assert len(rows) == 2
    assert rows[0]["module"] == "dns"
    assert rows[0]["target"] == "example.com"
    assert rows[1]["severity"] == "risk"


def test_export_jsonl(tmp_path) -> None:
    path = export_jsonl(_sample_report(), tmp_path / "out.jsonl")
    lines = [json.loads(line) for line in path.read_text().splitlines() if line]
    assert len(lines) == 2
    assert lines[0]["module"] == "dns"


def test_export_html_escapes_content(tmp_path) -> None:
    report = Report(target="<script>x</script>")
    result = ModuleResult(name="dns")
    result.add(Finding(category="dns", key="<b>k</b>", value="<i>v</i>"))
    report.add(result)
    path = export_html(report, tmp_path / "out.html")
    html = path.read_text()
    assert "<script>x</script>" not in html
    assert "&lt;script&gt;" in html
