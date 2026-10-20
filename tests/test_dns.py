"""Tests for the DNS record formatting helpers."""

from __future__ import annotations

from reconatlas.modules.dns import TYPE_IDS, _format_rdata, dns_findings, parse_mx, summarise


def test_parse_mx_normal() -> None:
    assert parse_mx("10 mail.example.com.") == (10, "mail.example.com")


def test_parse_mx_null_mx() -> None:
    priority, exchange = parse_mx("0 .")
    assert priority == 0
    assert exchange == ""


def test_parse_mx_garbage() -> None:
    priority, exchange = parse_mx("nonsense")
    assert priority == 0
    assert exchange == "nonsense"


def test_format_rdata_strips_root_label_for_names() -> None:
    assert _format_rdata(TYPE_IDS["NS"], "ns1.example.com.") == "ns1.example.com"
    assert _format_rdata(TYPE_IDS["CNAME"], "target.example.com.") == "target.example.com"


def test_format_rdata_leaves_txt_untouched() -> None:
    # A trailing dot is meaningful in some TXT values.
    assert _format_rdata(TYPE_IDS["TXT"], "some.verification.") == "some.verification."


def test_format_rdata_mx_keeps_priority() -> None:
    assert _format_rdata(TYPE_IDS["MX"], "10 mail.example.com.") == "10 mail.example.com."


def test_dns_findings_flags_spf() -> None:
    findings = dns_findings("example.com", {"TXT": ["v=spf1 -all"]})
    assert len(findings) == 1
    assert findings[0].severity == "good"
    assert "SPF" in findings[0].note


def test_dns_findings_renders_null_mx() -> None:
    findings = dns_findings("example.com", {"MX": ["0 "]})
    assert findings[0].value == "null MX"
    assert findings[0].severity == "warn"


def test_dns_findings_skips_error_bucket() -> None:
    findings = dns_findings("example.com", {"_errors": ["A: boom"], "A": ["1.2.3.4"]})
    assert [f.key for f in findings] == ["A (IPv4 address)"]


def test_summarise_ignores_error_bucket() -> None:
    assert summarise({"A": ["1.2.3.4"], "_errors": ["x"]}) == {"A": 1}
