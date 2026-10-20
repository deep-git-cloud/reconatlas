"""Tests for the web probe parsing helpers and the TLS certificate parser."""

from __future__ import annotations

from reconatlas.modules.tlsinfo import _flatten, _pairs, _parse_cert
from reconatlas.modules.webprobe import _fingerprint, _meta_tags, _title


def test_title_extraction() -> None:
    assert _title("<html><title>  Hello   World </title></html>") == "Hello World"
    assert _title("<html><body>no title</body></html>") == ""


def test_meta_tags_in_both_attribute_orders() -> None:
    html = (
        '<meta name="description" content="first">'
        '<meta content="second" name="keywords">'
    )
    meta = _meta_tags(html)
    assert meta["description"] == "first"
    assert meta["keywords"] == "second"


def test_fingerprint_detects_server_and_frameworks() -> None:
    headers = {"Server": "nginx/1.24.0", "X-Powered-By": "PHP/8.2.0"}
    body = '<script src="/_next/static/app.js"></script>'
    tech = dict(_fingerprint(headers, body))
    assert "nginx" in tech.get("Web server", "")
    assert tech.get("Detected") == "Next.js"


def test_fingerprint_has_no_duplicate_web_server_entry() -> None:
    headers = {"Server": "cloudflare", "CF-Ray": "123abc"}
    labels = [label for label, _ in _fingerprint(headers, "")]
    assert labels.count("Web server") == 1


def test_tls_subject_is_a_nested_tuple() -> None:
    cert = {
        "subject": ((("commonName", "*.example.com"),),),
        "issuer": ((("organizationName", "Let's Encrypt"),), (("commonName", "YE2"),)),
        "notBefore": "Jan  1 00:00:00 2026 GMT",
        "notAfter": "Apr  1 00:00:00 2026 GMT",
        "serialNumber": "01",
        "version": 3,
        "sigAlgName": "SHA256-RSA",
        "subjectAltName": (("DNS", "a.example.com"), ("DNS", "b.example.com")),
    }
    parsed = _parse_cert(cert)
    assert parsed["subject"]["commonName"] == "*.example.com"
    assert parsed["issuer"]["organizationName"] == "Let's Encrypt"
    assert parsed["issuer"]["commonName"] == "YE2"
    assert parsed["alt_names"] == ["a.example.com", "b.example.com"]


def test_pairs_flattens_both_shapes() -> None:
    assert _pairs((("DNS", "a.example.com"),)) == [("DNS", "a.example.com")]
    assert _pairs(((("commonName", "x"),),)) == [("commonName", "x")]
    assert _pairs(None) == []
    assert _flatten({"k": "v"}) == {"k": "v"}
