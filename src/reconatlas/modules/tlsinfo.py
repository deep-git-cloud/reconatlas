"""TLS certificate inspection using the standard library only."""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Any

from ..models import Finding
from .base import finding


def _parse_cert(cert: dict[str, Any]) -> dict[str, Any]:
    """Normalise the dict returned by ``ssl._test_decode_cert``."""
    out: dict[str, Any] = {}
    out["subject"] = _flatten(cert.get("subject"))
    out["issuer"] = _flatten(cert.get("issuer"))
    out["not_before"] = cert.get("notBefore")
    out["not_after"] = cert.get("notAfter")
    out["serial"] = cert.get("serialNumber")
    out["version"] = cert.get("version")
    out["sig_algo"] = cert.get("sigAlgName")
    out["alt_names"] = [value for key, value in _pairs(cert.get("subjectAltName")) if key == "DNS"]
    return out


def _is_pair(node: Any) -> bool:
    return (
        isinstance(node, (tuple, list))
        and len(node) == 2
        and isinstance(node[0], str)
        and isinstance(node[1], str)
    )


def _pairs(value: Any) -> list[tuple[str, str]]:
    """Flatten the certificate's arbitrarily nested tuples into pairs.

    ``_test_decode_cert`` returns structures such as
    ``((('commonName', 'example.com'),),)`` for the subject but a flat
    ``(('DNS', 'example.com'),)`` for the alternative names, so the
    nesting depth is not consistent and has to be walked generically.
    """
    out: list[tuple[str, str]] = []
    if value is None:
        return out
    if isinstance(value, dict):
        return [(str(k), str(v)) for k, v in value.items()]
    if _is_pair(value):
        return [(str(value[0]), str(value[1]))]
    if isinstance(value, (tuple, list)):
        for item in value:
            out.extend(_pairs(item))
    return out


def _flatten(value: Any) -> dict[str, str]:
    """Turn the certificate's nested tuples into a flat string dict."""
    return {key: val for key, val in _pairs(value)}


def fetch_certificate(host: str, port: int = 443, timeout: float = 10.0) -> tuple[dict[str, Any] | None, str]:
    """Retrieve and parse the TLS certificate presented by *host*."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
                version = tls.version()
                cipher = tls.cipher()
    except (OSError, ssl.SSLError) as exc:
        return None, f"{type(exc).__name__}: {exc}"

    if not der:
        return None, "no certificate returned"

    # ``_test_decode_cert`` only accepts a path, so decode through a temp file.
    import os
    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as handle:
        handle.write(ssl.DER_cert_to_PEM_cert(der).encode("utf-8"))
        pem_path = handle.name
    try:
        cert = ssl._ssl._test_decode_cert(pem_path)  # type: ignore[attr-defined]
    except Exception as exc:  # noqa: BLE001
        return None, f"could not parse certificate: {exc}"
    finally:
        try:
            os.unlink(pem_path)
        except OSError:
            pass

    parsed = _parse_cert(cert)
    parsed["tls_version"] = version
    parsed["cipher"] = cipher[0] if cipher else ""
    return parsed, ""


def collect_tls(host: str, port: int = 443) -> tuple[list[Finding], dict[str, Any]]:
    """Describe the TLS certificate served by *host*."""
    findings: list[Finding] = []
    cert, error = fetch_certificate(host, port)
    if not cert:
        return findings, {"error": error}

    subject = cert.get("subject", {})
    issuer = cert.get("issuer", {})
    summary: dict[str, Any] = {
        "tls_version": cert.get("tls_version", ""),
        "cipher": cert.get("cipher", ""),
    }

    common = subject.get("commonName")
    if common:
        findings.append(finding("tls", "Common name", common, source="TLS handshake"))
        summary["common_name"] = common
    if subject.get("organizationName"):
        findings.append(
            finding("tls", "Organisation", subject["organizationName"], source="TLS handshake")
        )
    if issuer.get("organizationName") or issuer.get("commonName"):
        issuer_name = issuer.get("organizationName") or issuer.get("commonName", "")
        findings.append(finding("tls", "Issuer", issuer_name, source="TLS handshake"))
        summary["issuer"] = issuer_name

    for label, key in (("Valid from", "not_before"), ("Valid until", "not_after")):
        value = cert.get(key)
        if value:
            findings.append(finding("tls", label, str(value), source="TLS handshake"))
            summary[key] = value

    alt = cert.get("alt_names") or []
    if alt:
        for name in alt[:40]:
            findings.append(finding("tls", "SAN", name, source="TLS handshake"))
        summary["alt_name_count"] = len(alt)

    if cert.get("sig_algo"):
        findings.append(finding("tls", "Signature algorithm", cert["sig_algo"], source="TLS handshake"))

    # Expiry warning
    expires = cert.get("not_after")
    if expires:
        try:
            expiry = datetime.strptime(str(expires), "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc
            )
            days = (expiry - datetime.now(timezone.utc)).days
            if days < 0:
                findings.append(
                    finding("tls", "Expiry", f"expired {abs(days)} days ago",
                            source="TLS handshake", severity="risk")
                )
            elif days <= 14:
                findings.append(
                    finding("tls", "Expiry", f"expires in {days} days",
                            source="TLS handshake", severity="warn")
                )
            else:
                findings.append(
                    finding("tls", "Expiry", f"{days} days remaining",
                            source="TLS handshake", severity="good")
                )
            summary["days_until_expiry"] = days
        except (ValueError, TypeError):
            pass

    return findings, summary
