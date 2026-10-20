"""Subdomain discovery from multiple free passive sources.

Sources (all keyless):
  * Cert Spotter  - Certificate Transparency API
  * crt.sh        - Certificate Transparency log (frequently rate limited)
  * HackerTarget  - hostsearch API
  * subdomain.center - aggregated subdomain list
  * AlienVault    - OTX passive DNS
"""

from __future__ import annotations

import re
from typing import Iterable

from ..http import HttpClient
from ..models import Finding
from .base import finding

_SUBDOMAIN_RE = re.compile(r"^[A-Za-z0-9_*-]+(?:\.[A-Za-z0-9_*-]+)*$")


def _is_valid_host(name: str, domain: str) -> bool:
    name = name.strip().lower().rstrip(".")
    if not name or len(name) > 253:
        return False
    if not name.endswith(domain):
        return False
    return bool(_SUBDOMAIN_RE.match(name))


def _certspotter(domain: str, http: HttpClient) -> tuple[set[str], str, str]:
    # The ``domain`` parameter already covers subdomains. Sending
    # ``include_subdomains`` counts against the free tier's domain-search
    # quota and gets the request rate limited, so it is left off.
    #
    # The API also runs a mix of healthy and misconfigured backends, so an
    # identical request can come back 400 "Invalid ctsearch API command"
    # from one node and 200 from the next. Retrying a few times lands on a
    # working node almost every time.
    params = {"domain": domain, "expand": "dns_names"}
    fetch = None
    for _attempt in range(4):
        fetch = http.get("https://api.certspotter.com/v1/issuances", params=params)
        if fetch.ok or fetch.status not in (400,):
            break

    payload = fetch.json() if fetch and fetch.ok else None
    names: set[str] = set()
    if isinstance(payload, list):
        for issuance in payload:
            for name in issuance.get("dns_names", []) or []:
                names.add(str(name).lower())
    return names, "Cert Spotter", "" if names else _describe_failure(fetch)


def _crtsh(domain: str, http: HttpClient) -> tuple[set[str], str, str]:
    fetch = http.get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"})
    payload = fetch.json() if fetch.ok else None
    names: set[str] = set()
    if isinstance(payload, list):
        for entry in payload:
            for name in str(entry.get("name_value", "")).split("\n"):
                cleaned = name.strip().lower().lstrip("*.")
                if cleaned:
                    names.add(cleaned)
    return names, "crt.sh", "" if names else _describe_failure(fetch)


def _hackertarget(domain: str, http: HttpClient) -> tuple[set[str], str, str]:
    fetch = http.get("https://api.hackertarget.com/hostsearch/", params={"q": domain})
    text = fetch.text
    names: set[str] = set()
    if text and not text.startswith("error") and "API count" not in text:
        for line in text.splitlines():
            host = line.split(",")[0].strip().lower()
            if host:
                names.add(host)
    error = "" if names else (_describe_failure(fetch) or text.strip()[:80])
    return names, "HackerTarget", error


def _subdomain_center(domain: str, http: HttpClient) -> tuple[set[str], str, str]:
    fetch = http.get("https://api.subdomain.center/", params={"domain": domain})
    payload = fetch.json() if fetch.ok else None
    names: set[str] = set()
    if isinstance(payload, list):
        for name in payload:
            if isinstance(name, str):
                names.add(name.strip().lower())
    return names, "subdomain.center", "" if names else _describe_failure(fetch)


def _otx_passive_dns(domain: str, http: HttpClient) -> tuple[set[str], str, str]:
    fetch = http.get(
        f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    )
    payload = fetch.json() if fetch.ok else None
    names: set[str] = set()
    if isinstance(payload, dict):
        for entry in payload.get("passive_dns", []) or []:
            host = entry.get("hostname")
            if host:
                names.add(str(host).lower())
    return names, "AlienVault OTX", "" if names else _describe_failure(fetch)


def _describe_failure(fetch) -> str:
    """Turn an unsuccessful response into a short, readable reason.

    Public APIs often explain the problem themselves, so their message is
    preferred over a bare status code.
    """
    if fetch.error:
        return fetch.error[:100]
    if fetch.status:
        detail = ""
        payload = fetch.json()
        if isinstance(payload, dict):
            message = payload.get("message") or payload.get("error")
            if isinstance(message, str) and message:
                detail = message[:120]
        return f"HTTP {fetch.status}" + (f" - {detail}" if detail else "")
    return "no response"


SOURCES = (
    ("certspotter", _certspotter),
    ("crtsh", _crtsh),
    ("hackertarget", _hackertarget),
    ("subdomain_center", _subdomain_center),
    ("otx", _otx_passive_dns),
)


def discover(
    domain: str, http: HttpClient, sources: Iterable[str] | None = None
) -> tuple[dict[str, set[str]], list[str]]:
    """Query each source and return ``{source: names}`` plus a list of errors."""
    wanted = set(sources) if sources else {name for name, _ in SOURCES}
    results: dict[str, set[str]] = {}
    errors: list[str] = []

    for name, func in SOURCES:
        if name not in wanted:
            continue
        try:
            names, label, error = func(domain, http)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{name}: {type(exc).__name__}: {exc}")
            continue
        cleaned = {n for n in names if _is_valid_host(n, domain)}
        if cleaned:
            results[label] = cleaned
        else:
            errors.append(f"{name}: {error or 'no results'}")
    return results, errors


def collect_subdomains(
    domain: str,
    http: HttpClient,
    *,
    sources: Iterable[str] | None = None,
    resolve: bool = True,
    max_resolve: int = 60,
) -> tuple[list[Finding], dict[str, object]]:
    """Discover subdomains and (optionally) resolve them to IP addresses."""
    findings: list[Finding] = []
    per_source, errors = discover(domain, http, sources)

    # Group by host so a name found by several sources is reported once,
    # with the corroborating sources listed in the note.
    hosts: dict[str, set[str]] = {}
    for label, names in per_source.items():
        for name in names:
            hosts.setdefault(name, set()).add(label)

    for name in sorted(hosts):
        labels = sorted(hosts[name])
        severity = "good" if len(labels) > 1 else "info"
        findings.append(
            finding(
                "subdomain",
                "Host",
                name,
                source=labels[0],
                severity=severity,
                note="corroborated by: " + ", ".join(labels) if len(labels) > 1 else "",
                sources=labels,
            )
        )

    all_hosts = set(hosts)
    summary: dict[str, object] = {
        "total_unique": len(all_hosts),
        "sources": {label: len(names) for label, names in per_source.items()},
    }
    if errors:
        summary["source_errors"] = errors

    if not resolve or not all_hosts:
        return findings, summary

    from .dns import DnsResolver

    resolver = DnsResolver(http)
    targets = sorted(all_hosts)[:max_resolve]
    resolved = 0

    for host in targets:
        values, _error = resolver.resolve(host, "A")
        if not values:
            continue
        resolved += 1
        for ip in values:
            findings.append(
                finding("subdomain", "A record", ip, source="dns.google (DoH)", note=host)
            )

    summary["resolved"] = resolved
    summary["unresolved"] = len(targets) - resolved
    return findings, summary
