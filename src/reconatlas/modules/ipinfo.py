"""IP address intelligence: geolocation, ASN, reverse DNS, open ports.

Data comes from keyless public endpoints (ipwho.is, ipinfo.io, RIPEstat,
Shodan's free InternetDB) plus a small local TCP port probe.
"""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from ..http import HttpClient
from ..models import Finding
from ..util.net import is_private_ip
from .base import finding

#: Ports worth probing when a target is a public web server.
COMMON_PORTS = (21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 6379, 8080, 8443)

#: Service hints for the ports we probe.
PORT_SERVICES = {
    21: "ftp", 22: "ssh", 25: "smtp", 53: "dns", 80: "http", 110: "pop3",
    143: "imap", 443: "https", 465: "smtps", 587: "submission", 993: "imaps",
    995: "pop3s", 3306: "mysql", 3389: "rdp", 5432: "postgres", 6379: "redis",
    8080: "http-alt", 8443: "https-alt",
}


def _geo_lookup(ip: str, http: HttpClient) -> tuple[dict[str, Any], str]:
    payload = http.get_json(f"https://ipwho.is/{ip}")
    if isinstance(payload, dict) and payload.get("success", True):
        return payload, "ipwho.is"
    return {}, "ipwho.is"


def _ipinfo_lookup(ip: str, http: HttpClient) -> tuple[dict[str, Any], str]:
    payload = http.get_json(f"https://ipinfo.io/{ip}/json")
    if isinstance(payload, dict) and payload:
        return payload, "ipinfo.io"
    return {}, "ipinfo.io"


def _asn_lookup(ip: str, http: HttpClient) -> dict[str, Any]:
    payload = http.get_json(
        "https://stat.ripe.net/data/prefix-overview/data.json", params={"resource": ip}
    )
    if isinstance(payload, dict):
        return payload.get("data", {}) or {}
    return {}


def probe_port(ip: str, port: int, timeout: float = 1.5) -> bool:
    """Return True when a TCP connection to *ip*:*port* succeeds."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def collect_ip(ip: str, http: HttpClient, *, probe_ports: bool = True) -> tuple[list[Finding], dict[str, Any]]:
    """Gather everything we can about an IP address."""
    findings: list[Finding] = []
    summary: dict[str, Any] = {"ip": ip}

    if is_private_ip(ip):
        findings.append(
            finding(
                "ip",
                "Scope",
                "private / non-routable",
                source="local",
                severity="warn",
                note="This address is not exposed to the public internet.",
            )
        )
        summary["scope"] = "private"

    # ---------------------------------------------------------- geolocation
    geo, geo_source = _geo_lookup(ip, http)
    if geo:
        location = ", ".join(
            part
            for part in (
                geo.get("city") or "",
                geo.get("region") or "",
                geo.get("country") or "",
            )
            if part
        )
        if location:
            findings.append(finding("ip", "Location", location, source=geo_source))
            summary["location"] = location
        if geo.get("latitude") is not None and geo.get("longitude") is not None:
            findings.append(
                finding(
                    "ip",
                    "Coordinates",
                    f"{geo.get('latitude')}, {geo.get('longitude')}",
                    source=geo_source,
                    note="Approximate geolocation from IP allocation, not device GPS.",
                )
            )
        for key, label in (("isp", "ISP"), ("org", "Organisation"), ("asn", "ASN")):
            value = geo.get(key)
            if value:
                findings.append(finding("ip", label, str(value), source=geo_source))
        timezone = geo.get("timezone")
        if isinstance(timezone, dict):
            timezone = timezone.get("id") or timezone.get("abbr")
        if timezone:
            findings.append(finding("ip", "Timezone", str(timezone), source=geo_source))
        if geo.get("is_eu") is not None:
            summary["is_eu"] = geo.get("is_eu")

    # -------------------------------------------------------------- ipinfo
    info, info_source = _ipinfo_lookup(ip, http)
    if info:
        org = info.get("org")
        if org:
            findings.append(finding("ip", "Netblock owner", str(org), source=info_source))
            summary["org"] = org
        if info.get("hostname"):
            findings.append(
                finding("ip", "Reverse hostname", str(info["hostname"]), source=info_source)
            )
        if info.get("country"):
            findings.append(finding("ip", "Country", str(info["country"]), source=info_source))
        if info.get("city"):
            findings.append(finding("ip", "City", str(info["city"]), source=info_source))

    # ----------------------------------------------------------------- ASN
    asn_data = _asn_lookup(ip, http)
    if asn_data:
        prefix = asn_data.get("resource")
        if prefix:
            findings.append(finding("ip", "Announced prefix", str(prefix), source="RIPEstat"))
            summary["prefix"] = prefix
        for entry in asn_data.get("asns", []) or []:
            asn = entry.get("asn")
            holder = entry.get("holder")
            if asn:
                findings.append(finding("ip", "ASN", str(asn), source="RIPEstat"))
                summary["asn"] = asn
            if holder:
                findings.append(finding("ip", "ASN holder", str(holder), source="RIPEstat"))
                summary["asn_holder"] = holder
        if asn_data.get("is_less_specific"):
            summary["note"] = "Result aligned to a less-specific prefix"

    # ------------------------------------------------------ reverse DNS
    from .dns import DnsResolver

    ptrs, error = DnsResolver(http).reverse(ip)
    for ptr in ptrs:
        findings.append(finding("ip", "PTR record", ptr, source="dns.google (DoH)"))
    if ptrs:
        summary["ptr"] = ptrs
    elif error and error != "NXDOMAIN":
        summary["ptr_error"] = error

    # ------------------------------------------------------- InternetDB
    internetdb = http.get_json(f"https://internetdb.shodan.io/{ip}")
    if isinstance(internetdb, dict) and internetdb:
        for host in internetdb.get("hostnames", []) or []:
            findings.append(finding("ip", "Hosted hostname", str(host), source="Shodan InternetDB"))
        for port in internetdb.get("ports", []) or []:
            findings.append(
                finding(
                    "ip",
                    f"Port {port}",
                    PORT_SERVICES.get(port, "open"),
                    source="Shodan InternetDB",
                )
            )
        for cpe in internetdb.get("cpes", []) or []:
            findings.append(finding("ip", "CPE", str(cpe), source="Shodan InternetDB"))
        for vuln in internetdb.get("vulns", []) or []:
            findings.append(
                finding("ip", "Known vulnerability", str(vuln), source="Shodan InternetDB", severity="risk")
            )
        summary["internetdb_ports"] = internetdb.get("ports", [])

    # ------------------------------------------------------ local port probe
    if probe_ports and not is_private_ip(ip):
        open_ports: list[int] = []
        with ThreadPoolExecutor(max_workers=12) as pool:
            futures = {pool.submit(probe_port, ip, port): port for port in COMMON_PORTS}
            for future in as_completed(futures):
                if future.result():
                    open_ports.append(futures[future])
        for port in sorted(open_ports):
            existing = any(f.key == f"Port {port}" for f in findings)
            if not existing:
                findings.append(
                    finding(
                        "ip",
                        f"Port {port}",
                        PORT_SERVICES.get(port, "open"),
                        source="local probe",
                        severity="warn",
                    )
                )
        summary["open_ports"] = sorted(open_ports)

    return findings, summary
