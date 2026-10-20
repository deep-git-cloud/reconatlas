"""DNS resolution over DNS-over-HTTPS.

Public resolvers are queried over HTTPS so the tool works on networks where
outbound port 53 is filtered. A local resolver is used as a fallback.
"""

from __future__ import annotations

from typing import Any, Iterable

from ..http import HttpClient
from ..models import Finding
from .base import finding

DOH_ENDPOINT = "https://dns.google/resolve"

RECORD_TYPES = (
    "A",
    "AAAA",
    "MX",
    "NS",
    "TXT",
    "SOA",
    "CNAME",
    "CAA",
    "SRV",
    "DNSKEY",
    "DS",
    "NAPTR",
)

#: Human labels for the record types we care about most.
TYPE_LABELS = {
    "A": "IPv4 address",
    "AAAA": "IPv6 address",
    "MX": "Mail exchanger",
    "NS": "Name server",
    "TXT": "TXT record",
    "SOA": "Start of authority",
    "CNAME": "Canonical name",
    "CAA": "CA policy",
    "SRV": "Service record",
    "DNSKEY": "DNSSEC key",
    "DS": "DNSSEC delegation",
}

#: DNS RR type codes, used to filter the answer section by type.
TYPE_IDS = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "SOA": 6,
    "PTR": 12,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
    "SRV": 33,
    "DS": 43,
    "RRSIG": 46,
    "DNSKEY": 48,
    "CAA": 257,
}

#: Record types whose value is a domain name ending in a root label.
_FQDN_TYPES = {TYPE_IDS["NS"], TYPE_IDS["CNAME"], TYPE_IDS["PTR"]}


def _format_rdata(rtype: int, data: str) -> str:
    """Normalise one RR's presentation format.

    Only domain-name records have their trailing root label removed - TXT
    values are left untouched because a trailing dot can be meaningful.
    """
    if rtype in _FQDN_TYPES:
        return data.strip().rstrip(".")
    if rtype == TYPE_IDS["MX"]:
        return data.strip()
    if rtype == TYPE_IDS["SOA"]:
        parts = data.split()
        if len(parts) >= 2:
            parts[0] = parts[0].rstrip(".")
            parts[1] = parts[1].rstrip(".")
        return " ".join(parts)
    return data.strip()


def parse_mx(value: str) -> tuple[int, str]:
    """Split an MX record into ``(priority, exchange)``.

    An empty exchange means a "null MX" (RFC 7505): the domain explicitly
    accepts no mail at all.
    """
    parts = value.split()
    if not parts:
        return 0, ""
    try:
        priority = int(parts[0])
    except ValueError:
        return 0, value.strip()
    exchange = parts[1].rstrip(".") if len(parts) > 1 else ""
    return priority, exchange


class DnsResolver:
    """Resolves records through DNS-over-HTTPS with a local fallback."""

    def __init__(self, http: HttpClient) -> None:
        self.http = http
        self._local = None

    # ------------------------------------------------------------- transports

    def _doh(self, name: str, rtype: str) -> tuple[dict[int, list[str]], str]:
        payload = self.http.get_json(
            DOH_ENDPOINT,
            params={"name": name, "type": rtype},
            cache=True,
        )
        if not isinstance(payload, dict):
            return {}, "DoH request failed"

        status = int(payload.get("Status", 0))
        if status == 3:  # NXDOMAIN
            return {}, "NXDOMAIN"
        if status not in (0,):
            return {}, f"DNS status {status}"

        # Group the answer section by record type. A CNAME in the chain is
        # returned alongside the record that was actually asked for.
        by_type: dict[int, list[str]] = {}
        for answer in payload.get("Answer", []) or []:
            data = answer.get("data")
            if data is None:
                continue
            atype = int(answer.get("type", 0) or 0)
            by_type.setdefault(atype, []).append(_format_rdata(atype, str(data)))
        return by_type, ""

    def _local_resolve(self, name: str, rtype: str) -> tuple[list[str], str]:
        try:
            import dns.resolver
        except ModuleNotFoundError:
            return [], "dnspython unavailable"
        try:
            if self._local is None:
                self._local = dns.resolver.Resolver()
                self._local.lifetime = 6.0
                self._local.timeout = 6.0
            answers = self._local.resolve(name, rtype)
            values = []
            for rdata in answers:
                text = rdata.to_text()
                if rtype in ("CNAME", "NS", "PTR"):
                    text = text.rstrip(".")
                values.append(text)
            return values, ""
        except Exception as exc:  # noqa: BLE001
            return [], f"{type(exc).__name__}: {exc}"

    # ------------------------------------------------------------------ public

    def resolve(self, name: str, rtype: str = "A") -> tuple[list[str], str]:
        """Resolve *name*/*rtype*, returning ``(values, error)``.

        Only records of the requested type are returned, so a CNAME that
        appears in the answer chain never masquerades as an A record.
        """
        wanted = TYPE_IDS.get(rtype.upper())
        by_type, error = self._doh(name, rtype)
        if by_type:
            values = list(by_type.get(wanted, [])) if wanted else []
            if not values and wanted:
                # No record of the requested type, but a CNAME was returned.
                cnames = by_type.get(TYPE_IDS["CNAME"], [])
                if cnames:
                    return [], f"CNAME -> {cnames[0]}"
                return [], error
            return values, ""
        if error == "NXDOMAIN":
            return [], error
        local_values, local_error = self._local_resolve(name, rtype)
        if local_values:
            return local_values, ""
        return [], error or local_error

    def records(self, name: str, rtypes: Iterable[str] = RECORD_TYPES) -> dict[str, list[str]]:
        """Resolve a set of record types, skipping the ones that do not exist."""
        out: dict[str, list[str]] = {}
        for rtype in rtypes:
            values, error = self.resolve(name, rtype)
            if values:
                out[rtype] = values
            elif error and error not in ("NXDOMAIN",):
                out.setdefault("_errors", []).append(f"{rtype}: {error}")
        return out

    def reverse(self, ip: str) -> tuple[list[str], str]:
        """Reverse (PTR) lookup for an IP address."""
        import ipaddress

        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return [], "invalid IP"
        if addr.version == 4:
            ptr = ".".join(reversed(str(addr).split("."))) + ".in-addr.arpa"
        else:
            nibbles = addr.exploded.replace(":", "")
            ptr = ".".join(reversed(nibbles)) + ".ip6.arpa"
        return self.resolve(ptr, "PTR")


def dns_findings(
    domain: str,
    records: dict[str, list[str]],
    source: str = "dns.google (DoH)",
) -> list[Finding]:
    """Turn a record mapping into findings."""
    out: list[Finding] = []
    for rtype, values in records.items():
        if rtype.startswith("_"):
            continue
        label = TYPE_LABELS.get(rtype, rtype)
        for value in values:
            severity = "info"
            note = ""
            if rtype == "MX":
                priority, exchange = parse_mx(value)
                if not exchange:
                    severity = "warn"
                    note = "Null MX (RFC 7505) - this domain accepts no mail."
                    value = "null MX"
                else:
                    value = exchange
                    note = f"priority {priority}"
            elif rtype == "TXT" and value.startswith("v=spf1"):
                severity = "good"
                note = "SPF policy present"
            elif rtype == "TXT" and value.startswith("v=dmarc"):
                severity = "good"
                note = "DMARC policy present"
            elif rtype == "TXT" and "v=DKIM1" in value:
                severity = "good"
                note = "DKIM key present"
            elif rtype == "CAA" and "issue" not in value:
                severity = "warn"
                note = "no CAA issue restriction"
            out.append(
                finding(
                    "dns",
                    f"{rtype} ({label})",
                    value,
                    source=source,
                    severity=severity,
                    note=note,
                )
            )
    return out


def summarise(records: dict[str, list[str]]) -> dict[str, Any]:
    """A small summary dict for the module result."""
    return {k: len(v) for k, v in records.items() if not k.startswith("_")}
