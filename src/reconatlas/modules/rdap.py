"""Domain registration data via RDAP.

RDAP is the structured successor to WHOIS and is served over plain HTTP by
registry operators, so no API key is required. ``rdap.org`` is used as a
bootstrap redirector with a hand-rolled IANA fallback.
"""

from __future__ import annotations

from typing import Any

from ..http import HttpClient
from ..models import Finding
from .base import finding

BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
RDAP_ORG = "https://rdap.org"


def _bootstrap_for(tld: str) -> str | None:
    """Look up the RDAP base URL for a TLD in the IANA bootstrap file."""
    import json
    import urllib.request

    try:
        with urllib.request.urlopen(BOOTSTRAP_URL, timeout=15) as response:
            data = json.loads(response.read().decode("utf-8"))
    except Exception:  # noqa: BLE001
        return None

    for service in data.get("services", []):
        tlds, urls = service
        if tld in tlds:
            return urls[0] if urls else None
    return None


def _events(rdap: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for event in rdap.get("events", []) or []:
        action = (event.get("eventAction") or "").lower()
        date = event.get("eventDate")
        if not date:
            continue
        if "registration" in action:
            out.setdefault("registered", date)
        elif "expiration" in action:
            out.setdefault("expires", date)
        elif "last changed" in action or "update" in action:
            out.setdefault("updated", date)
        elif "last update" in action:
            out.setdefault("updated", date)
    return out


def _statuses(rdap: dict[str, Any]) -> list[str]:
    return [str(s) for s in (rdap.get("status") or [])]


def _nameservers(rdap: dict[str, Any]) -> list[str]:
    names = []
    for ns in rdap.get("nameservers", []) or []:
        value = ns.get("ldhName") or ns.get("unicodeName")
        if value:
            names.append(str(value).lower())
    return names


def collect_registration(domain: str, http: HttpClient) -> tuple[list[Finding], dict[str, Any]]:
    """Fetch RDAP registration data for *domain*."""
    findings: list[Finding] = []
    summary: dict[str, Any] = {}

    fetch = http.get(f"{RDAP_ORG}/domain/{domain}", allow_redirects=True)
    payload = fetch.json() if fetch.ok else None
    source = "rdap.org"

    if not isinstance(payload, dict):
        # Fall back to the IANA bootstrap registry.
        tld = domain.rsplit(".", 1)[-1].lower()
        base = _bootstrap_for(tld)
        if base:
            fetch = http.get(f"{base.rstrip('/')}/domain/{domain}")
            payload = fetch.json() if fetch.ok else None
            source = f"IANA bootstrap ({base})"

    if not isinstance(payload, dict):
        return findings, summary

    summary["source"] = source
    summary["handle"] = payload.get("handle", "")

    # --- registrar / sponsoring organisation
    for entity in payload.get("entities", []) or []:
        roles = [str(r).lower() for r in (entity.get("roles") or [])]
        name = _entity_name(entity)
        if not name:
            continue
        if "registrar" in roles:
            findings.append(finding("registration", "Registrar", name, source=source))
            summary["registrar"] = name
        for sub in entity.get("entities", []) or []:
            abuse = _abuse_contact(sub) or _abuse_contact(entity)
            if abuse:
                findings.append(
                    finding(
                        "registration",
                        "Abuse contact",
                        abuse,
                        source=source,
                        note="Report abuse or legal requests here",
                    )
                )
                summary["abuse_contact"] = abuse
                break

    # --- dates
    dates = _events(payload)
    for label, key in (("registered", "registered"), ("expires", "expires"), ("updated", "updated")):
        if key in dates:
            severity = "warn" if key == "expires" else "info"
            findings.append(
                finding("registration", label.capitalize(), dates[key], source=source, severity=severity)
            )
    summary.update({k: v for k, v in dates.items() if k not in summary})

    # --- nameservers
    for ns in _nameservers(payload):
        findings.append(finding("registration", "Nameserver", ns, source=source))

    # --- status
    for status in _statuses(payload):
        severity = "warn" if "hold" in status.lower() or "lock" in status.lower() else "info"
        findings.append(finding("registration", "Status", status, source=source, severity=severity))

    # --- registrar contact details (whois-style, sometimes redacted)
    for entity in payload.get("entities", []) or []:
        name = _entity_name(entity)
        if not name:
            continue
        email = _vcard_field(entity, "email")
        phone = _vcard_field(entity, "tel")
        if email:
            findings.append(finding("registration", "Registrant email", email, source=source))
        if phone:
            findings.append(finding("registration", "Registrant phone", phone, source=source))
        addr = _vcard_field(entity, "adr")
        if addr:
            findings.append(finding("registration", "Registrant address", addr, source=source))

    return findings, summary


def _entity_name(entity: dict[str, Any]) -> str:
    for item in entity.get("vcardArray", [[], []])[1:]:
        for row in item:
            if row and row[0] == "fn":
                return str(row[3])
    for item in entity.get("entities", []) or []:
        name = _entity_name(item)
        if name:
            return name
    return ""


def _vcard_field(entity: dict[str, Any], field: str) -> str:
    vcard = entity.get("vcardArray")
    if not isinstance(vcard, list) or len(vcard) < 2:
        return ""
    for row in vcard[1]:
        if row and row[0] == field:
            value = row[3]
            if isinstance(value, list):
                return ", ".join(str(v) for v in value)
            return str(value)
    return ""


def _abuse_contact(entity: dict[str, Any]) -> str:
    for role in entity.get("roles", []) or []:
        if str(role).lower() == "abuse":
            email = _vcard_field(entity, "email")
            if email:
                return email
            phone = _vcard_field(entity, "tel")
            if phone:
                return phone
    return ""
